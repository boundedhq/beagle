import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdLeaks, cmdSearch, cmdShow, cmdStatus } from "../src/cli/commands";
import { buildRunEnv, AGENTS } from "../src/cli/agents";
import { Store, type CallRecord } from "../src/core/store/store";
import { ulid } from "../src/core/store/ulid";

function seed(stateDir: string): { callId: string } {
  const store = Store.open(stateDir);
  const callId = ulid();
  const call: CallRecord = {
    id: callId, sessionId: "s1", runId: "r1", source: "wire",
    agent: "claude-code", provider: "anthropic", model: "claude-sonnet-5",
    endpoint: "/v1/messages", tsRequest: Date.now(), tsResponse: Date.now(),
    status: 200, tokensIn: 10, tokensOut: 5, bytesReq: 100, bytesResp: 50,
    summary: "user asked to read files", scanState: "ok", captureState: "ok",
    sessionTier: "prefix",
    requestBody: new TextEncoder().encode('{"messages":[{"role":"user","content":"my password is hunter2"}]}'),
    requestHeaders: [["content-type", "application/json"]],
    responseBody: new TextEncoder().encode('{"content":"ok"}'),
    responseHeaders: [], sseRaw: null,
    searchText: "my password is hunter2 ok",
  };
  store.insertCall(call);
  store.upsertLeakEvent({
    fingerprint: "fp1", sessionId: "s1", detector: "generic-api-key",
    secretType: "generic-api-key", severity: "medium", confidenceTier: "possible",
    destination: "anthropic", callId: callId, ts: Date.now(),
  });
  store.close();
  return { callId };
}

describe("CLI commands (headless loop, R12)", () => {
  let stateDir: string;
  let callId: string;

  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-cli-"));
    callId = seed(stateDir).callId;
  });

  test("search: definitive found-in-N answer", () => {
    const out = cmdSearch(stateDir, "hunter2");
    expect(out).toContain("found in 1 call");
    expect(out).toContain("s1");
  });

  test("search: unambiguous never-sent answer", () => {
    const out = cmdSearch(stateDir, "never-sent-credential");
    expect(out.toLowerCase()).toContain("no matches");
  });

  test("search: with no argument, reads the term from stdin (keeps secrets out of shell history)", () => {
    // `echo $SECRET | beagle search` / `pbpaste | beagle search` — the term
    // must never have to appear in argv, where it would land in shell
    // history and `ps` output.
    const run = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), "search"], {
      stdin: new TextEncoder().encode("hunter2\n"),
      env: { ...process.env, BEAGLE_STATE_DIR: stateDir },
    });
    expect(run.stdout.toString()).toContain("found in 1 call");
  });

  test("search: stdin longer than 256 bytes is read whole (JWT-sized terms)", () => {
    // Seed a call whose text contains a 300-char run of 'y'. Then search for
    // 301 'y's via stdin: a reader that truncates at 256 bytes would search
    // the shorter prefix and WRONGLY report "found"; a full read gives the
    // honest "no matches". This pins the difference.
    const store = Store.open(stateDir);
    store.insertCall({
      id: ulid(), sessionId: "s9", runId: "r9", source: "wire", agent: "claude-code",
      provider: "anthropic", endpoint: "/v1/messages", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "y".repeat(300),
    });
    store.close();
    const run = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), "search"], {
      stdin: new TextEncoder().encode("y".repeat(301) + "\n"),
      env: { ...process.env, BEAGLE_STATE_DIR: stateDir },
    });
    expect(run.stdout.toString().toLowerCase()).toContain("no matches");
    expect(run.exitCode).toBe(0);
  });

  test("leaks: lists events with type/destination/occurrences", () => {
    const out = cmdLeaks(stateDir);
    expect(out).toContain("generic-api-key");
    expect(out).toContain("anthropic");
  });

  test("show: accepts id prefix, prints summary and metadata", () => {
    const out = cmdShow(stateDir, callId.slice(0, 8));
    expect(out).toContain("claude-sonnet-5");
    expect(out).toContain("user asked to read files");
  });

  test("show: ambiguous or unknown prefix says so plainly", () => {
    const out = cmdShow(stateDir, "ZZZZZZZZ");
    expect(out.toLowerCase()).toContain("no call");
  });

  test("show: traffic-derived text is stripped of terminal escapes", () => {
    const store = Store.open(stateDir);
    const id = ulid();
    store.insertCall({
      id, sessionId: "s2", runId: "r1", source: "wire", agent: "claude-code",
      provider: "anthropic", model: "m", endpoint: "/v1/messages",
      tsRequest: Date.now(), scanState: "ok", captureState: "ok", sessionTier: "run",
      summary: "evil \x1b[2J\x1b[31m wipe-your-screen summary",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "x",
    });
    store.close();
    // full id: two same-millisecond ULIDs share an 8-char prefix
    const out = cmdShow(stateDir, id);
    expect(out).not.toContain("\x1b");
    expect(out).toContain("wipe-your-screen");
  });

  test("status: trust-strip text works with no daemon running", () => {
    const out = cmdStatus(stateDir);
    expect(out.toLowerCase()).toContain("daemon: not running");
    expect(out).toContain("calls: 1");
    expect(out.toLowerCase()).toContain("local only");
  });
});

describe("parseRunArgs", () => {
  const { parseRunArgs } = require("../src/cli/commands") as typeof import("../src/cli/commands");

  test("shim invocation: --real and separator", () => {
    const r = parseRunArgs(["--real", "/opt/bin/claude", "--", "-p", "hello"]);
    expect(r.realBinary).toBe("/opt/bin/claude");
    expect(r.agentArgs).toEqual(["-p", "hello"]);
    expect(r.telemetry).toBe(false);
  });

  test("--telemetry before the separator is beagle's", () => {
    const r = parseRunArgs(["--telemetry", "--", "-p", "hi"]);
    expect(r.telemetry).toBe(true);
    expect(r.agentArgs).toEqual(["-p", "hi"]);
  });

  test("--telemetry AFTER the separator belongs to the agent", () => {
    const r = parseRunArgs(["--", "--telemetry"]);
    expect(r.telemetry).toBe(false);
    expect(r.agentArgs).toEqual(["--telemetry"]);
  });

  test("no separator: beagle flags are stripped from agent args", () => {
    const r = parseRunArgs(["--telemetry", "-p", "hi"]);
    expect(r.telemetry).toBe(true);
    expect(r.agentArgs).toEqual(["-p", "hi"]);
  });
});

describe("run env mapping", () => {
  test("claude uses ANTHROPIC_BASE_URL with the run prefix", () => {
    const env = buildRunEnv("claude", 4242, "uuid-1");
    expect(env.ANTHROPIC_BASE_URL).toBe("http://127.0.0.1:4242/run/uuid-1");
  });

  test("codex uses OPENAI_BASE_URL", () => {
    const env = buildRunEnv("codex", 4242, "uuid-2");
    expect(env.OPENAI_BASE_URL).toBe("http://127.0.0.1:4242/run/uuid-2");
  });

  test("agent registry covers the four v1 CLI agents", () => {
    expect(Object.keys(AGENTS).sort()).toEqual(["claude", "codex", "opencode", "pi"]);
  });

  test("opencode is config-driven (OPENCODE_CONFIG), not env-base-URL", () => {
    expect(AGENTS.opencode!.baseUrlEnv).toBeUndefined();
    expect(AGENTS.opencode!.config?.configEnv).toBe("OPENCODE_CONFIG");
    expect(AGENTS.opencode!.config?.baseUrlPath).toEqual(["provider", "openai", "options", "baseURL"]);
    // env-base-URL helper returns nothing for config-driven agents
    expect(buildRunEnv("opencode", 1, "x")).toEqual({});
  });

  test("pi is extension-driven: -e flag re-points the openai provider", () => {
    expect(AGENTS.pi!.baseUrlEnv).toBeUndefined();
    expect(AGENTS.pi!.config).toBeUndefined();
    expect(AGENTS.pi!.extension).toEqual({ flag: "-e", baseUrlProvider: "openai" });
  });
});

describe("config-driven run redirect (opencode)", () => {
  const { buildRedirectConfig, readFirstConfig } =
    require("../src/install/config-redirect") as typeof import("../src/install/config-redirect");

  test("merges an existing opencode config and injects the proxy baseURL", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-oc-"));
    const cfgDir = join(dir, ".config", "opencode");
    require("node:fs").mkdirSync(cfgDir, { recursive: true });
    require("node:fs").writeFileSync(
      join(cfgDir, "opencode.json"),
      JSON.stringify({ provider: { openai: { options: { apiKey: "sk-mine" } } }, theme: "dark" }),
    );
    const spec = AGENTS.opencode!.config!;
    const user = readFirstConfig(spec.realConfigCandidates(dir));
    const merged = buildRedirectConfig(user, spec.baseUrlPath, "http://127.0.0.1:9/run/r") as any;
    expect(merged.provider.openai.options.baseURL).toBe("http://127.0.0.1:9/run/r");
    expect(merged.provider.openai.options.apiKey).toBe("sk-mine"); // preserved
    expect(merged.theme).toBe("dark"); // preserved
  });
});

describe("pi extension redirect (run-level)", () => {
  test("run pi injects -e <beagle extension> before user args, deletes it after", async () => {
    const { existsSync, readFileSync, writeFileSync, chmodSync } = await import("node:fs");
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-pi-"));
    // A faithful argv printer as the fake "agent". NOT /bin/echo: GNU echo
    // eats "-e" as its own escape flag (BSD echo prints it), which is exactly
    // the argument this test needs to see.
    const fakeAgent = join(stateDir, "argv-printer.sh");
    writeFileSync(fakeAgent, '#!/bin/sh\nprintf "%s\\n" "$@"\n');
    chmodSync(fakeAgent, 0o755);
    const run = Bun.spawnSync(
      ["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"),
       "run", "pi", "--real", fakeAgent, "--", "user-arg"],
      { env: { ...process.env, BEAGLE_STATE_DIR: stateDir } },
    );
    const argv = run.stdout.toString().trim().split("\n");
    expect(argv[0]).toBe("-e"); // beagle's flag first
    expect(argv[1]).toMatch(/agent-config\/pi-[0-9a-f-]+\.ts$/); // per-RUN path (concurrent runs must not collide)
    expect(argv[2]).toBe("user-arg"); // user args after
    // the Beagle-owned extension is deleted once the agent exits
    const { readdirSync } = await import("node:fs");
    expect(readdirSync(join(stateDir, "agent-config"))).toEqual([]);

    // reap the auto-started ephemeral daemon
    try {
      const info = JSON.parse(readFileSync(join(stateDir, "daemon.json"), "utf8")) as { socketPath: string };
      const { controlRequest } = await import("../src/daemon/control");
      await controlRequest(info.socketPath, { cmd: "shutdown" });
    } catch { /* already gone */ }
  }, 20_000);
});

describe("__hook forwarder safety (Mode B tool-output hook)", () => {
  const bin = () => ["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), "__hook"];

  test("no telemetry env: silent no-op, exits 0 (a bare tool call never fails)", () => {
    const run = Bun.spawnSync(bin(), { stdin: new TextEncoder().encode('{"tool_response":"x"}') });
    expect(run.exitCode).toBe(0);
    expect(run.stdout.toString()).toBe(""); // MUST be silent — output could reach the model
    expect(run.stderr.toString()).toBe("");
  });

  test("unreachable receiver: still exits 0 promptly (best-effort; never stalls the agent)", () => {
    const t0 = Date.now();
    const run = Bun.spawnSync(bin(), {
      stdin: new TextEncoder().encode('{"session_id":"s","tool_name":"Bash","tool_response":"AKIAZQ3DRSTUVWXY2345"}'),
      // 127.0.0.1:1 refuses fast; the 2s fetch timeout bounds the worst case regardless
      env: { ...process.env, BEAGLE_HOOK_ENDPOINT: "http://127.0.0.1:1/v1/hook", BEAGLE_HOOK_TOKEN: "t" },
    });
    expect(run.exitCode).toBe(0);
    expect(run.stdout.toString()).toBe("");
    expect(Date.now() - t0).toBeLessThan(4000); // bounded by the 2s AbortSignal, not hung
  });

  test("stdin that never reaches EOF is time-bounded (the read can't hang the agent)", async () => {
    // A partial payload with stdin left OPEN: the read must not block forever
    // waiting for EOF — the 1.5s deadline cancels it, then the process exits.
    const proc = Bun.spawn(bin(), {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, BEAGLE_HOOK_ENDPOINT: "http://127.0.0.1:1/v1/hook", BEAGLE_HOOK_TOKEN: "t" },
    });
    proc.stdin.write('{"tool_response":"partial'); // never closed
    proc.stdin.flush();
    const t0 = Date.now();
    const code = await Promise.race([
      proc.exited,
      new Promise<number>((r) => setTimeout(() => { proc.kill(); r(-1); }, 6000)),
    ]);
    expect(code).toBe(0); // exited on its own (not the 6s kill fallback)
    expect(Date.now() - t0).toBeLessThan(5000); // bounded by the 1.5s stdin deadline + fetch
  });
});
