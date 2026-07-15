import { beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdLeaks, cmdSearch, cmdShow, cmdStatus, cmdUninstall, detectLine, interpretAskAnswer, otelCallsArrivedSince, parseRunArgs, readCodexApiKey, resolveRunMode, runCallsArrived } from "../src/cli/commands";
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
    expect(out.toLowerCase()).toContain("not running");
    expect(out).toContain("1 call");
    expect(out).toContain("1 detected");
    expect(out.toLowerCase()).toContain("local only");
    expect(out).not.toContain("\x1b"); // trust strip must never emit terminal escapes
  });

  test("status: every value line is label-aligned into two columns", () => {
    const out = cmdStatus(stateDir);
    for (const line of out.split("\n")) {
      if (line === "") continue;
      // 11-char label gutter: either a label padded to the gutter or a
      // continuation line of pure indent
      expect(line.length).toBeGreaterThan(11);
      expect(line[11]).not.toBe(" ");
      expect(/^[a-z ]{11}$/.test(line.slice(0, 11))).toBe(true);
    }
  });

  test("status: discloses the Mode B content gap whenever agent-reported calls exist (R2)", () => {
    const store = Store.open(stateDir);
    const otel: CallRecord = {
      id: ulid(), sessionId: "s2", runId: "r2", source: "otel",
      agent: "claude-code", provider: "anthropic", model: "claude-sonnet-5",
      endpoint: "otlp", tsRequest: Date.now(), tsResponse: Date.now(),
      status: 200, tokensIn: 1, tokensOut: 1, bytesReq: 10, bytesResp: 10,
      summary: "otel", scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: new TextEncoder().encode("{}"), requestHeaders: [],
      responseBody: null, responseHeaders: [], sseRaw: null, searchText: "otel",
    };
    store.insertCall(otel);
    store.close();
    const out = cmdStatus(stateDir);
    expect(out).toContain("1 agent-reported (Mode B)");
    expect(out.toLowerCase()).toContain("lag");
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

  test("codex redirects via a custom provider, NOT OPENAI_BASE_URL (which it ignores)", () => {
    // codex ignores OPENAI_BASE_URL (verified live) — buildRunEnv must not
    // pretend otherwise, and the wire redirect is a custom model_provider.
    expect(AGENTS.codex!.baseUrlEnv).toBeUndefined();
    expect(buildRunEnv("codex", 4242, "uuid-2")).toEqual({});
    const args = AGENTS.codex!.wireArgs!("http://127.0.0.1:4242/run/uuid-2");
    expect(args).toContain('model_provider="beagle"');
    expect(args).toContain('model_providers.beagle.base_url="http://127.0.0.1:4242/run/uuid-2"');
    expect(args).toContain('model_providers.beagle.env_key="OPENAI_API_KEY"'); // reads the user's key
    expect(args).toContain('model_providers.beagle.wire_api="responses"');
    expect(args.filter((a) => a === "-c").length).toBe(5); // every knob a -c override
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

  test("pi is extension-driven: -e flag re-points whichever provider pi is signed in with", () => {
    expect(AGENTS.pi!.baseUrlEnv).toBeUndefined();
    expect(AGENTS.pi!.config).toBeUndefined();
    expect(AGENTS.pi!.extension?.flag).toBe("-e");
    // baseUrlProvider is a resolver now (login-dependent: openai vs openai-codex);
    // with no pi install it falls back to the openai API-key assumption.
    const resolveProvider = AGENTS.pi!.extension!.baseUrlProvider as (home: string) => string;
    expect(resolveProvider(mkdtempSync(join(tmpdir(), "beagle-pi-none-")))).toBe("openai");
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

describe("readCodexApiKey (fail-open: supply codex's key from auth.json)", () => {
  test("reads OPENAI_API_KEY from $CODEX_HOME/auth.json; null when absent", () => {
    const h = mkdtempSync(join(tmpdir(), "beagle-cxk-"));
    writeFileSync(join(h, "auth.json"), '{"auth_mode":"apikey","OPENAI_API_KEY":"sk-fromfile"}');
    expect(readCodexApiKey(h)).toBe("sk-fromfile");
    writeFileSync(join(h, "auth.json"), '{"auth_mode":"apikey"}'); // no key field
    expect(readCodexApiKey(h)).toBeNull();
    writeFileSync(join(h, "auth.json"), "not json");
    expect(readCodexApiKey(h)).toBeNull();
    expect(readCodexApiKey(mkdtempSync(join(tmpdir(), "beagle-empty-")))).toBeNull(); // no file
  });
});

describe("cmdUninstall (safe full teardown)", () => {
  test("non-interactive without --yes: refuses to prompt (no hang), asks for --yes", async () => {
    // Pass isTTY=false explicitly (not the runner's ambient stdin) so this stays
    // deterministic — under `bun run check` in a real terminal isTTY is true,
    // which would otherwise make cmdUninstall prompt and block the whole run.
    const dir = mkdtempSync(join(tmpdir(), "beagle-uninst-nt-"));
    const store = Store.open(dir); store.close(); // a store → not the empty-noop path
    const out = await cmdUninstall(dir, false, false);
    expect(out).toContain("--yes");
    expect(existsSync(join(dir, "beagle.db"))).toBe(true); // nothing deleted
  });

  test("no daemon, watches, or store: reports nothing to remove", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-uninst-empty-"));
    const out = await cmdUninstall(dir, true);
    expect(out.toLowerCase()).toContain("nothing to remove");
  });

  test("--yes: securely erases the store and removes the state dir; names the binary step", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-uninst-"));
    // a store with a captured secret present
    const store = Store.open(dir);
    store.insertCall({
      id: ulid(), sessionId: "s1", runId: "r1", source: "wire", agent: "claude-code",
      provider: "anthropic", endpoint: "/v1/messages", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: new TextEncoder().encode("AKIAZQ3DRSTUVWXY2345"),
      requestHeaders: null, responseBody: null, responseHeaders: null, sseRaw: null,
      searchText: "AKIAZQ3DRSTUVWXY2345",
    });
    store.close();
    expect(existsSync(join(dir, "beagle.db"))).toBe(true);
    const out = await cmdUninstall(dir, true);
    expect(out).toContain("securely erased captured data");
    expect(out).toContain(`removed ${dir}`);
    expect(out).toContain("brew uninstall beagle");
    expect(existsSync(dir)).toBe(false); // exclusive dir → whole dir gone
  });

  test("removes ONLY Beagle-owned files — never the user's own files in a shared dir", async () => {
    // A user who pointed BEAGLE_STATE_DIR at a directory holding their own
    // files must NOT lose them to `rm -rf` (confirmed data loss before the fix).
    const dir = mkdtempSync(join(tmpdir(), "beagle-shared-"));
    writeFileSync(join(dir, "notes.txt"), "my precious data");
    const store = Store.open(dir); // creates beagle.db (+ config on next status)
    store.close();
    writeFileSync(join(dir, "config.json"), "{}");
    const out = await cmdUninstall(dir, true);
    expect(existsSync(dir)).toBe(true); // dir kept — it wasn't exclusively Beagle's
    expect(existsSync(join(dir, "notes.txt"))).toBe(true); // user's file survives
    expect(existsSync(join(dir, "beagle.db"))).toBe(false); // Beagle's files gone
    expect(existsSync(join(dir, "config.json"))).toBe(false);
    expect(out).toContain("kept your other files");
  });
});

describe("beagle help / detect surfaces", () => {
  test("'beagle help' prints the command list and exits 0 (not the unknown-command path)", () => {
    for (const arg of ["help", "--help", "-h"]) {
      const run = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), arg]);
      expect(run.exitCode).toBe(0);
      expect(run.stdout.toString()).toContain("beagle run <agent>");
      expect(run.stdout.toString()).toContain("beagle stop");
    }
  });

  test("an unknown command still prints help but exits 2", () => {
    const run = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), "bogus-cmd"]);
    expect(run.exitCode).toBe(2);
  });

  test("detectLine puts the command on its own arrowed line, with a plain-English capture note", () => {
    // The command must read as "type this" — its own line, marked, not buried
    // mid-row between unlabeled facts (the old single-line format).
    const sub = detectLine("claude", "subscription");
    expect(sub).toContain("→ beagle run claude");
    expect(sub.split("\n").length).toBe(2);
    // no bare jargon: each login kind is explained in plain words
    expect(sub).toContain("subscription");
    expect(sub).toContain("usage report");
    expect(detectLine("codex", "api-key")).toContain("API key");
    expect(detectLine("codex", "api-key")).toContain("on the wire");
    expect(detectLine("codex", "unknown")).toContain("asks once");
    // the command itself is always the plain one — no flags to memorize
    expect(detectLine("codex", "unknown")).toContain("→ beagle run codex");
  });
});

describe("interpretAskAnswer (strict — a fumbled keystroke is never remembered)", () => {
  test("only an unambiguous 1 or 2 counts", () => {
    expect(interpretAskAnswer("1")).toBe("wire");
    expect(interpretAskAnswer(" 2 ")).toBe("telemetry");
    expect(interpretAskAnswer("")).toBeNull(); // blank Enter
    expect(interpretAskAnswer("yes")).toBeNull();
    expect(interpretAskAnswer("1)")).toBeNull();
    expect(interpretAskAnswer("12")).toBeNull();
  });
});

describe("resolveRunMode (flag > saved > detected > ask > wire)", () => {
  test("explicit flags always win", () => {
    expect(resolveRunMode({ telemetry: true, wire: false }, "wire", "api-key", true)).toEqual({ mode: "telemetry", source: "flag" });
    expect(resolveRunMode({ telemetry: false, wire: true }, "telemetry", "subscription", true)).toEqual({ mode: "wire", source: "flag" });
  });

  test("a remembered answer beats detection", () => {
    expect(resolveRunMode({ telemetry: false, wire: false }, "telemetry", "api-key", true)).toEqual({ mode: "telemetry", source: "saved" });
    expect(resolveRunMode({ telemetry: false, wire: false }, "wire", "subscription", true)).toEqual({ mode: "wire", source: "saved" });
  });

  test("detection decides when nothing is saved", () => {
    expect(resolveRunMode({ telemetry: false, wire: false }, undefined, "subscription", false)).toEqual({ mode: "telemetry", source: "detected" });
    expect(resolveRunMode({ telemetry: false, wire: false }, undefined, "api-key", false)).toEqual({ mode: "wire", source: "detected" });
  });

  test("unknown login: ask on a TTY, silently default to wire otherwise", () => {
    // non-TTY (the PATH shim, scripts) must NEVER hang on a prompt
    expect(resolveRunMode({ telemetry: false, wire: false }, undefined, "unknown", false)).toEqual({ mode: "wire", source: "default" });
    expect(resolveRunMode({ telemetry: false, wire: false }, undefined, "unknown", true)).toEqual({ mode: "ask" });
  });
});

describe("runCallsArrived (the wire zero-capture tripwire's predicate)", () => {
  test("true as soon as a row exists for the runId; false when none within the deadline", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-trip-"));
    const store = Store.open(stateDir);
    store.insertCall({
      id: ulid(), sessionId: "s1", runId: "run-covered", source: "wire", agent: "codex",
      provider: "openai", endpoint: "/v1/responses", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "x",
    });
    store.close();
    expect(await runCallsArrived(stateDir, "run-covered", 500)).toBe(true);
    // a different runId has zero rows → tripwire condition
    expect(await runCallsArrived(stateDir, "run-empty", 500)).toBe(false);
  });

  test("an absent store never cries wolf", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-trip-"));
    expect(await runCallsArrived(stateDir, "any", 300)).toBe(true);
  });

  test("hook rows never satisfy the EXPORT tripwire — a dead exporter can't hide behind tool traffic", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-trip-"));
    const store = Store.open(stateDir);
    // only a HOOK row lands (PostToolUse works, OTel export dead/diverted)
    store.insertCall({
      id: ulid(), sessionId: "s1", runId: "otel", source: "otel", agent: "claude",
      provider: "anthropic", endpoint: "otel:tool_output:Bash", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "x",
    });
    store.close();
    expect(await otelCallsArrivedSince(stateDir, Date.now() - 1000, 400)).toBe(false);
    // an EXPORT row (the turn) does satisfy it
    const s2 = Store.open(stateDir);
    s2.insertCall({
      id: ulid(), sessionId: "s1", runId: "otel", source: "otel", agent: "claude",
      provider: "anthropic", endpoint: "otel:claude_code.turn", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "y",
    });
    s2.close();
    expect(await otelCallsArrivedSince(stateDir, Date.now() - 1000, 400)).toBe(true);
  });

  test("otelCallsArrivedSince is timestamp-based — old rows don't count, deletions can't fake a zero", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-trip-"));
    const store = Store.open(stateDir);
    const old = Date.now() - 3_600_000; // an hour-old otel row from a PREVIOUS run
    store.insertCall({
      id: ulid(old), sessionId: "s1", runId: "otel", source: "otel", agent: "codex",
      provider: "openai", endpoint: "otel:codex:user_prompt", tsRequest: old,
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "old",
    });
    store.close();
    // a run that started NOW must not be satisfied by the stale row
    expect(await otelCallsArrivedSince(stateDir, Date.now(), 400)).toBe(false);
    // …but a row landing within the run window (with clock margin) counts
    const store2 = Store.open(stateDir);
    store2.insertCall({
      id: ulid(), sessionId: "s1", runId: "otel", source: "otel", agent: "codex",
      provider: "openai", endpoint: "otel:codex:user_prompt", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "fresh",
    });
    store2.close();
    expect(await otelCallsArrivedSince(stateDir, Date.now() - 1000, 400)).toBe(true);
  });
});

