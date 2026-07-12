import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdLeaks, cmdSearch, cmdShow, cmdStatus } from "../src/cli/commands";
import { buildRunEnv, AGENTS } from "../src/cli/agents";
import { Store, type CallRecord } from "../src/core/store/store";
import { ulid } from "../src/core/store/ulid";

function seed(stateDir: string): { exId: string } {
  const store = Store.open(stateDir);
  const exId = ulid();
  const ex: CallRecord = {
    id: exId, sessionId: "s1", runId: "r1", source: "wire",
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
  store.insertCall(ex);
  store.upsertLeakEvent({
    fingerprint: "fp1", sessionId: "s1", detector: "generic-api-key",
    secretType: "generic-api-key", severity: "medium", confidenceTier: "possible",
    destination: "anthropic", callId: exId, ts: Date.now(),
  });
  store.close();
  return { exId };
}

describe("CLI commands (headless loop, R12)", () => {
  let stateDir: string;
  let exId: string;

  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-cli-"));
    exId = seed(stateDir).exId;
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

  test("leaks: lists events with type/destination/occurrences", () => {
    const out = cmdLeaks(stateDir);
    expect(out).toContain("generic-api-key");
    expect(out).toContain("anthropic");
  });

  test("show: accepts id prefix, prints summary and metadata", () => {
    const out = cmdShow(stateDir, exId.slice(0, 8));
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

  test("pi has no confirmed config mechanism yet (spike-pending)", () => {
    expect(AGENTS.pi!.baseUrlEnv).toBeUndefined();
    expect(AGENTS.pi!.config).toBeUndefined();
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
