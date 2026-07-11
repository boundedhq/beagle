import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdLeaks, cmdSearch, cmdShow, cmdStatus } from "../src/cli/commands";
import { buildRunEnv, AGENTS } from "../src/cli/agents";
import { Store, type ExchangeRecord } from "../src/core/store/store";
import { ulid } from "../src/core/store/ulid";

function seed(stateDir: string): { exId: string } {
  const store = Store.open(stateDir);
  const exId = ulid();
  const ex: ExchangeRecord = {
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
  store.insertExchange(ex);
  store.upsertLeakEvent({
    fingerprint: "fp1", sessionId: "s1", detector: "generic-api-key",
    secretType: "generic-api-key", severity: "medium", confidenceTier: "possible",
    destination: "anthropic", exchangeId: exId, ts: Date.now(),
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
    expect(out).toContain("found in 1 exchange");
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
    expect(out.toLowerCase()).toContain("no exchange");
  });

  test("show: traffic-derived text is stripped of terminal escapes", () => {
    const store = Store.open(stateDir);
    const id = ulid();
    store.insertExchange({
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
    expect(out).toContain("exchanges: 1");
    expect(out.toLowerCase()).toContain("local only");
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
});
