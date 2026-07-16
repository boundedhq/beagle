import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Daemon } from "../src/daemon/daemon";
import { controlRequest } from "../src/daemon/control";
import { Store } from "../src/core/store/store";
import { listCalls, listLeakEvents } from "../src/viewer/feed-query";
import type { AlertEvent } from "../src/core/alert/engine";

// Claude Code's real Mode-B export (event schema, verified in the Phase-0
// spike): a turn is a user_prompt + api_request + assistant_response sharing
// session.id/prompt.id. The run token rides the HTTP header, not an attribute.
function otlpBody(_token: string, prompt: string | null, sessionId = "otel-conv-1", response: string | null = "acknowledged") {
  const ev = (name: string, attrs: Record<string, string | number>) => ({
    timeUnixNano: String(Date.now() * 1e6),
    body: { stringValue: `claude_code.${name}` },
    attributes: [
      { key: "event.name", value: { stringValue: name } },
      { key: "session.id", value: { stringValue: sessionId } },
      { key: "prompt.id", value: { stringValue: "prompt-x" } },
      ...Object.entries(attrs).map(([key, value]) =>
        typeof value === "number"
          ? { key, value: { intValue: value } }
          : { key, value: { stringValue: value } },
      ),
    ],
  });
  return {
    resourceLogs: [{
      scopeLogs: [{
        scope: { name: "com.anthropic.claude_code.events" },
        logRecords: [
          ...(prompt === null ? [] : [ev("user_prompt", { prompt })]),
          ev("api_request", { model: "claude-sonnet-5", input_tokens: 50, output_tokens: 4 }),
          ...(response === null ? [] : [ev("assistant_response", { model: "claude-sonnet-5", response })]),
        ],
      }],
    }],
  };
}

// The receiver 200s before the ingest pipeline (scan → insert → alert) runs,
// so a fixed sleep races it under CI load.
// Default stays under bun's 5s per-test timeout, so a real regression surfaces
// as "timed out waiting for <what>" rather than a bare bun timeout.
async function waitFor(cond: () => boolean | Promise<boolean>, what: string, timeoutMs = 4_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await cond())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(10);
  }
}

// Wait until the daemon has fully finished the batch(es) posted so far: the
// receiver's ingest is one tracked promise per batch, so inflight===0 means
// every call in it is scanned, stored and alerted — nothing more is coming.
// Waiting on the alert sink instead would return at the FIRST alert and let a
// spurious second one land after the assertion, silently passing `toBe(1)`.
// `minCalls` guards the start of the race, before ingest has been dispatched.
async function settled(socketPath: string, minCalls = 1): Promise<void> {
  await waitFor(async () => {
    const status = await controlRequest(socketPath, { cmd: "status" });
    const d = status.data as { calls: number; inflight: number };
    return d.calls >= minCalls && d.inflight === 0;
  }, `the daemon to finish ingesting ${minCalls} call(s)`);
}

describe("Mode B end-to-end through the daemon", () => {
  let stateDir: string;
  let daemon: Daemon;
  let alerts: AlertEvent[];
  let otlpPort: number;
  let token: string;

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-modeb-"));
    alerts = [];
    daemon = await Daemon.start({ stateDir, alertSinkForTest: (a) => alerts.push(a), persistent: true });
    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort: number; otlpToken: string };
    otlpPort = data.otlpPort;
    token = data.otlpToken;
  });

  afterEach(async () => {
    await daemon.stop();
  });

  async function post(body: unknown) {
    return fetch(`http://127.0.0.1:${otlpPort}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": token },
      body: JSON.stringify(body),
    });
  }

  test("OTel-reported call is captured, labeled otel, and scanned", async () => {
    const r = await post(otlpBody(token, "please read the readme"));
    expect(r.status).toBe(200);
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const hits = store.searchLiteral("please read the readme");
    expect(hits.length).toBe(1);
    const call = store.getCall(hits[0]!.callId)!;
    expect(call.source).toBe("otel");
    expect(call.model).toBe("claude-sonnet-5");
    expect(call.tokensOut).toBe(4);
    store.close();
  });

  test("Mode B call persists its display messages for the session transcript", async () => {
    await post(otlpBody(token, "please read the readme"));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("please read the readme")[0]!.callId)!;
    // the self-report's structure survives persistence (schema v3) — this is
    // what the viewer's transcript and detail views render for Mode B rows
    expect(call.displayMessages).toEqual([{ role: "user", content: "please read the readme" }]);
    store.close();
  });

  test("redact-on-capture scrubs display messages too", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    await post(otlpBody(token, "my key AKIAZQ3DRSTUVWXY2345 leaked", "otel-conv-dm", null));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("my key")[0]!.callId)!;
    const dm = JSON.stringify(call.displayMessages);
    expect(dm).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(dm).toContain("[REDACTED:aws-access-key-id:");
    store.close();
  });

  test("a leaked secret in an OTel-reported prompt fires the same alert", async () => {
    await post(otlpBody(token, "the key is AKIAZQ3DRSTUVWXY2345"));
    await settled(daemon.socketPath);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.title).toContain("aws-access-key-id");
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(1);
    store.close();
  });

  test("one batch carrying two turns fires one alert per turn", async () => {
    // The agent batches its export, so a single POST can carry several turns —
    // ingestOtel awaits the scanner per call and yields between them. Nothing
    // pins the fixtures above to one turn each, so pin the multi-turn shape
    // here: it is what makes their exact `toBe(1)` counts meaningful.
    const ev = (sid: string, prompt: string) => ({
      timeUnixNano: String(Date.now() * 1e6),
      body: { stringValue: "claude_code.user_prompt" },
      attributes: [
        { key: "event.name", value: { stringValue: "user_prompt" } },
        { key: "session.id", value: { stringValue: sid } },
        { key: "prompt.id", value: { stringValue: `p-${sid}` } },
        { key: "prompt", value: { stringValue: prompt } },
      ],
    });
    await post({ resourceLogs: [{ scopeLogs: [{
      scope: { name: "com.anthropic.claude_code.events" },
      logRecords: [
        ev("otel-two-a", "first key AKIAZQ3DRSTUVWXY2345 here"),
        ev("otel-two-b", "second key AKIAZQ3DRSTUVWXY6789 here"),
      ],
    }] }] });
    await settled(daemon.socketPath, 2);
    expect(alerts.length).toBe(2);
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(2); // distinct secrets — neither deduped away
    store.close();
  });

  test("redact-on-capture scrubs Mode B body, search text, and summary", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    // No assistant_response in the batch: the summary falls back to the raw
    // prompt line — exactly where the secret sits.
    await post(otlpBody(token, "my key AKIAZQ3DRSTUVWXY2345 leaked", "otel-conv-r", null));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    // the leak event still exists (audit value kept)...
    expect(listLeakEvents(store).length).toBe(1);
    // ...but the raw secret is gone from the body, the index, and the summary
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    const hit = store.searchLiteral("my key")[0]!;
    const call = store.getCall(hit.callId)!;
    expect(call.redacted).toBe(true);
    const body = new TextDecoder().decode(call.requestBody!);
    expect(body).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(body).toContain("[REDACTED:aws-access-key-id:");
    expect(call.summary).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(call.summary).toContain("[REDACTED:aws-access-key-id:");
    store.close();
  });

  test("redact-on-capture scrubs a secret echoed in a response-only batch", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    // The prompt that leaked the key rode an earlier batch; this batch carries
    // only the assistant's echo — no request-side scan surface at all.
    await post(otlpBody(token, null, "otel-conv-echo", "your key is AKIAZQ3DRSTUVWXY2345"));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    const hit = store.searchLiteral("your key is")[0]!;
    const call = store.getCall(hit.callId)!;
    expect(call.redacted).toBe(true);
    expect(new TextDecoder().decode(call.responseBody!)).toContain("[REDACTED:aws-access-key-id:");
    expect(call.summary).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(call.summary).toContain("[REDACTED:aws-access-key-id:");
    // Inbound content is redacted but never alerts — the outbound leak fired
    // with the batch that carried the prompt.
    expect(alerts.length).toBe(0);
    store.close();
  });

  test("an incomplete Mode B scan withholds body, summary, and search text", async () => {
    // A 0ms scan deadline fires before the worker can respond: every scan
    // reports incomplete, the fail-safe path.
    const dir2 = mkdtempSync(join(tmpdir(), "beagle-modeb-inc-"));
    const d2 = await Daemon.start({ stateDir: dir2, persistent: true, scanDeadlineMs: 0, alertSinkForTest: () => {} });
    try {
      const status = await controlRequest(d2.socketPath, { cmd: "status" });
      const data = status.data as { otlpPort: number; otlpToken: string };
      await controlRequest(d2.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
      await fetch(`http://127.0.0.1:${data.otlpPort}/v1/logs`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-beagle-run": data.otlpToken },
        body: JSON.stringify(otlpBody(data.otlpToken, "unverified AKIAZQ3DRSTUVWXY2345")),
      });
      await settled(d2.socketPath);
      const store = Store.openReadOnly(dir2);
      expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
      expect(store.searchLiteral("unverified")).toEqual([]); // search index withheld too
      const ex = listCalls(store, 10)[0]!;
      expect(ex.scanState).toBe("incomplete");
      expect(ex.summary).toBe("[REDACTION INCOMPLETE: content withheld]");
      const full = store.getCall(ex.id)!;
      expect(new TextDecoder().decode(full.requestBody!)).toContain("[REDACTION INCOMPLETE");
      store.close();
    } finally {
      await d2.stop();
    }
  });

  test("wrong OTLP token is rejected, nothing captured", async () => {
    const r = await fetch(`http://127.0.0.1:${otlpPort}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": "wrong" },
      body: JSON.stringify(otlpBody("wrong", "should not be stored")),
    });
    expect(r.status).toBe(401);
    // No wait: the token gate 401s before the body is even read, so no ingest
    // was ever dispatched — there is nothing asynchronous to settle.
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("should not be stored")).toEqual([]);
    store.close();
  });
});

describe("Mode B tool-output capture (PostToolUse hook)", () => {
  let stateDir: string;
  let daemon: import("../src/daemon/daemon").Daemon;
  let alerts: import("../src/core/alert/engine").AlertEvent[];
  let otlpPort: number;
  let token: string;

  beforeEach(async () => {
    const { mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { Daemon } = await import("../src/daemon/daemon");
    stateDir = mkdtempSync(join(tmpdir(), "beagle-hook-"));
    alerts = [];
    daemon = await Daemon.start({ stateDir, alertSinkForTest: (a) => alerts.push(a), persistent: true });
    const status = await (await import("../src/daemon/control")).controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort: number; otlpToken: string };
    otlpPort = data.otlpPort;
    token = data.otlpToken;
  });
  afterEach(async () => { await daemon.stop(); });

  test("a secret in a TOOL OUTPUT (cat .env) fires an alert — the Mode B gap, closed", async () => {
    // This is exactly what the OTel export can't see: the secret is only in the
    // tool's RESULT, never in the prompt or the command.
    const hook = { session_id: "sess-x", tool_name: "Bash",
      tool_input: { command: "cat secrets.env" },
      tool_response: "AWS_SECRET=AKIAZQ3DRSTUVWXY2345\n" };
    const r = await fetch(`http://127.0.0.1:${otlpPort}/v1/hook`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": token },
      body: JSON.stringify(hook),
    });
    expect(r.status).toBe(200);
    await settled(daemon.socketPath);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.title).toContain("aws-access-key-id");
  });
});

// Codex on a ChatGPT login can't be wire-proxied; --telemetry captures it via
// Codex's own OTel export (codex.* schema, scope codex_otel.log_only). Unlike
// Claude Code, that export carries tool OUTPUT inline — no hook needed.
function codexBody(name: string, attrs: Record<string, string>) {
  return {
    resourceLogs: [{
      scopeLogs: [{
        scope: { name: "codex_otel.log_only" },
        logRecords: [{
          timeUnixNano: String(Date.now() * 1e6),
          attributes: [
            { key: "event.name", value: { stringValue: name } },
            { key: "conversation.id", value: { stringValue: "codex-conv-1" } },
            ...Object.entries(attrs).map(([key, value]) => ({ key, value: { stringValue: value } })),
          ],
        }],
      }],
    }],
  };
}

describe("Codex Mode B end-to-end through the daemon", () => {
  let stateDir: string;
  let daemon: Daemon;
  let alerts: AlertEvent[];
  let otlpPort: number;
  let token: string;

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-codex-"));
    alerts = [];
    daemon = await Daemon.start({ stateDir, alertSinkForTest: (a) => alerts.push(a), persistent: true });
    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort: number; otlpToken: string };
    otlpPort = data.otlpPort;
    token = data.otlpToken;
  });
  afterEach(async () => { await daemon.stop(); });

  const post = (body: unknown) =>
    fetch(`http://127.0.0.1:${otlpPort}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": token },
      body: JSON.stringify(body),
    });

  test("a codex prompt is captured, labeled codex/openai, and scanned", async () => {
    const r = await post(codexBody("codex.user_prompt", { prompt: "refactor the parser", model: "gpt-5.6" }));
    expect(r.status).toBe(200);
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const hits = store.searchLiteral("refactor the parser");
    expect(hits.length).toBe(1);
    const call = store.getCall(hits[0]!.callId)!;
    expect(call.source).toBe("otel");
    expect(call.agent).toBe("codex");
    expect(call.provider).toBe("openai");
    store.close();
  });

  test("a secret in a codex PROMPT fires the leak alert", async () => {
    await post(codexBody("codex.user_prompt", { prompt: "ship it with AKIAZQ3DRSTUVWXY2345" }));
    await settled(daemon.socketPath);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.title).toContain("aws-access-key-id");
  });

  test("a secret in a codex TOOL OUTPUT (cat key.txt) fires the leak alert — no hook needed", async () => {
    // Codex exports the tool result inline, so the secret is visible in Mode B
    // without the PostToolUse hook Claude Code requires for the same coverage.
    await post(codexBody("codex.tool_result", {
      tool_name: "exec_command",
      arguments: '{"cmd":"cat key.txt"}',
      output: "token = AKIAZQ3DRSTUVWXY2345",
    }));
    await settled(daemon.socketPath);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.title).toContain("aws-access-key-id");
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(1);
    store.close();
  });
});
