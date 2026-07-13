import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Daemon } from "../src/daemon/daemon";
import { controlRequest } from "../src/daemon/control";
import { Store } from "../src/core/store/store";
import { listLeakEvents } from "../src/viewer/feed-query";
import type { AlertEvent } from "../src/core/alert/engine";

// Claude Code's real Mode-B export (event schema, verified in the Phase-0
// spike): a turn is a user_prompt + api_request + assistant_response sharing
// session.id/prompt.id. The run token rides the HTTP header, not an attribute.
function otlpBody(_token: string, prompt: string, sessionId = "otel-conv-1") {
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
          ev("user_prompt", { prompt }),
          ev("api_request", { model: "claude-sonnet-5", input_tokens: 50, output_tokens: 4 }),
          ev("assistant_response", { model: "claude-sonnet-5", response: "acknowledged" }),
        ],
      }],
    }],
  };
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
    await Bun.sleep(100);
    const store = Store.openReadOnly(stateDir);
    const hits = store.searchLiteral("please read the readme");
    expect(hits.length).toBe(1);
    const call = store.getCall(hits[0]!.callId)!;
    expect(call.source).toBe("otel");
    expect(call.model).toBe("claude-sonnet-5");
    expect(call.tokensOut).toBe(4);
    store.close();
  });

  test("a leaked secret in an OTel-reported prompt fires the same alert", async () => {
    await post(otlpBody(token, "the key is AKIAZQ3DRSTUVWXY2345"));
    await Bun.sleep(100);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.title).toContain("aws-access-key-id");
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(1);
    store.close();
  });

  test("wrong OTLP token is rejected, nothing captured", async () => {
    const r = await fetch(`http://127.0.0.1:${otlpPort}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": "wrong" },
      body: JSON.stringify(otlpBody("wrong", "should not be stored")),
    });
    expect(r.status).toBe(401);
    await Bun.sleep(50);
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("should not be stored")).toEqual([]);
    store.close();
  });
});
