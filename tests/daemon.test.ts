import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";
import { Daemon } from "../src/daemon/daemon";
import { controlRequest } from "../src/daemon/control";
import { Store } from "../src/core/store/store";
import { listCalls, listLeakEvents } from "../src/viewer/feed-query";
import type { AlertEvent } from "../src/core/alert/engine";
import { createServer, type Server } from "node:net";

// fake upstream that replies with a fixed Anthropic-ish JSON body
function fakeUpstream(): Promise<{ server: Server; port: number; seen: string[] }> {
  const seen: string[] = [];
  const server = createServer((sock) => {
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString("latin1");
      const i = buf.indexOf("\r\n\r\n");
      if (i === -1) return;
      const m = buf.match(/content-length:\s*(\d+)/i);
      const need = i + 4 + (m ? Number(m[1]) : 0);
      if (buf.length < need) return;
      seen.push(buf.slice(0, need));
      buf = "";
      const body = JSON.stringify({
        model: "claude-sonnet-5",
        content: [{ type: "text", text: "done!" }],
        usage: { input_tokens: 9, output_tokens: 3 },
      });
      sock.write(`HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${body.length}\r\n\r\n${body}`);
    });
    sock.on("error", () => {});
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: (server.address() as { port: number }).port, seen }),
    ),
  );
}

function sendThroughProxy(port: number, runId: string, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const raw =
      `POST /run/${runId}/v1/messages HTTP/1.1\r\nHost: x\r\n` +
      `x-api-key: sk-ant-realkey000000000000000000\r\ncontent-type: application/json\r\n` +
      `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
    const sock = connect(port, "127.0.0.1", () => sock.write(raw));
    let got = "";
    let quiet: ReturnType<typeof setTimeout> | null = null;
    sock.on("data", (d) => {
      got += d.toString();
      if (quiet) clearTimeout(quiet);
      quiet = setTimeout(() => sock.end(), 100);
    });
    sock.on("close", () => resolve(got));
    sock.on("error", reject);
  });
}

describe("Daemon end-to-end", () => {
  let stateDir: string;
  let daemon: Daemon;
  let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
  let alerts: AlertEvent[];

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-daemon-"));
    upstream = await fakeUpstream();
    alerts = [];
    daemon = await Daemon.start({
      stateDir,
      alertSinkForTest: (a) => alerts.push(a),
      persistent: true, // these test capture, not lifecycle — no idle-exit
    });
    await controlRequest(daemon.socketPath, {
      cmd: "register-run",
      args: {
        id: "run-e2e",
        agent: "claude-code",
        provider: "anthropic",
        upstream: `http://127.0.0.1:${upstream.port}`,
        authLocation: "x-api-key",
      },
    });
  });

  afterEach(async () => {
    await daemon.stop();
    upstream.server.close();
  });

  const requestBody = (content: string) =>
    JSON.stringify({
      model: "claude-sonnet-5",
      system: "You are Claude Code.",
      messages: [{ role: "user", content }],
    });

  test("streaming call persists the raw SSE stream (sse_raw)", async () => {
    // upstream in this rig returns a non-streamed JSON body, so drive a
    // streaming upstream to exercise the fidelity column.
    const streamServer = createServer((sock) => {
      sock.on("data", () => {
        sock.write("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n");
        const e = 'event: content_block_delta\ndata: {"delta":{"type":"text_delta","text":"hi"}}\n\n';
        sock.write(e.length.toString(16) + "\r\n" + e + "\r\n0\r\n\r\n");
      });
      sock.on("error", () => {});
    });
    await new Promise<void>((r) => streamServer.listen(0, "127.0.0.1", () => r()));
    const sport = (streamServer.address() as { port: number }).port;
    await controlRequest(daemon.socketPath, {
      cmd: "register-run",
      args: { id: "run-stream", agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${sport}`, authLocation: "x-api-key" },
    });
    await sendThroughProxy(daemon.proxyPort, "run-stream", requestBody("stream please"));
    // poll for the capture instead of guessing a delay
    let hit: { callId: string } | undefined;
    let store = Store.openReadOnly(stateDir);
    for (let i = 0; i < 40 && !hit; i++) {
      await Bun.sleep(50);
      store.close();
      store = Store.openReadOnly(stateDir);
      hit = store.searchLiteral("stream please")[0];
    }
    const call = store.getCall(hit!.callId)!;
    expect(call.sseRaw).not.toBeNull();
    expect(new TextDecoder().decode(call.sseRaw!)).toContain("event: content_block_delta");
    store.close();
    streamServer.close();
  });

  test("captures a full call: session, parse, summary, search text", async () => {
    const resp = await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("read main.ts"));
    expect(resp).toContain("done!");
    await Bun.sleep(150);

    const store = Store.openReadOnly(stateDir);
    const hits = store.searchLiteral("read main.ts");
    expect(hits.length).toBe(1);
    const call = store.getCall(hits[0]!.callId)!;
    expect(call.provider).toBe("anthropic");
    expect(call.model).toBe("claude-sonnet-5");
    expect(call.sessionTier).toBe("prefix");
    expect(call.tokensOut).toBe(3);
    expect(call.scanState).toBe("ok");
    // response text also searchable
    expect(store.searchLiteral("done!").length).toBe(1);
    store.close();
  });

  test("a captured call is pushed to an open viewer as an SSE 'call' event", async () => {
    // Guards the daemon->viewer->app.js contract: the live feed event MUST be
    // named "call" (app.js listens for exactly that). A one-sided rename of the
    // event name would slip past tsc (app.js is buildless) — this catches it.
    const ui = await controlRequest(daemon.socketPath, { cmd: "ui" });
    const url = new URL((ui.data as { url: string }).url);
    const sess = await fetch(`${url.origin}/api/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ boot: url.searchParams.get("boot") }),
    });
    const cred = ((await sess.json()) as { credential: string }).credential;

    // Subscribe to the live feed BEFORE driving traffic so the push can't be missed.
    const stream = await fetch(`${url.origin}/api/stream`, { headers: { "x-beagle-token": cred } });
    const reader = stream.body!.getReader();
    const dec = new TextDecoder();

    await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("push me live"));

    // Read frames until the pushed event arrives; bounded so a miss fails, not hangs.
    const timer = setTimeout(() => void reader.cancel(), 3000);
    let buf = "";
    try {
      while (!buf.includes("event: call")) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
      }
    } finally {
      clearTimeout(timer);
      await reader.cancel().catch(() => {});
    }
    expect(buf).toContain("event: call"); // the renamed event, not "exchange"
    expect(buf).not.toContain("event: exchange");
    expect(buf).toContain('"summary"'); // frame carries the feed row
  });

  test("leak in request body alerts in real time and records the event", async () => {
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      requestBody('here is my key: AKIAZQ3DRSTUVWXY2345'),
    );
    await Bun.sleep(150);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.title).toContain("aws-access-key-id");

    const store = Store.openReadOnly(stateDir);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]!.destination).toBe("anthropic");
    store.close();
  });

  test("multi-turn conversation stays one session; re-sent secret alerts once", async () => {
    const secret = 'key AKIAZQ3DRSTUVWXY2345';
    const turn1 = JSON.stringify({
      model: "m", system: "s",
      messages: [{ role: "user", content: secret }],
    });
    const turn2 = JSON.stringify({
      model: "m", system: "s",
      messages: [
        { role: "user", content: secret },
        { role: "assistant", content: "done!" },
        { role: "user", content: "next" },
      ],
    });
    await sendThroughProxy(daemon.proxyPort, "run-e2e", turn1);
    await Bun.sleep(100);
    await sendThroughProxy(daemon.proxyPort, "run-e2e", turn2);
    await Bun.sleep(150);

    expect(alerts.length).toBe(1); // deduped
    const store = Store.openReadOnly(stateDir);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]!.occurrences).toBe(2); // both calls marked
    const sessions = new Set(store.searchLiteral("AKIAZQ3DRSTUVWXY2345").map((h) => h.sessionId));
    expect(sessions.size).toBe(1);
    store.close();
  });

  test("auth header is scrubbed in the persisted call", async () => {
    await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("hello"));
    await Bun.sleep(150);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("hello")[0]!.callId)!;
    const persisted = JSON.stringify(call.requestHeaders);
    expect(persisted).not.toContain("sk-ant-realkey");
    expect(persisted).toContain("[AUTH:anthropic:");
    store.close();
  });

  test("control socket: ping, status, pause/resume", async () => {
    const pong = await controlRequest(daemon.socketPath, { cmd: "ping" });
    expect(pong.ok).toBe(true);

    await controlRequest(daemon.socketPath, { cmd: "pause" });
    await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("while paused"));
    await Bun.sleep(150);
    let store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("while paused")).toEqual([]); // forwarded, not captured
    store.close();

    await controlRequest(daemon.socketPath, { cmd: "resume" });
    await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("after resume"));
    await Bun.sleep(150);
    store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("after resume").length).toBe(1);

    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    expect(status.ok).toBe(true);
    expect((status.data as { calls: number }).calls).toBeGreaterThan(0);
    store.close();
  });

  test("redact-on-capture removes the raw secret from the stored body", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      requestBody("my aws key AKIAZQ3DRSTUVWXY2345 here"),
    );
    await Bun.sleep(200);
    const store = Store.openReadOnly(stateDir);
    // the leak event still exists (audit value kept)...
    expect(listLeakEvents(store).length).toBe(1);
    // ...but the raw secret is gone from the stored payload and the index
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    const anyEx = listCalls(store, 10).find((e) => e.hasLeak);
    const full = store.getCall(anyEx!.id)!;
    expect(new TextDecoder().decode(full.requestBody!)).toContain("[REDACTED:aws-access-key-id:");
    store.close();
  });

  test("excluded agent traffic is forwarded but never captured", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { excludedAgents: ["claude-code"] } });
    const resp = await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("excluded content"));
    expect(resp).toContain("done!"); // still forwarded
    await Bun.sleep(150);
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("excluded content")).toEqual([]);
    store.close();
  });

  test("purge via socket wipes captures", async () => {
    await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("sensitive thing"));
    await Bun.sleep(150);
    const r = await controlRequest(daemon.socketPath, { cmd: "purge", args: { kind: "all" } });
    expect(r.ok).toBe(true);
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("sensitive thing")).toEqual([]);
    store.close();
  });
});
