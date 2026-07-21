import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";
import { Daemon, type EmittedAlert } from "../src/daemon/daemon";
import { controlRequest } from "../src/daemon/control";
import { Store } from "../src/core/store/store";
import { listCalls, listLeakEvents } from "../src/viewer/feed-query";
import { listSessions } from "../src/viewer/session-view";
import { buildDetail } from "../src/viewer/detail";
import { parseRequest } from "../src/parsers/parsers";
import { compileRules, scan } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";
import { createServer, type Server } from "node:net";

// The daemon's own corpus, run in-test — for pinning what the BODY scan sees in
// a fixture, so a test about the derived scan can assert that premise instead of
// asserting it in a comment. The hmac key only salts fingerprints here.
const corpusRules = compileRules(
  loadRuleFile(readFileSync("rules/beagle-rules.json", "utf8")),
  new Uint8Array(32).fill(7),
);
const scanRaw = (text: string) => scan(new TextEncoder().encode(text), {}, corpusRules);

// fake upstream that replies with a fixed Anthropic-ish JSON body
function fakeUpstream(replyBody?: string): Promise<{ server: Server; port: number; seen: string[] }> {
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
      const body = replyBody ?? JSON.stringify({
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

// Upstream that holds its response until release() — lets tests flip daemon
// state (pause/resume, TTL sweep) while a call is in flight. `arrived`
// resolves once the forwarded request reaches it.
function slowUpstream(): Promise<{
  server: Server;
  port: number;
  arrived: Promise<void>;
  release: () => void;
}> {
  let requestArrived!: () => void;
  const arrived = new Promise<void>((r) => (requestArrived = r));
  let release!: () => void;
  const released = new Promise<void>((r) => (release = r));
  let sent = false;
  const server = createServer((sock) => {
    sock.on("data", () => {
      requestArrived();
      void released.then(() => {
        if (sent) return; // the request may arrive chunked — reply exactly once
        sent = true;
        const body = JSON.stringify({ model: "m", content: [{ type: "text", text: "slow done" }] });
        sock.write(`HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${body.length}\r\n\r\n${body}`);
      });
    });
    sock.on("error", () => {});
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: (server.address() as { port: number }).port, arrived, release }),
    ),
  );
}

function sendThroughProxy(port: number, runId: string, body: string, path = "/v1/messages"): Promise<string> {
  return new Promise((resolve, reject) => {
    const raw =
      `POST /run/${runId}${path} HTTP/1.1\r\nHost: x\r\n` +
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

// Wait until the daemon has finished capturing everything sent so far. Capture
// is a tracked pipeline promise, so inflight===0 means the call is scanned,
// stored and alerted and nothing more is coming. A fixed sleep cannot say that,
// and a NEGATIVE assertion ("no alert fired") is exactly the shape that passes
// against a sleep for the wrong reason — because the work had not happened yet.
// Timeout stays under bun's 5s per-test default so the diagnostic surfaces.
async function captured(socketPath: string, minCalls = 1, timeoutMs = 4_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const status = await controlRequest(socketPath, { cmd: "status" });
    const d = status.data as { calls: number; inflight: number };
    if (d.calls >= minCalls && d.inflight === 0) return;
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for the daemon to capture ${minCalls} call(s)`);
    }
    await Bun.sleep(10);
  }
}

describe("Daemon end-to-end", () => {
  let stateDir: string;
  let daemon: Daemon;
  let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
  let alerts: EmittedAlert[];

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-daemon-"));
    upstream = await fakeUpstream();
    alerts = [];
    daemon = await Daemon.start({
      stateDir,
      alertSinkForTest: (a) => alerts.push(a),
      persistent: true, // these test capture, not lifecycle — no idle-exit
      exitProcessOnIdle: false, // in-process daemon must never process.exit() the test runner
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

  test("beagle stop: refuses while a lease is held, stops when idle, --force overrides", async () => {
    const { cmdStop } = await import("../src/cli/commands");
    const { openLease } = await import("../src/daemon/control");
    // a live capture session (lease) must block a graceful stop
    const lease = await openLease(daemon.socketPath);
    const refused = await cmdStop(stateDir);
    expect(refused).toContain("live agent session");
    expect(daemon.isRunning).toBe(true);
    lease.end();
    await Bun.sleep(100);
    // idle → stops (the daemon's shutdown calls process.exit in prod; here we
    // just verify the control round-trip asked it to stop)
    const stopping = await cmdStop(stateDir);
    expect(stopping.toLowerCase()).toMatch(/stopped|asked the daemon/);
  });

  test("shutdown refuses while a lease is held, obeys force (daemon re-checks, closing the client race)", async () => {
    const { openLease } = await import("../src/daemon/control");
    const lease = await openLease(daemon.socketPath);
    const refused = await controlRequest(daemon.socketPath, { cmd: "shutdown" });
    expect(refused.ok).toBe(false);
    expect(String(refused.error)).toContain("capturing");
    expect(daemon.isRunning).toBe(true);
    // force overrides even with the lease still held
    const forced = await controlRequest(daemon.socketPath, { cmd: "shutdown", args: { force: true } });
    expect(forced.ok).toBe(true);
    lease.end();
  });

  test("cmdUnwatch refuses mid-capture BEFORE tearing anything down (unless forced)", async () => {
    const { cmdUnwatch } = await import("../src/cli/commands");
    const { openLease } = await import("../src/daemon/control");
    const lease = await openLease(daemon.socketPath);
    const out = await cmdUnwatch(stateDir, "claude");
    expect(out).toContain("not unwatching claude");
    expect(out.toLowerCase()).toContain("live session");
    expect(daemon.isRunning).toBe(true); // nothing torn down
    lease.end();
  });

  test("ping reports the daemon's version so an upgraded CLI can detect a stale daemon", async () => {
    const { BEAGLE_VERSION } = await import("../src/core/version");
    const r = await controlRequest(daemon.socketPath, { cmd: "ping" });
    expect(r.ok).toBe(true);
    expect((r.data as { version?: string }).version).toBe(BEAGLE_VERSION);
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

  // Drives a streamed reply through the proxy and returns the stored row. The
  // frames go out as one chunk; what matters here is the framing the capture
  // path keeps, not how many TCP writes carried it. `extraHeaders` must end
  // with its own CRLF when given. `body` overrides the default well-formed
  // request for tests about the REQUEST side being broken — the marker must
  // then appear in the override, since it is what the poll searches for.
  async function streamedCall(runId: string, marker: string, frames: string, extraHeaders = "", body = requestBody(marker)) {
    let replied = false;
    const server = createServer((sock) => {
      sock.on("data", () => {
        if (replied) return; // the request may arrive chunked — reply exactly once
        replied = true;
        sock.write(`HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n${extraHeaders}transfer-encoding: chunked\r\n\r\n`);
        sock.write(frames.length.toString(16) + "\r\n" + frames + "\r\n0\r\n\r\n");
      });
      sock.on("error", () => {});
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;
    await controlRequest(daemon.socketPath, {
      cmd: "register-run",
      args: { id: runId, agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${port}`, authLocation: "x-api-key" },
    });
    // finally, so a capture that never lands fails on its own assertion rather
    // than leaking a listening socket and an open store handle behind it.
    let store: Store | undefined;
    try {
      await sendThroughProxy(daemon.proxyPort, runId, body);
      let hit: { callId: string } | undefined;
      for (let i = 0; i < 40 && !hit; i++) {
        await Bun.sleep(50); // stays under bun's 5s default so a miss reports, not hangs
        store?.close();
        store = Store.openReadOnly(stateDir);
        hit = store.searchLiteral(marker)[0];
      }
      return store!.getCall(hit!.callId)!;
    } finally {
      store?.close();
      server.close();
    }
  }

  // One text_delta frame carrying `text` verbatim.
  const deltaFrame = (text: string) =>
    'event: content_block_delta\ndata: ' +
    JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }) +
    "\n\n";

  test("a streamed secret under the value-scrub floor is redacted from the stored raw stream", async () => {
    // Nothing scans the raw stream on its own — it borrows the response scan's
    // verdict — and it used to borrow only the VALUES. redactValuesInText floors
    // at 8 chars while connection-string captures the password alone (four chars
    // here), so the span was spliced out of the response body while the stream
    // stored beside it kept the password in cleartext. Same bytes, so that
    // scan's spans reach it. The secret sits in the SECOND frame: the splice
    // only lands right if the stream really is the bytes the scan indexed.
    const call = await streamedCall(
      "run-short-secret",
      "stream a short secret",
      deltaFrame("connecting now, ") + deltaFrame("use postgres://svc:pw12@db.internal/app please"),
    );
    const raw = new TextDecoder().decode(call.sseRaw!);
    expect(raw).not.toContain("pw12");
    expect(raw).toContain("[REDACTED:connection-string:");
    // Spliced, not dropped — and still a well-formed stream. The viewer
    // re-parses this column (viewer/detail.ts), so a splice landing at the
    // wrong offset would corrupt the detail view rather than fail a test.
    const payloads = raw.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5));
    expect(payloads.length).toBe(2);
    const texts = payloads.map((p) => (JSON.parse(p) as { delta: { text: string } }).delta.text);
    expect(texts[0]).toBe("connecting now, "); // the untouched frame is byte-exact
    expect(texts[1]).toContain("[REDACTED:connection-string:");
    // ...and the body beside it agrees: same bytes in, same redaction out.
    expect(new TextDecoder().decode(call.responseBody!)).not.toContain("pw12");
  });

  test("a content-encoded stream is withheld rather than stored on a header's word", async () => {
    // decodeBody falls back to the RAW bytes whenever it cannot decompress, so
    // for a stream whose encoding it could not apply, bodyBytes and sseRaw match
    // byte for byte and the same-bytes check passes — it cannot tell ciphertext
    // from plaintext. The header check is what actually withholds here; without
    // it a genuinely compressed stream carrying a secret no pass can read would
    // be stored. Fixture: an encoding header over a body that is not encoded.
    const call = await streamedCall(
      "run-encoded-stream",
      "stream an encoded secret",
      deltaFrame("use postgres://svc:pw12@db.internal/app please"),
      "content-encoding: gzip\r\n",
    );
    expect(call.sseRaw).toBeNull(); // withheld outright
    // The body is still captured and scrubbed — dropping the stream costs the
    // fidelity view, not the record.
    expect(new TextDecoder().decode(call.responseBody!)).not.toContain("pw12");
  });

  // Same four-char password, the other derived surface. The summary is the
  // always-visible feed line, so it is the worst place for the value-scrub's
  // 8-char floor to hold: the body and the stream beside it were both spliced
  // by span while the line the user actually reads kept the password.
  test("a short streamed secret never reaches the stored summary", async () => {
    const call = await streamedCall(
      "run-short-summary",
      "probe short marker",
      deltaFrame("use postgres://svc:pw12@db.internal/app now"),
    );
    expect(call.summary).not.toContain("pw12");
    expect(call.summary).toContain("[REDACTED:connection-string:");
    expect(call.summary).toContain("probe short marker"); // the line itself survived
  });

  test("a short streamed secret stays out of the summary with redact-on-capture off", async () => {
    // The feed line is the ONE surface that scrubs regardless of the setting,
    // so it cannot be left depending on `redaction.values` to do it.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: false } });
    const call = await streamedCall(
      "run-short-summary-raw",
      "probe raw marker",
      deltaFrame("use postgres://svc:pw12@db.internal/app now"),
    );
    expect(call.summary).not.toContain("pw12");
    expect(call.summary).toContain("[REDACTED:connection-string:");
    expect(call.summary).toContain("probe raw marker"); // the line itself survived
    // ...while the stored bytes keep their raw fidelity, which is what the
    // setting is for. Pinned so the scrub doesn't quietly grow into them.
    expect(new TextDecoder().decode(call.responseBody!)).toContain("pw12");
    // And the row still reads "not redacted": the summary's unconditional
    // scrub deliberately does NOT set that flag, which tracks whether the
    // stored CONTENT was rewritten. A divergence worth pinning, not a bug.
    expect(call.redacted).toBe(false);
  });

  test("a secret split across two SSE frames stays split in the stored stream", async () => {
    // The shape a streaming provider actually produces — deltas cut mid-token.
    // No rule matches either half, so the scanned bytes (which ARE the stream:
    // the capture path decodes content-encoding and reassembles nothing) hold
    // nothing to splice, the same boundary the request-side content-block case
    // below documents for the request body. This fix does not change that; it
    // is pinned here because it is what the raw stream gets asked about.
    //
    // NOT a claim that the key is unreachable: the join manufactures it in the
    // readable text, and while the derived scan keeps it out of the summary,
    // viewer/detail.ts re-parses this column at view time and reassembles it
    // there. Asserted below only for the surfaces that ARE covered.
    const call = await streamedCall(
      "run-split-frames",
      "stream a split secret",
      deltaFrame("key AKIAZQ3DRSTUV") + deltaFrame("WXY2345 done"),
    );
    expect(call.sseRaw).not.toBeNull(); // kept: nothing here was unverified
    expect(call.summary).not.toContain("AKIAZQ3DRSTUVWXY2345"); // the derived scan caught it
    expect(call.redacted).toBe(true);
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
    // search is OUTBOUND-only: `beagle search` answers "was this sent", so a
    // string that appears only in the provider's RESPONSE ("done!") is not a
    // hit — the request text ("read main.ts") above is.
    expect(store.searchLiteral("done!").length).toBe(0);
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
    expect(alerts[0]!.secretType).toBe("aws-access-key-id");
    // the daemon enriches the event with rendered copy before it reaches any
    // surface (this is what the dashboard banner + OS notification consume) —
    // guard the facts→copy wiring, not just the facts.
    expect(alerts[0]!.title).toContain("Beagle");
    expect(alerts[0]!.subtitle).toBe("AWS access key");
    expect(alerts[0]!.body).toContain("beagle ui");

    const store = Store.openReadOnly(stateDir);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]!.destination).toBe("anthropic");
    store.close();
  });

  test("a secret split across two content blocks alerts and stays out of the search index", async () => {
    // The wire path's own copy of the Mode B hole: flattenContent joins a
    // message's content blocks with NOTHING between them, so this key exists in
    // the readable projection — the summary and the search index — while the
    // scanned bytes hold only the two halves either side of `"},{"type":…`.
    // Nothing matched, so nothing alerted and `beagle search` answered with the
    // key. The derived text is scanned on its own now.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "claude-sonnet-5",
        messages: [{
          role: "user",
          content: [
            { type: "text", text: "block one ends AKIAZQ3DRSTUV" },
            { type: "text", text: "WXY2345 begins block two" },
          ],
        }],
      }),
    );
    await Bun.sleep(150);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.secretType).toBe("aws-access-key-id");
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(1);
    // The stored body keeps its bytes — no rule ever matched them, and neither
    // half is a secret on its own.
    const call = store.getCall(store.searchLiteral("block one ends")[0]!.callId)!;
    expect(call.redacted).toBe(true); // the derived surfaces WERE rewritten
    expect(call.summary).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    // …and the VIEWER, which is the surface a human actually reads. A wire row
    // normally carries no stored transcript and the viewer re-parses the body —
    // which would re-join these two blocks and render the assembled key, with
    // the summary and index masked right beside it. The row persists its
    // redacted projection precisely so that re-derive can't happen.
    const { buildDetail, leakSpansFor } = await import("../src/viewer/detail");
    const detail = buildDetail(call, leakSpansFor(store, call.id));
    expect(JSON.stringify(detail.messages)).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(JSON.stringify(detail.messages)).toContain("[REDACTED:aws-access-key-id:");
    // The placeholder lives only in the transcript (the body never held the
    // assembled key), so R7's highlight has to find it there or the one masked
    // surface renders unmarked.
    expect(detail.leaks.map((l) => l.secretType)).toContain("aws-access-key-id");
    store.close();
  });

  test("a `detail` secret UNDER the value-scrub floor is span-redacted", async () => {
    // The sibling of "a persisted transcript scrubs a tool result's detail",
    // and the reason `detail` had to become a scanned part rather than keep the
    // value scrub that test pins: the scrub floors at 8 chars, and
    // connection-string's secretGroup captures the password ALONE, so this one
    // is a FOUR-char value. That test's AWS key clears the floor and so passes
    // under either approach — it structurally cannot catch this. Below the
    // floor, only offsets of its own reach the field. Same row, masked in the
    // body and in the sibling content, printed in full in the detail.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "gpt-5",
        input: [
          { role: "user", content: "run the migration" },
          {
            type: "function_call", call_id: "c1", name: "Bash",
            arguments: JSON.stringify({ command: "psql postgres://svc:pw12@db.internal/app" }),
          },
          { type: "function_call_output", call_id: "c1", output: "ok" },
        ],
      }),
      "/v1/responses",
    );
    await Bun.sleep(150);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("run the migration")[0]!.callId)!;
    // The projection IS persisted here (the derived scan rewrote it), so this is
    // the copy the viewer renders — not a re-parse of the scrubbed body.
    expect(call.displayMessages).not.toBeNull();
    const result = call.displayMessages!.find(
      (m) => (m as { kind?: string }).kind === "result",
    ) as { detail?: string } | undefined;
    // Still labeled — redacted, not dropped: losing the field would hide which
    // command produced the result and pass this test for the wrong reason.
    expect(result?.detail).toBeDefined();
    expect(result!.detail).not.toContain("pw12");
    expect(result!.detail).toContain("[REDACTED:connection-string:");
    expect(JSON.stringify(call.displayMessages)).not.toContain("pw12");
    store.close();
  });

  test("a detail that echoes its own call's arguments doesn't alert twice", async () => {
    // The cost of giving `detail` its own offsets: the same secret is now
    // scanned in two outbound parts, and they are two DIFFERENT strings — a
    // detail decodes one JSON level further than the content it echoes, so the
    // escaped and decoded forms fingerprint differently and land as two leak
    // events rather than one event with two occurrences. Two rows for one
    // secret sent once is exactly what the value-keyed dedup exists to stop.
    // Needs a password carrying an escape, or both forms are the same bytes and
    // the body scan's own dedup would cover this without the echo rule.
    //
    // The fixture carries that password EXACTLY ONCE, inside `arguments`, and
    // that is load-bearing for the count below. Put the same escaped password
    // in a plain user message too and the row emits two events from the BODY
    // scan alone — the body then holds it at two escaping depths, which
    // fingerprint differently — while every derived finding is suppressed by
    // `known` and the echo rule never engages at all. The assertion would then
    // read "2" for reasons that have nothing to do with what it guards.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "gpt-5",
        input: [
          { role: "user", content: "escaped password ask" },
          {
            type: "function_call", call_id: "c1", name: "Bash",
            arguments: JSON.stringify({ command: 'psql postgres://svc:pw"12@db.internal/app' }),
          },
          { type: "function_call_output", call_id: "c1", output: "ok" },
        ],
      }),
      "/v1/responses",
    );
    await Bun.sleep(150);
    const store = Store.openReadOnly(stateDir);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]!.secretType).toBe("connection-string");
    // …and the suppressed half is still REDACTED. Dropping a finding from the
    // alert set must never drop it from the splice — the two are independent,
    // and only the alert set is deduped.
    const call = store.getCall(store.searchLiteral("escaped password ask")[0]!.callId)!;
    expect(JSON.stringify(call.displayMessages)).not.toContain('pw"12');
    expect(JSON.stringify(call.displayMessages)).not.toContain('pw\\"12');
    store.close();
  });

  test("a placeholder that exists only in a `detail` is still highlighted", async () => {
    // R7 marks a redacted row by DISCOVERING placeholders in the text it
    // renders, and dedups them by the whole placeholder — hash included. The
    // hash is over the form found at those offsets, and a detail's form is one
    // escaping level further decoded than its sibling content's, so one secret
    // legitimately leaves two DIFFERENT placeholders. Discovery that reads only
    // `content` finds one of them and the transcript renders the other as
    // unmarked text: masked, but silently.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "gpt-5",
        input: [
          { role: "user", content: "highlight both forms" },
          {
            type: "function_call", call_id: "c1", name: "Bash",
            arguments: JSON.stringify({ command: 'psql postgres://svc:pw"12@db.internal/app' }),
          },
          { type: "function_call_output", call_id: "c1", output: "ok" },
        ],
      }),
      "/v1/responses",
    );
    await Bun.sleep(150);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("highlight both forms")[0]!.callId)!;
    const { buildDetail, leakSpansFor } = await import("../src/viewer/detail");
    const view = buildDetail(call, leakSpansFor(store, call.id));
    const rendered = new Set(
      [...JSON.stringify(view.messages).matchAll(/\[REDACTED:[^\s:\]]+:[0-9a-f]{6}\]/g)].map((m) => m[0]!),
    );
    // The premise: two distinct placeholders, or this asserts nothing.
    expect(rendered.size).toBe(2);
    // Every one of them is marked — the hash is per-install, so this compares
    // what was rendered against what was found rather than pinning literals.
    const found = view.leaks.map((l) => l.value);
    for (const p of rendered) expect(found).toContain(p);
    store.close();
  });

  test("a secret only the DERIVED scan can see is masked in the stored BODY too", async () => {
    // The other half of the derived scan, and the one it left open: a finding
    // the body scan never made cannot be in `requestFindings`, so redactBody
    // masks nothing and the derived pass only rewrites the derived PARTS. The
    // row then reported `redacted: true` over a body still holding the key.
    //
    // JSON escaping is what hides it, and that is the COMMON case rather than a
    // corner (35 of 35 derived-only findings over 671 real wire calls): the
    // generic rule allows `["':=\s]{1,5}` between keyword and value, and the
    // body spends SIX characters on `\": \"` — with a backslash, which is not
    // even in the class — where the parsed message content spends four on `": "`.
    const key = "Xk7Qm2Vb9Rt4Ws8Yz1Nc6Pd3aJ5Hf0Lg";
    const body = JSON.stringify({
      model: "claude-sonnet-5",
      messages: [{ role: "user", content: `config has "api_key": "${key}" in it` }],
    });
    // Precondition, asserted rather than described: the real engine finds
    // NOTHING in these bytes. Without it every assertion below would pass just
    // as well on a body the ordinary span redaction had masked, and the test
    // would stop covering the hole the moment a rule change made the raw form
    // matchable.
    expect(scanRaw(body)).toEqual([]);
    await sendThroughProxy(daemon.proxyPort, "run-e2e", body);
    // Polled, not slept: this row makes THREE worker round-trips (request scan,
    // response scan, derived scan) where its neighbours make two, and on a cold
    // daemon the first also pays worker spawn and rule-pin verification. A
    // fixed delay that loses the race fails as "undefined is not an object" on
    // the line below rather than as what it is.
    let store: Store | undefined;
    let hit: { callId: string } | undefined;
    for (let i = 0; i < 40 && !hit; i++) {
      await Bun.sleep(50);
      store?.close();
      store = Store.openReadOnly(stateDir);
      hit = store.searchLiteral("config has")[0];
    }
    if (!hit) throw new Error("timed out waiting for the derived-only call to be captured");
    const call = store!.getCall(hit.callId)!;
    expect(listLeakEvents(store!).length).toBe(1); // the derived scan did see it
    // THE PIN — the stored payload, which is what redact-on-capture exists to
    // keep off the disk, and the one thing the derived pass never touched.
    const stored = new TextDecoder().decode(call.requestBody!);
    expect(stored).not.toContain(key);
    expect(stored).toContain("[REDACTED:generic-api-key:");
    // Guards, NOT pins: these three held before the fix too. The row flag is
    // ORed with `derived.values.length > 0` upstream so it read true either
    // way, and the index was already fed from the span-redacted projection on
    // a row this one, before the fix, did not count as redacted. They are here
    // so a fix cannot quietly trade one hole for another — read the two
    // assertions above as the ones that fail on a revert.
    expect(call.redacted).toBe(true);
    expect(JSON.stringify(call.displayMessages)).not.toContain(key);
    expect(call.summary).not.toContain(key);
    expect(store!.searchLiteral(key)).toEqual([]);
    store!.close();
  });

  test("a sub-floor derived-only password stays in the body — the residual, pinned", async () => {
    // A KNOWN LIMIT, asserted so it is a decision rather than a discovery.
    // connection-string captures the bare password, four chars here, and the
    // value scrub floors at eight — so extraValues, which has no span to fall
    // back on, cannot reach it. Everything a human READS is still masked: the
    // transcript, the feed line and the index all come from parts the derived
    // scan spliced by offset. What keeps the password is the raw body pane.
    //
    // The fixture is an ordinary Python client, not a contrivance: json.dumps
    // writes `", "` between the two content blocks, and connection-string's
    // `[^\s@\/]{4,}` cannot cross that space — so the body scan reports
    // nothing, and only the flattened text sees the whole URL. Closing this
    // means blanking a four-char string across a whole request body, which
    // takes `root` in a path and every id that contains it along with it.
    const body = '{"model": "claude-sonnet-5", "messages": [{"role": "user", "content": '
      + '[{"type": "text", "text": "python split db: postgres://svc:pw12"}, '
      + '{"type": "text", "text": "@db.internal/app"}]}]}';
    expect(scanRaw(body)).toEqual([]); // the body scan really is blind to it
    await sendThroughProxy(daemon.proxyPort, "run-e2e", body);
    let store: Store | undefined;
    let hit: { callId: string } | undefined;
    for (let i = 0; i < 40 && !hit; i++) {
      await Bun.sleep(50);
      store?.close();
      store = Store.openReadOnly(stateDir);
      hit = store.searchLiteral("python split db")[0];
    }
    if (!hit) throw new Error("timed out waiting for the split connection string to be captured");
    const call = store!.getCall(hit.callId)!;
    // The derived scan DID see it, so the surfaces built from its parts are clean…
    expect(call.summary).not.toContain("pw12");
    expect(JSON.stringify(call.displayMessages)).not.toContain("pw12");
    expect(store!.searchLiteral("svc:pw12")).toEqual([]);
    // …and this is the part that is not. If a change starts covering it, this
    // line fails on purpose — promote it, don't delete it.
    expect(new TextDecoder().decode(call.requestBody!)).toContain("pw12");
    store!.close();
  });

  test("scrubbing the body by value does NOT move the search index off the projection", async () => {
    // Two derived-only findings on one call, and they need different surfaces:
    // the api_key is verbatim in the body, so the value scrub reaches it and
    // the bodies really are rewritten — while the AWS key is MANUFACTURED by
    // the join between two content blocks, so it exists in no body at all and
    // only the projection's span covers it.
    //
    // The trap: making `redacted` honest about the value pass also flipped the
    // flag that decides which surface feeds fts5. Following it would index the
    // body — where the manufactured key sits as two innocent-looking halves 25
    // bytes apart — in place of a projection that carries one placeholder over
    // the whole thing. The index follows the SPANS now, so it doesn't.
    const key = "Xk7Qm2Vb9Rt4Ws8Yz1Nc6Pd3aJ5Hf0Lg";
    const body = JSON.stringify({
      model: "claude-sonnet-5",
      messages: [{
        role: "user",
        content: [
          { type: "text", text: `config has "api_key": "${key}" and creds AKIAZQ3DRSTUV` },
          { type: "text", text: "WXY2345 done" },
        ],
      }],
    });
    expect(scanRaw(body)).toEqual([]); // premise: neither is visible in the bytes
    await sendThroughProxy(daemon.proxyPort, "run-e2e", body);
    let store: Store | undefined;
    let hit: { callId: string } | undefined;
    for (let i = 0; i < 40 && !hit; i++) {
      await Bun.sleep(50);
      store?.close();
      store = Store.openReadOnly(stateDir);
      hit = store.searchLiteral("config has")[0];
    }
    if (!hit) throw new Error("timed out waiting for the two-finding call to be captured");
    // searchLiteral is a substring match, so a HALF of the manufactured key is a
    // hit if the raw body reached the index. Both halves, because splicing a
    // finding that spans the join masks it out of both parts.
    expect(store!.searchLiteral("AKIAZQ3DRSTUV")).toEqual([]);
    expect(store!.searchLiteral("WXY2345")).toEqual([]);
    // …while the body is still scrubbed of the value that WAS in it, which is
    // the fix this test must not undo.
    expect(new TextDecoder().decode(store!.getCall(hit.callId)!.requestBody!)).not.toContain(key);
    store!.close();
  });

  test("a derived-only secret in the REPLY is scrubbed from the response body and the raw stream", async () => {
    // The inbound half of the same hole, and the path extraValues newly
    // reaches: `redaction.values` is what redactRawStream borrows for the SSE
    // column (it has no scan of its own), so before this the stream and the
    // response body both kept a key only the reply's derived text matched.
    // Same escaping cause read on the response: a text_delta frame serializes
    // the quotes, so the scanned bytes spend six characters on `\": \"` while
    // the reassembled answer spends four.
    const key = "Tq9Wn3Zx6Bv1Mk8Ld5Rf2Cp7Gs4Hj0Y";
    const frames = deltaFrame(`config has "api_key": "${key}" here`);
    expect(scanRaw(frames)).toEqual([]); // premise: nothing matches the bytes
    const call = await streamedCall("run-derived-reply", "ask about the reply", frames);
    const body = new TextDecoder().decode(call.responseBody!);
    expect(body).not.toContain(key);
    expect(body).toContain("[REDACTED:generic-api-key:");
    // The fidelity column, which nothing scans on its own.
    expect(call.sseRaw).not.toBeNull();
    expect(new TextDecoder().decode(call.sseRaw!)).not.toContain(key);
    // …and it still alerts on NOTHING: a secret in the model's answer came FROM
    // the provider, so it is redacted without being attributed to the agent.
    // The asymmetry the response-body scan already holds, now that the derived
    // scan reaches this half too.
    expect(alerts.length).toBe(0);
  });

  test("an ordinary wire call still renders from its body, with no stored transcript", async () => {
    // The guard on the row above: persisting a projection is the EXCEPTION, for
    // rows whose body would re-derive wrongly. Every other call keeps the old
    // behaviour — nothing extra stored, the viewer re-parses byte-exact bytes —
    // so the fix can't quietly double every row's storage.
    await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("just an ordinary ask"));
    await Bun.sleep(150);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("just an ordinary ask")[0]!.callId)!;
    expect(call.displayMessages).toBeNull();
    const detail = buildDetail(call, []);
    expect(detail.messages[0]!.content).toBe("just an ordinary ask");
    expect(detail.system).toBe("You are Claude Code."); // still lifted from the body
    store.close();
  });

  test("a tool call's ARGS are masked, not just its detail", async () => {
    // args is the tool card's BODY (app.js draws `args ?? detail`), and for
    // anthropic-messages it is JSON.stringify(input) — a RE-SERIALIZATION that
    // decodes \uXXXX. A key written escaped in the response bytes matches no
    // rule there, so nothing is spliced and no matched value exists to scrub
    // by; only scanning the re-serialized string reaches it. Masking `detail`
    // alone left the unmasked copy winning on the same card.
    const key = "AKIAZQ3DRSTUVWXY2345";
    const escaped = "\\u0041KIAZQ3DRSTUVWXY2345"; // A === "A"
    const reply = `{"model":"m","content":[{"type":"tool_use","name":"bash","id":"t1","input":{"command":"aws set k ${escaped}"}}]}`;
    const server = createServer((sock) => {
      let sent = false;
      sock.on("data", () => {
        if (sent) return;
        sent = true;
        sock.write(`HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${reply.length}\r\n\r\n${reply}`);
      });
      sock.on("error", () => {});
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    let store: Store | undefined;
    try {
      const port = (server.address() as { port: number }).port;
      await controlRequest(daemon.socketPath, {
        cmd: "register-run",
        args: { id: "run-tool-args", agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${port}`, authLocation: "x-api-key" },
      });
      await sendThroughProxy(daemon.proxyPort, "run-tool-args", requestBody("escaped tool arg"));
      let hit: { callId: string } | undefined;
      for (let i = 0; i < 40 && !hit; i++) {
        await Bun.sleep(50);
        store?.close();
        store = Store.openReadOnly(stateDir);
        hit = store.searchLiteral("escaped tool arg")[0];
      }
      if (!hit) throw new Error("timed out waiting for the tool-call reply to be captured");
      const call = store!.getCall(hit.callId)!;
      // The bytes hold only the ESCAPED form, so no rule matched and nothing was
      // spliced — the precondition that makes this unreachable by body redaction.
      expect(new TextDecoder().decode(call.responseBody!)).not.toContain(key);
      // …and this row is a live instance of the residual applyCaptureRedaction's
      // extraValues note documents: the derived value is the DECODED key, and
      // none of the three forms scrubbed from these bytes is `AKIA…`,
      // because \uXXXX is an escape JSON.stringify never emits for an ASCII
      // letter. Pinned deliberately, the way the two-events case in
      // tests/otlp-daemon.test.ts is: the card the user reads is masked (below),
      // the raw pane still shows the bytes as received. A change that starts
      // reaching this should update this line, not discover it.
      expect(new TextDecoder().decode(call.responseBody!)).toContain("\\u0041KIAZQ3DRSTUVWXY2345");
      const action = buildDetail(call, []).responseCalls[0]!;
      expect(action.args ?? "").not.toContain(key);
      expect(action.detail ?? "").not.toContain(key);
      expect(action.args ?? "").toContain("[REDACTED:aws-access-key-id:");
      expect(action.tool).toBe("bash"); // the card still renders
    } finally {
      store?.close();
      server.close();
    }
  });

  test("a manufactured secret is masked in the view even with redact-on-capture OFF", async () => {
    // The setting buys the raw view of bytes that were ON THE WIRE. This key
    // never was in that form — the reassembly builds it at read time out of two
    // individually innocent frames — so there is no raw copy for the opt-out to
    // protect, and storing nothing just meant the viewer rebuilt it. Same line
    // the always-visible summary already draws.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: false } });
    try {
      const call = await streamedCall(
        "run-split-noredact",
        "stream a split secret unredacted",
        deltaFrame("key AKIAZQ3DRSTUV") + deltaFrame("WXY2345 done"),
      );
      const d = buildDetail(call, []);
      expect(d.responseText).not.toContain("AKIAZQ3DRSTUVWXY2345");
      expect(d.responseText).toContain("[REDACTED:aws-access-key-id:");
      // The raw panes still show every byte as received — that IS the setting.
      expect(new TextDecoder().decode(call.sseRaw!)).toContain("AKIAZQ3DRSTUV");
    } finally {
      await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    }
  });

  test("a reply-split secret is masked in the view even when the REQUEST doesn't parse", async () => {
    // The projection gate used to require `parsed`, but the reply parses on its
    // own: a truncated or malformed request body still ships with a streamed
    // answer whose reassembly is exactly the re-derive the projection exists to
    // preempt. Before the fix this row stored NO transcript, so the viewer
    // rebuilt the split key whole from the stored frames — under a header that
    // read "secrets masked in storage" (redacted=1 via the derived OR), with no
    // placeholder anywhere for extractLeaks to highlight. The value scrub can't
    // reach it either: the whole key never sits contiguously in any stored byte.
    const key = "AKIAZQ3DRSTUVWXY2345";
    // Cut mid-string, the shape a captureState "truncated" body actually has.
    const reqBody = '{"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "unparseable request, reply splits a key';
    expect(parseRequest("anthropic-messages", new TextEncoder().encode(reqBody))).toBeNull();
    const frames = deltaFrame("key AKIAZQ3DRSTUV") + deltaFrame("WXY2345 done");
    // Premise: whole in no frame and absent from the request, so no body scan
    // matches anything — the row's redacted flag comes from the derived pass alone.
    expect(scanRaw(frames)).toEqual([]);
    expect(scanRaw(reqBody)).toEqual([]);
    const call = await streamedCall("run-unparseable-req", "unparseable request", frames, "", reqBody);
    // The header line this row prints is only honest if the reply really is masked.
    expect(call.redacted).toBe(true);
    expect(call.displayMessages).not.toBeNull();
    expect(JSON.stringify(call.displayMessages)).not.toContain(key);
    const d = buildDetail(call, []);
    expect(d.responseText).not.toContain(key);
    expect(d.responseText).toContain("[REDACTED:aws-access-key-id:");
    // …and the placeholder is discoverable, so the masked reply is highlighted.
    expect(d.leaks.some((l) => l.secretType === "aws-access-key-id")).toBe(true);
    // The request half stays honestly absent — the empty system head must not
    // surface as a phantom prompt or message.
    expect(d.system).toBeNull();
    expect(d.messages).toEqual([]);
    // From the provider, not the agent: a reply-side secret still never alerts.
    await captured(daemon.socketPath);
    expect(alerts.length).toBe(0);
  });

  test("a pasted QUOTED .env line alerts, end to end", async () => {
    // The scanner reads the wire body, where requestBody has turned the pasted
    // quotes into \" — so the secret's separator is an escape, not a bare
    // quote. This is the whole user-visible point of that rule's escape
    // handling: before it, the same paste unquoted alerted and quoted did not,
    // because the demoted finding never cleared AlertEngine's structured gate.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      requestBody('here is my env:\nAWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYZZZZZKEY42"\nplease use it'),
    );
    await Bun.sleep(150);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.secretType).toBe("aws-secret-access-key");
    expect(alerts[0]!.subtitle).toBe("AWS secret key");
  });

  test("a persisted transcript scrubs a tool result's detail, not just its content", async () => {
    // The derived pass scans and rewrites `content` only: outboundParts is
    // built from m.content, and the persist replaces m.content. But a
    // Responses-API tool RESULT also carries `detail` — the originating call's
    // command/pattern/query, lifted by responsesItem — which is display text
    // stored and rendered exactly like content. Nothing scans it and nothing
    // scrubs it, so a secret in a tool's arguments rides into display_messages
    // raw, on a row that alerted and whose body redacted.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "gpt-5",
        input: [
          {
            type: "function_call", call_id: "c1", name: "Bash",
            arguments: JSON.stringify({ command: "deploy --key AKIAZQ3DRSTUVWXY2345" }),
          },
          { type: "function_call_output", call_id: "c1", output: "deployed ok" },
        ],
      }),
      "/v1/responses",
    );
    await Bun.sleep(200);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("deployed ok")[0]!.callId)!;
    // Precondition: this row DID persist a projection (otherwise the assertion
    // below would pass for the wrong reason — nothing stored to leak).
    expect(call.displayMessages).not.toBeNull();
    expect(JSON.stringify(call.displayMessages)).not.toContain("AKIAZQ3DRSTUVWXY2345");
    const { buildDetail, leakSpansFor } = await import("../src/viewer/detail");
    const view = buildDetail(call, leakSpansFor(store, call.id));
    expect(JSON.stringify(view.messages)).not.toContain("AKIAZQ3DRSTUVWXY2345");
    // Load-bearing: scrubbing is the fix, DROPPING the field is not. Without
    // this the assertions above pass just as well for a projection that threw
    // `detail` away, losing the result header's "what was this call" label.
    const result = view.messages.find((m) => m.kind === "result")!;
    expect(result.detail).toContain("[REDACTED:aws-access-key-id:");
    expect(result.detail).toContain("deploy --key");
    store.close();
  });

  test("a secret only the JOINED prompt reveals is detected on the wire path", async () => {
    // The block-split case above is manufactured by flattenContent's join("").
    // This is the OTHER join, the one derivedScanText itself owns: messages are
    // joined with "\n", so a multi-line secret whose halves sit in two adjacent
    // messages is whole in the derived text while the scanned bytes run
    // BEGIN…END straight through the structural `"},{"role":"user","content":"`.
    // The wire equivalent of tests/otlp-daemon.test.ts's spanning-PEM case,
    // which until now covered Mode B only.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "claude-sonnet-5",
        messages: [
          { role: "user", content: "part one:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwireSplitAcrossMessages" },
          { role: "user", content: "part two:\nbbb\n-----END RSA PRIVATE KEY-----" },
        ],
      }),
    );
    await captured(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    // The body scan sees a PEM too — its value carries the `"},{"role":…` the
    // display drops, so the two are different strings that nothing can key
    // together. Same deliberate double-alert the Mode B test pins.
    expect(listLeakEvents(store).length).toBe(2);
    expect(alerts.some((a) => a.secretType === "private-key")).toBe(true);
    const call = store.getCall(store.searchLiteral("part one")[0]!.callId)!;
    const dm = JSON.stringify(call.displayMessages);
    expect(dm).not.toContain("MIIEowIBAAKCAQEAwireSplitAcrossMessages");
    expect(dm).toContain("[REDACTED:private-key:");
    expect(store.searchLiteral("MIIEowIBAAKCAQEAwireSplitAcrossMessages")).toEqual([]);
    store.close();
  });

  test("a benign message boundary cannot manufacture an alert", async () => {
    // The false-positive guard the derived scan never had on any path. Joining
    // every message with "\n" puts text next to text that was never adjacent,
    // and the generic detector is context-gated — `(?:key|secret|token…)` then
    // ["':=\s]{1,5} then the value — so an ordinary message ending in one of
    // those words, followed by an ordinary one starting with a token-shaped
    // string, is exactly the shape that would manufacture a leak out of nothing.
    // Measured over 671 real captured/reassembled wire calls this never fired,
    // and that has to stay true: an alert here is a lie about what was sent.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "claude-sonnet-5",
        messages: [
          { role: "user", content: "remind me how the store handles the refresh token" },
          { role: "assistant", content: "It rotates on every call; see store.ts." },
          { role: "user", content: "ExchangesFtsContentRowid is the column, right?" },
        ],
      }),
    );
    // Quiesce, not a sleep: this asserts an ABSENCE, so it has to be able to
    // tell "nothing fired" from "nothing has run yet".
    await captured(daemon.socketPath);
    expect(alerts.length).toBe(0);
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(0);
    const call = store.getCall(store.searchLiteral("refresh token")[0]!.callId)!;
    // Nothing was rewritten, so the row must not claim it was — and it keeps
    // the cheap no-transcript shape rather than persisting a projection.
    expect(call.redacted).toBe(false);
    expect(call.displayMessages).toBeNull();
    store.close();
  });

  test("a derived-only leak that sits verbatim in the body keeps a usable highlight", async () => {
    // Why the body scan can miss a value the body plainly contains: the generic
    // rule allows ["':=\s]{1,5} between keyword and value, and a JSON body
    // spends six characters on `\": \"` where the unescaped derived text spends
    // four on `": "`. Measured on real traffic this is the COMMON reason a
    // derived-only finding exists — 35 of 35 such findings re-anchored — so
    // these earn a body span instead of being span-less on principle, which
    // left the one masked surface rendering unmarked.
    // redact-on-capture off: that is the only state in which the viewer
    // consults spans at all (a redacted row highlights placeholders instead).
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: false } });
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "claude-sonnet-5",
        messages: [{ role: "user", content: 'config has "api_key": "Xk7Qm2Vb9Rt4Ws8Yz1Nc6Pd3aJ5Hf0Lg" in it' }],
      }),
    );
    await captured(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]!.secretType).toBe("generic-api-key");
    const call = store.getCall(store.searchLiteral("config has")[0]!.callId)!;
    const { buildDetail, leakSpansFor } = await import("../src/viewer/detail");
    const spans = leakSpansFor(store, call.id);
    // The span was recorded and it indexes the STORED body: slicing it back has
    // to return the secret itself, not neighbouring JSON.
    expect(spans.length).toBe(1);
    const raw = new TextDecoder().decode(call.requestBody!);
    expect(raw.slice(spans[0]!.start, spans[0]!.end)).toBe("Xk7Qm2Vb9Rt4Ws8Yz1Nc6Pd3aJ5Hf0Lg");
    expect(buildDetail(call, spans).leaks.map((l) => l.value)).toContain(
      "Xk7Qm2Vb9Rt4Ws8Yz1Nc6Pd3aJ5Hf0Lg",
    );
    store.close();
  });

  test("under redact-on-capture the derived span is recorded but placeholders win", async () => {
    // The boundary of the test above, and the reason the re-anchor is narrower
    // than it looks: ANY derived finding produces a redacted part, so with
    // redact-on-capture on — the default — the row reads `redacted` and
    // extractLeaks takes the placeholder branch, discarding every span. The
    // span is still written (the row may later be read with a different view),
    // it is simply not what the viewer uses here.
    //
    // Pinned because the tempting "improvement" — unioning span-recovered
    // values into the placeholder branch — is a BUG: on a redacted row the body
    // was rewritten underneath these offsets, so slicing by them returns a
    // fragment of whatever now occupies them. If someone removes the gate in
    // extractLeaks, this fails.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "claude-sonnet-5",
        messages: [{ role: "user", content: 'cfg has "api_key": "Xk7Qm2Vb9Rt4Ws8Yz1Nc6Pd3aJ5Hf0Lg" here' }],
      }),
    );
    await captured(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("cfg has")[0]!.callId)!;
    expect(call.redacted).toBe(true);
    const { leakSpansFor } = await import("../src/viewer/detail");
    const spans = leakSpansFor(store, call.id);
    expect(spans.length).toBe(1); // the anchor still ran
    // …and the viewer ignored it: every leak it reports is a placeholder, none
    // is a slice taken at those offsets.
    const leaks = buildDetail(call, spans).leaks;
    expect(leaks.length).toBeGreaterThan(0);
    for (const l of leaks) expect(l.value.startsWith("[REDACTED:")).toBe(true);
    store.close();
  });

  test("a failure in one derived alert pass does not take the other down with it", () => {
    // The derived findings go out in TWO alertEngine.process calls, because the
    // span flag is per-call: re-anchored findings carry body offsets, the rest
    // are span-less. process() opens a store transaction per finding, so it can
    // throw — and one call split into two means a throw in the first would lose
    // every finding in the second. That half is the higher-value one: a secret
    // the body scan structurally cannot see, which this pass is the only chance
    // to report. Pinned white-box because there is no way to make the real
    // store fail on demand.
    const seen: Array<{ n: number; bodySpans: boolean }> = [];
    const d = daemon as unknown as {
      alertEngine: { process: (m: unknown, f: unknown[], b: boolean) => void };
      alertDerived: (m: unknown, derived: unknown) => number;
    };
    d.alertEngine = {
      process: (_m, f, bodySpans) => {
        seen.push({ n: f.length, bodySpans });
        if (bodySpans) throw new Error("store transaction failed");
      },
    };
    const finding = (start: number) => ({
      detector: "generic-api-key", secretType: "generic", severity: "medium",
      tier: "possible", start, end: start + 4, fingerprint: `fp${start}`,
      destinationOwnKey: false,
    });
    expect(() =>
      d.alertDerived(
        { id: "call-1", sessionId: "sess-1", provider: "anthropic" },
        {
          outbound: [], inbound: [], values: [],
          anchoredFindings: [finding(0)], leakFindings: [finding(9)],
          incomplete: false,
        },
      ),
    ).toThrow("store transaction failed");
    // Both passes ran, in order, and the span-less one was not collateral.
    expect(seen).toEqual([
      { n: 1, bodySpans: true },
      { n: 1, bodySpans: false },
    ]);
  });

  test("protocol identity fields (prompt_cache_key) never create leak events", async () => {
    // The exact false positive from live traffic: opencode's own session id,
    // high-entropy and preceded by "…key", flagged by the generic detector.
    await sendThroughProxy(
      daemon.proxyPort, "run-e2e",
      JSON.stringify({
        model: "m",
        messages: [{ role: "user", content: "hello there" }],
        prompt_cache_key: "ses_092219142ffe1QxlfF0u9eAL0B",
      }),
    );
    await Bun.sleep(150);
    expect(alerts.length).toBe(0);
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(0);          // no event, either tier
    expect(listCalls(store, 5).some((c) => c.hasLeak)).toBe(false);
    store.close();
  });

  test("opencode /responses: prompt_cache_key groups the conversation; title-gen one-shots never cross-link", async () => {
    // A REAL /responses reply, with a response id: every turn must survive a
    // full recordResponse cycle (a resp_… id must not clobber the session's
    // cache-key identity — conv_id is a single column).
    const ocUpstream = await fakeUpstream(JSON.stringify({
      id: "resp_upstream_1",
      output: [{ type: "message", content: [{ type: "output_text", text: "ok" }] }],
      usage: { input_tokens: 1, output_tokens: 1 },
    }));
    await controlRequest(daemon.socketPath, {
      cmd: "register-run",
      args: { id: "run-oc", agent: "opencode", provider: "openai",
        upstream: `http://127.0.0.1:${ocUpstream.port}`, authLocation: "authorization" },
    });
    // opencode's title-generation turn: store:false, no cache key, and the
    // SAME instructions + opening message in every conversation — the shape
    // that used to fuzzy-link into the oldest look-alike session.
    const titleGen = (firstPrompt: string) => JSON.stringify({
      model: "gpt-5", store: false, instructions: "You are a title generator. Output only a title.",
      input: [
        { role: "user", content: [{ type: "input_text", text: "Generate a title for this conversation:\n" }] },
        { role: "user", content: [{ type: "input_text", text: firstPrompt }] },
      ],
    });
    // A conversational call: opencode pins its own session id as the cache key.
    const convo = (key: string, text: string) => JSON.stringify({
      model: "gpt-5", prompt_cache_key: key, instructions: "You are opencode.",
      input: [{ role: "user", content: [{ type: "input_text", text }] }],
    });
    await sendThroughProxy(daemon.proxyPort, "run-oc", titleGen("first convo opening"), "/v1/responses");
    await sendThroughProxy(daemon.proxyPort, "run-oc", convo("ses_A", "first convo opening"), "/v1/responses");
    await sendThroughProxy(daemon.proxyPort, "run-oc", titleGen("second convo opening"), "/v1/responses");
    await sendThroughProxy(daemon.proxyPort, "run-oc", convo("ses_B", "second convo opening"), "/v1/responses");
    // Disjoint follow-up — no shared history prefix at all; the cache key
    // alone must pin it to conversation A.
    await sendThroughProxy(daemon.proxyPort, "run-oc", convo("ses_A", "totally different follow-up"), "/v1/responses");
    await Bun.sleep(150);

    const store = Store.openReadOnly(stateDir);
    const oc = listCalls(store, 20).filter((c) => c.agent === "opencode").reverse(); // oldest first
    const utilityById = new Map(listSessions(store, 50).map((s) => [s.sessionId, s.utility]));
    store.close();
    ocUpstream.server.close();
    expect(oc.length).toBe(5);
    const [t1, a1, t2, b1, a2] = oc;
    expect(a2!.sessionId).toBe(a1!.sessionId);     // the cache key groups conversation A…
    expect(a2!.sessionTier).toBe("conv-id");       // …deterministically, not by heuristic
    expect(b1!.sessionId).not.toBe(a1!.sessionId); // B is its own conversation
    expect(t2!.sessionId).not.toBe(t1!.sessionId); // identical title-gens never merge…
    expect(t2!.sessionId).not.toBe(b1!.sessionId); // …and don't glue onto a conversation
    // …and the sessions list knows which is which: title turns badge as
    // utility sessions, real conversations never do.
    expect(utilityById.get(t1!.sessionId)).toBe(true);
    expect(utilityById.get(t2!.sessionId)).toBe(true);
    expect(utilityById.get(a1!.sessionId)).toBe(false);
    expect(utilityById.get(b1!.sessionId)).toBe(false);
  });

  test("multi-turn conversation stays one session; re-sent secret alerts once", async () => {
    // This case searches for the raw secret to prove session grouping, so it
    // opts into raw capture — redaction is on by default now (secure default),
    // which would mask the value out of the search index.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: false } });
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

  test("a secret MANUFACTURED by SSE delta reassembly is scrubbed from the summary", async () => {
    // The response-side twin of the split-content-block case, and the reason
    // the derived scan can't be gated on the body scan having found something.
    // The provider streams the key across two text_delta frames, so it is split
    // in the raw stream AND split in the response body — the only place it is
    // contiguous is parseResponse's reassembly, which is exactly what the
    // summary renders. Both scans come back clean, so there is no matched value
    // for a scrub to key off: only scanning the reassembled text reaches it.
    //
    // Inbound, so it must NOT alert — the key came FROM the provider, the same
    // asymmetry redactDerived holds by scanning the response half separately.
    //
    // Asserted on every surface the value reached, INCLUDING the detail view.
    // That one is the reason `display_derived` exists: buildDetail re-derives
    // at read time, and a manufactured secret leaves the stored body untouched
    // (there was nothing in the bytes to rewrite), so the re-parse handed the
    // key back on every page load even once the summary and index were clean.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    const key = "AKIAZQ3DRSTUVWXY2345";
    const delta = (text: string) =>
      `event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"${text}"}}\n\n`;
    // Split mid-key so neither frame carries anything a rule can match.
    const frames = delta(`key is ${key.slice(0, 11)}`) + delta(`${key.slice(11)} ok`);
    const streamServer = createServer((sock) => {
      sock.on("data", () => {
        sock.write("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n");
        sock.write(frames.length.toString(16) + "\r\n" + frames + "\r\n0\r\n\r\n");
      });
      sock.on("error", () => {});
    });
    await new Promise<void>((r) => streamServer.listen(0, "127.0.0.1", () => r()));
    let store: Store | undefined;
    // finally, not a trailing close(): an assertion below throws past any
    // cleanup after it, and a leaked listener outlives the test.
    try {
      const sport = (streamServer.address() as { port: number }).port;
      await controlRequest(daemon.socketPath, {
        cmd: "register-run",
        args: { id: "run-split-sse", agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${sport}`, authLocation: "x-api-key" },
      });
      await sendThroughProxy(daemon.proxyPort, "run-split-sse", requestBody("hello there"));
      let hit: { callId: string } | undefined;
      store = Store.openReadOnly(stateDir);
      for (let i = 0; i < 40 && !hit; i++) {
        await Bun.sleep(50);
        store.close();
        store = Store.openReadOnly(stateDir);
        hit = store.searchLiteral("hello there")[0];
      }
      // Named, so a capture that never lands reads as that rather than as a
      // TypeError on `undefined.callId` two lines later.
      if (!hit) throw new Error("timed out waiting for the streamed call to be captured");
      const call = store.getCall(hit.callId)!;
      // Neither scanned surface ever held it contiguously, which is what makes
      // this unreachable by any scrub keyed off the body's matched values.
      expect(new TextDecoder().decode(call.sseRaw!)).not.toContain(key);
      expect(new TextDecoder().decode(call.responseBody!)).not.toContain(key);
      expect(call.summary).not.toContain(key);
      expect(call.summary).toContain("[REDACTED:aws-access-key-id:");
      expect(call.redacted).toBe(true); // the derived pass rewrote content, so the row says so
      expect(listLeakEvents(store).length).toBe(0); // inbound: redacted, never alerted
      expect(alerts.length).toBe(0);
      // …and the DETAIL view, which is where this leaked longest: it re-runs
      // parseResponse on the stored body, and the body was never rewritten
      // (the scan found nothing in it to rewrite), so the reassembly handed
      // the key back on every page load. The stored projection is what stops
      // that — assert through buildDetail, not through the row.
      const { buildDetail } = await import("../src/viewer/detail");
      const detail = buildDetail(call, []);
      expect(detail.responseText).not.toContain(key);
      expect(detail.responseText).toContain("[REDACTED:aws-access-key-id:");
    } finally {
      store?.close();
      streamServer.close();
    }
  });

  test("the derived join does NOT fuse two innocuous messages into a leak", async () => {
    // The cost of scanning parts joined: the separator is whitespace, and the
    // quiet rules' delimiter classes accept whitespace — generic-api-key is
    // `(?:…|token|…)["':=\s]{1,5}(value)`. So a message ending "…an API token"
    // followed by one starting with a base64-ish word matches ACROSS the join,
    // and nothing like it was ever sent: the two are adjacent only here.
    //
    // It cost twice. A bogus leak event, and — worse — the genuinely-sent text
    // replaced by a placeholder in the search index, so `beagle search` denies
    // a string that DID leave the machine. That is a false negative on the one
    // question search answers definitively, manufactured by a false positive.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    const benign = "aG9sZDEyMzQ1Njc4OTB4eXo3Nzc";
    const body = JSON.stringify({
      model: "claude-sonnet-5",
      messages: [
        { role: "user", content: "FPSENTINEL yes - that endpoint needs an API token" },
        { role: "assistant", content: `${benign} please try again` },
      ],
    });
    await sendThroughProxy(daemon.proxyPort, "run-e2e", body);
    await Bun.sleep(250);
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(0); // no leak was manufactured
    expect(alerts.length).toBe(0);
    // The text was genuinely sent, so search must still find it.
    expect(store.searchLiteral(benign).length).toBe(1);
    const call = store.getCall(store.searchLiteral("FPSENTINEL")[0]!.callId)!;
    expect(call.redacted).toBe(false);
    store.close();
  });

  test("summary stays bounded when a tool detail is huge and isn't a path", async () => {
    // toolAction deliberately stops clamping so the secret scrub sees whole
    // values, which makes bounding the READER's job. Two summarizeActions
    // branches take `detail.split("/").pop()` — and that returns the WHOLE
    // string when there is no "/" in it. A Grep `pattern` or a `query` is
    // exactly that, so the stored summary grew to the size of the tool input.
    // summary is the always-visible feed line, stored per row and broadcast to
    // every open dashboard.
    const pattern = "z".repeat(5000); // no "/" — the tail-taking branch
    const reply = JSON.stringify({
      model: "claude-sonnet-5",
      content: [{ type: "tool_use", id: "t1", name: "Grep", input: { pattern } }],
      usage: { input_tokens: 5, output_tokens: 2 },
    });
    const up = await fakeUpstream(reply);
    try {
      await controlRequest(daemon.socketPath, {
        cmd: "register-run",
        args: { id: "run-bigdetail", agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${up.port}`, authLocation: "x-api-key" },
      });
      await sendThroughProxy(daemon.proxyPort, "run-bigdetail", requestBody("find it"));
      await Bun.sleep(250);
      const store = Store.openReadOnly(stateDir);
      const call = store.getCall(store.searchLiteral("find it")[0]!.callId)!;
      expect(call.summary).not.toContain(pattern);
      expect(call.summary?.length ?? 0).toBeLessThan(200);
      store.close();
    } finally {
      up.server.close();
    }
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

  test("call started while paused is dropped even if resumed before the response", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    const slow = await slowUpstream();
    await controlRequest(daemon.socketPath, {
      cmd: "register-run",
      args: { id: "run-slow", agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${slow.port}`, authLocation: "x-api-key" },
    });

    await controlRequest(daemon.socketPath, { cmd: "pause" });
    const respP = sendThroughProxy(
      daemon.proxyPort, "run-slow",
      requestBody("paused-time secret AKIAZQ3DRSTUVWXY2345"),
    );
    await slow.arrived; // request forwarded → the skip decision is already made
    await controlRequest(daemon.socketPath, { cmd: "resume" });
    slow.release();
    await respP;
    await Bun.sleep(150);

    // The never-scanned body must not be stored at all — in particular not
    // raw with scanState "ok".
    let store = Store.openReadOnly(stateDir);
    expect(store.countCalls()).toBe(0);
    expect(store.searchLiteral("paused-time secret")).toEqual([]);
    store.close();

    // The skip is per-call, not sticky: post-resume traffic captures normally.
    await sendThroughProxy(daemon.proxyPort, "run-e2e", requestBody("after the race"));
    await Bun.sleep(150);
    store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("after the race").length).toBe(1);
    store.close();
    slow.server.close();
  });

  test("a capture whose pending entry was TTL-swept mid-flight is stored incomplete, not raw-ok", async () => {
    // A genuinely long in-flight call: the scan runs and a pending entry is
    // created, but the sweep evicts it (TTL passed) before the slow response
    // lands. captureCall then finds no stash — and must not label the never-
    // trusted body scanState "ok". End-to-end via short TTL knobs, so the real
    // sweep + capture path is exercised, not a hand-driven captureCall.
    const dir = mkdtempSync(join(tmpdir(), "beagle-ttl-"));
    const up = await slowUpstream();
    const d = await Daemon.start({
      stateDir: dir,
      persistent: true,
      pendingTtlMs: 120,
      sweepIntervalMs: 60,
    });
    try {
      await controlRequest(d.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
      await controlRequest(d.socketPath, {
        cmd: "register-run",
        args: { id: "run-ttl", agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${up.port}`, authLocation: "x-api-key" },
      });
      const respP = sendThroughProxy(d.proxyPort, "run-ttl", requestBody("stash-gone secret AKIAZQ3DRSTUVWXY2345"));
      await up.arrived;
      await Bun.sleep(300); // let the pending entry age past its TTL and a sweep evict it
      up.release();
      await respP;
      await Bun.sleep(150);

      const store = Store.openReadOnly(dir);
      const rows = listCalls(store, 10); // body/summary are withheld, so find by feed row
      expect(rows.length).toBe(1);
      const call = store.getCall(rows[0]!.id)!;
      expect(call.scanState).toBe("incomplete");
      expect(new TextDecoder().decode(call.requestBody!)).toContain("[REDACTION INCOMPLETE");
      expect(call.responseBody).toBeNull();
      expect(call.summary).toBe("[REDACTION INCOMPLETE: content withheld]");
      expect(store.searchLiteral("stash-gone secret")).toEqual([]);
      store.close();
    } finally {
      await d.stop();
      up.server.close();
      rmSync(dir, { recursive: true, force: true });
    }
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

  // The summary derives from the same raw messages the body redaction already
  // scrubbed — it must not carry the secret into the always-visible feed,
  // `beagle show`, or the viewer.
  // `content` defaults to a reply with no text, so buildSummary falls back to
  // the last user message — the line that carries the secret. Pass blocks to
  // put the secret on the RESPONSE side instead.
  async function silentRun(
    runId: string,
    content: unknown[] = [],
  ): Promise<Awaited<ReturnType<typeof fakeUpstream>>> {
    const silent = await fakeUpstream(JSON.stringify({ model: "claude-sonnet-5", content, usage: {} }));
    await controlRequest(daemon.socketPath, {
      cmd: "register-run",
      args: { id: runId, agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${silent.port}`, authLocation: "x-api-key" },
    });
    return silent;
  }

  test("redact-on-capture scrubs the secret from the summary", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    const silent = await silentRun("run-summary");
    await sendThroughProxy(daemon.proxyPort, "run-summary", requestBody("my key AKIAZQ3DRSTUVWXY2345 leaked"));
    await Bun.sleep(200);
    const store = Store.openReadOnly(stateDir);
    const ex = listCalls(store, 10).find((e) => e.hasLeak)!;
    expect(ex.summary).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(ex.summary).toContain("[REDACTED:aws-access-key-id:");
    store.close();
    silent.server.close();
  });

  test("a short secret in a tool action's detail never reaches the stored summary", async () => {
    // The action branch is the ONLY reader of the inbound half's i + 1 offset
    // (inbound is [reply, ...one per action]), and it is the summary's other
    // response-side surface — a shell command carrying a password is the shape
    // this rule exists for. Two actions, because one cannot distinguish a
    // correct offset from one that slid the empty reply into slot 0 and every
    // detail down by one: `second-cmd` is what pins it. Read at i instead of
    // i + 1 and the summary misreports what the agent ran.
    const silent = await silentRun("run-action-secret", [
      { type: "tool_use", name: "Bash", input: { command: "psql postgres://svc:pw12@db.internal/app" } },
      { type: "tool_use", name: "Bash", input: { command: "echo second-cmd" } },
    ]);
    await sendThroughProxy(daemon.proxyPort, "run-action-secret", requestBody("probe action marker"));
    await Bun.sleep(200);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("probe action marker")[0]!.callId)!;
    expect(call.summary).not.toContain("pw12");
    // summarizeActions caps each detail at 40 chars AFTER the splice, so only
    // the placeholder's head survives this branch — enough to prove a splice.
    expect(call.summary).toContain("[REDACTED:connectio");
    expect(call.summary).toContain("second-cmd"); // the second action's OWN detail
    store.close();
    silent.server.close();
  });

  test("a short secret in a request message never reaches the stored summary", async () => {
    // The outbound half of the same hole. The reply is empty, so the summary
    // quotes the user line the password sits in — and at 100 chars the whole
    // placeholder survives here, unlike the 40-char action branch above.
    const silent = await silentRun("run-req-short");
    await sendThroughProxy(
      daemon.proxyPort, "run-req-short",
      requestBody("connect with postgres://svc:pw12@db.internal/app"),
    );
    await Bun.sleep(200);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("connect with")[0]!.callId)!;
    expect(call.summary).not.toContain("pw12");
    expect(call.summary).toContain("[REDACTED:connection-string:");
    expect(call.summary).toContain("connect with"); // the line itself survived
    store.close();
    silent.server.close();
  });

  test("summary redaction survives the 100-char truncation splitting the secret", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    const silent = await silentRun("run-straddle");
    // Secret starts at char 95: truncating first and scrubbing after would
    // keep the secret's head, so the scrub must run before the cap.
    await sendThroughProxy(
      daemon.proxyPort, "run-straddle",
      requestBody("p".repeat(94) + " AKIAZQ3DRSTUVWXY2345"),
    );
    await Bun.sleep(200);
    const store = Store.openReadOnly(stateDir);
    const ex = listCalls(store, 10).find((e) => e.hasLeak)!;
    expect(ex.summary).not.toContain("AKIA");
    // ...and the cap lands past the placeholder, not through it: a `[RED…`
    // stump reads as a corrupted line and names no secret type.
    expect(ex.summary).toMatch(/\[REDACTED:aws-access-key-id:[0-9a-f]{6}\]/);
    store.close();
    silent.server.close();
  });

  test("an incomplete scan under redact-on-capture withholds body, summary, and search text", async () => {
    // A 0ms scan deadline fires before the worker can respond: every scan
    // reports incomplete, the fail-safe path.
    const dir2 = mkdtempSync(join(tmpdir(), "beagle-incomplete-"));
    const up = await fakeUpstream();
    const d2 = await Daemon.start({ stateDir: dir2, persistent: true, scanDeadlineMs: 0, alertSinkForTest: () => {} });
    try {
      await controlRequest(d2.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
      await controlRequest(d2.socketPath, {
        cmd: "register-run",
        args: { id: "run-inc", agent: "claude-code", provider: "anthropic", upstream: `http://127.0.0.1:${up.port}`, authLocation: "x-api-key" },
      });
      await sendThroughProxy(d2.proxyPort, "run-inc", requestBody("unverified AKIAZQ3DRSTUVWXY2345 here"));
      await Bun.sleep(300);
      const store = Store.openReadOnly(dir2);
      const ex = listCalls(store, 10)[0]!;
      expect(ex.scanState).toBe("incomplete");
      expect(ex.summary).toBe("[REDACTION INCOMPLETE: content withheld]");
      const full = store.getCall(ex.id)!;
      expect(new TextDecoder().decode(full.requestBody!)).not.toContain("AKIAZQ3DRSTUVWXY2345");
      expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
      expect(store.searchLiteral("unverified")).toEqual([]); // search index withheld too
      store.close();
    } finally {
      await d2.stop();
      up.server.close();
    }
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

// stop() drains in-flight pipeline writes before closing the store. Both ways
// that drain can betray its own purpose — returning before it finishes, or
// never finishing — lose the write it exists to protect, so both are pinned.
describe("Daemon shutdown", () => {
  test("concurrent stop() callers await the same drain", async () => {
    // stop() is bound to SIGINT *and* SIGTERM (cli/main.ts), and idle-exit and
    // the shutdown command reach it too — each as stop().then(process.exit).
    // A double Ctrl-C must not exit out from under the first caller's drain.
    const dir = mkdtempSync(join(tmpdir(), "beagle-stop-race-"));
    const d = await Daemon.start({ stateDir: dir, persistent: true, exitProcessOnIdle: false });
    const first = d.stop();
    const second = d.stop();
    expect(second).toBe(first); // one drain, not a race
    await Promise.all([first, second]);
    rmSync(dir, { recursive: true, force: true });
  });

  test("stop() completes when the store throws mid-scan-pipeline", async () => {
    // captureCall awaits scanDone with no timeout, so a throw between the scan
    // and resolveScan() would wedge the capture — and the drain with it. The
    // 5s per-test timeout is the assertion: pre-fix this hung forever.
    const up = await fakeUpstream();
    const dir = mkdtempSync(join(tmpdir(), "beagle-stop-wedge-"));
    const d = await Daemon.start({
      stateDir: dir, persistent: true, exitProcessOnIdle: false,
      scanDeadlineMs: 0, // every scan reports incomplete → updateCallScanState runs
      alertSinkForTest: () => {},
    });
    await controlRequest(d.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    await controlRequest(d.socketPath, {
      cmd: "register-run",
      args: { id: "run-wedge", agent: "claude-code", provider: "anthropic",
        upstream: `http://127.0.0.1:${up.port}`, authLocation: "x-api-key" },
    });
    (d as unknown as { store: { updateCallScanState: () => void } }).store.updateCallScanState = () => {
      throw new Error("Database has closed");
    };
    await sendThroughProxy(d.proxyPort, "run-wedge", JSON.stringify({
      model: "claude-sonnet-5", messages: [{ role: "user", content: "hello there" }],
    }));
    await d.stop();
    up.server.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
