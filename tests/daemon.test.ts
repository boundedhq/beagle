import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";
import { Daemon, type EmittedAlert } from "../src/daemon/daemon";
import { controlRequest } from "../src/daemon/control";
import { Store } from "../src/core/store/store";
import { listCalls, listLeakEvents } from "../src/viewer/feed-query";
import { listSessions } from "../src/viewer/session-view";
import { createServer, type Server } from "node:net";

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
  // with its own CRLF when given.
  async function streamedCall(runId: string, marker: string, frames: string, extraHeaders = "") {
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
      await sendThroughProxy(daemon.proxyPort, runId, requestBody(marker));
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
    const { buildDetail } = await import("../src/viewer/detail");
    const detail = buildDetail(call, []);
    expect(detail.messages[0]!.content).toBe("just an ordinary ask");
    expect(detail.system).toBe("You are Claude Code."); // still lifted from the body
    store.close();
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
  async function silentRun(runId: string): Promise<Awaited<ReturnType<typeof fakeUpstream>>> {
    // A reply with no text: buildSummary falls back to the last user message —
    // the line that carries the secret.
    const silent = await fakeUpstream(JSON.stringify({ model: "claude-sonnet-5", content: [], usage: {} }));
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
