import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { parseUpstream, ResponseReader } from "../src/core/proxy/http1";
import { decodeBody, scrubAuthHeaders } from "../src/core/normalize/normalize";
import { createServer, type Server, type Socket } from "node:net";
import { gzipSync } from "node:zlib";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProxyServer, type CapturedCall } from "../src/core/proxy/server";
import { RunRegistry } from "../src/core/proxy/registry";
import { Store } from "../src/core/store/store";

// ---- fake upstream: a raw TCP server that records exact request bytes ----
interface FakeUpstream {
  server: Server;
  port: number;
  requests: Buffer[];        // raw bytes per request (headers + body)
  connections: number;
  close(): void;
}

function startFakeUpstream(
  respond: (raw: Buffer, sock: Socket) => void,
): Promise<FakeUpstream> {
  const fake = {
    requests: [] as Buffer[],
    connections: 0,
  } as FakeUpstream;
  const server = createServer((sock) => {
    fake.connections++;
    let buf: Buffer = Buffer.alloc(0);
    sock.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      // naive full-request detector: headers + content-length body
      const headerEnd = buf.indexOf("\r\n\r\n");
      if (headerEnd === -1) return;
      const head = buf.subarray(0, headerEnd).toString();
      const m = head.match(/content-length:\s*(\d+)/i);
      const bodyLen = m ? Number(m[1]) : 0;
      if (buf.length >= headerEnd + 4 + bodyLen) {
        const raw = buf.subarray(0, headerEnd + 4 + bodyLen);
        fake.requests.push(Buffer.from(raw));
        buf = buf.subarray(headerEnd + 4 + bodyLen);
        respond(raw, sock);
      }
    });
    sock.on("error", () => {});
  });
  fake.server = server;
  fake.close = () => server.close();
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      fake.port = (server.address() as { port: number }).port;
      resolve(fake);
    });
  });
}

const OK_JSON = (body: string) =>
  `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;

function sendRaw(port: number, raw: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const { connect } = require("node:net") as typeof import("node:net");
    const sock = connect(port, "127.0.0.1", () => sock.write(raw));
    const chunks: Buffer[] = [];
    let quiet: ReturnType<typeof setTimeout> | null = null;
    sock.on("data", (d: Buffer) => {
      chunks.push(d);
      if (quiet) clearTimeout(quiet);
      quiet = setTimeout(() => sock.end(), 120); // resolve once the response goes quiet
    });
    sock.on("end", () => resolve(Buffer.concat(chunks)));
    sock.on("close", () => resolve(Buffer.concat(chunks)));
    sock.on("error", reject);
    setTimeout(() => sock.end(), 1500); // hard backstop
  });
}

describe("proxy", () => {
  let store: Store;
  let registry: RunRegistry;
  let proxy: ProxyServer;
  let upstream: FakeUpstream;
  let calls: CapturedCall[];
  let scanned: Uint8Array[];

  beforeEach(async () => {
    store = Store.open(mkdtempSync(join(tmpdir(), "beagle-proxy-")));
    registry = new RunRegistry(store);
    calls = [];
    scanned = [];
    // Bind to THIS test's array by value: a prior test's proxy could still be
    // finishing a late capture, and onCall closing over the `calls`
    // variable would otherwise push it into the reassigned array.
    const myCalls = calls;
    upstream = await startFakeUpstream((_raw, sock) => {
      sock.write(OK_JSON('{"ok":true}'));
    });
    proxy = new ProxyServer({
      registry,
      scan: (bytes) => { scanned.push(bytes); return new Promise(() => {}); }, // never resolves
      onCall: (call) => myCalls.push(call),
      captureBufferCap: 1 << 20,
    });
    await proxy.listen(0);
  });

  afterEach(() => {
    proxy.close();
    upstream.close();
    store.close();
  });

  function register(overrides: Partial<Parameters<RunRegistry["register"]>[0]> = {}) {
    return registry.register({
      id: "run-abc",
      agent: "claude-code",
      provider: "anthropic",
      upstream: `http://127.0.0.1:${upstream.port}`,
      authLocation: "x-api-key",
      ...overrides,
    });
  }

  test("an upstream WITH a base path (…/v1) has it prefixed onto every forwarded request", async () => {
    // The OpenAI family replaces a default base that INCLUDES /v1 and appends
    // only /responses — before this, the proxy forwarded bare /responses to
    // the host root and every codex/opencode/pi wire request 404'd.
    register({ upstream: `http://127.0.0.1:${upstream.port}/v1` });
    const body = '{"model":"m","input":"hi"}';
    const raw =
      `POST /run/run-abc/responses HTTP/1.1\r\n` +
      `Host: 127.0.0.1\r\n` +
      `Authorization: Bearer sk-test\r\n` +
      `Content-Type: application/json\r\n` +
      `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n` + body;
    await sendRaw(proxy.port, raw);
    const line = upstream.requests[0]!.toString().split("\r\n")[0];
    expect(line).toBe("POST /v1/responses HTTP/1.1");
  });

  test("an over-cap request is rejected with 413, not buffered without bound", async () => {
    // Dedicated small-cap proxy so we can trip the limit without a 128 MiB body.
    const capped = new ProxyServer({
      registry,
      scan: () => new Promise(() => {}),
      onCall: () => {},
      captureBufferCap: 1 << 20,
      maxRequestBytes: 512,
    });
    await capped.listen(0);
    try {
      const body = "x".repeat(2000); // well over the 512-byte cap
      const raw =
        `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n` +
        `Content-Length: ${body.length}\r\n\r\n${body}`;
      const resp = (await sendRaw(capped.port, raw)).toString();
      expect(resp).toContain("413 Payload Too Large");
    } finally {
      capped.close();
    }
  });

  test("parseUpstream keeps the base path; bare hosts stay prefix-free", () => {
    expect(parseUpstream("https://api.anthropic.com").basePath).toBe("");
    expect(parseUpstream("https://api.openai.com/v1").basePath).toBe("/v1");
    expect(parseUpstream("https://api.openai.com/v1/").basePath).toBe("/v1"); // trailing slash normalized
    expect(parseUpstream("https://chatgpt.com/backend-api/codex").basePath).toBe("/backend-api/codex");
    // and the anthropic default keeps working: no prefix, client path verbatim
    expect(parseUpstream("http://127.0.0.1:8080").basePath).toBe("");
  });

  test("forwards body byte-identical with header order preserved, prefix stripped", async () => {
    register();
    const body = '{"model":"m","messages":[{"role":"user","content":"hi"}]}';
    const raw =
      `POST /run/run-abc/v1/messages HTTP/1.1\r\n` +
      `Host: 127.0.0.1\r\n` +
      `X-Api-Key: sk-ant-123\r\n` +
      `Anthropic-Version: 2023-06-01\r\n` +
      `Content-Type: application/json\r\n` +
      `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n` + body;
    const resp = await sendRaw(proxy.port, raw);
    expect(resp.toString()).toContain('{"ok":true}');

    const seen = upstream.requests[0]!.toString();
    // path prefix stripped
    expect(seen.startsWith("POST /v1/messages HTTP/1.1\r\n")).toBe(true);
    // body byte-identical
    expect(seen.endsWith(body)).toBe(true);
    // header order and casing preserved
    const xi = seen.indexOf("X-Api-Key");
    const ai = seen.indexOf("Anthropic-Version");
    const ci = seen.indexOf("Content-Type");
    expect(xi).toBeGreaterThan(-1);
    expect(ai).toBeGreaterThan(xi);
    expect(ci).toBeGreaterThan(ai);
    // no proxy fingerprints
    expect(seen).not.toContain("Via:");
    expect(seen).not.toContain("X-Forwarded");
    // Host rewritten to upstream authority
    expect(seen).toContain(`Host: 127.0.0.1:${upstream.port}`);
  });

  test("re-adds configured headers the agent dropped", async () => {
    register({ extraHeaders: [["anthropic-beta", "context-1m"]] });
    const body = "{}";
    await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n${body}`);
    expect(upstream.requests[0]!.toString()).toContain("anthropic-beta: context-1m");
  });

  test("does not duplicate extra header when agent already sends it", async () => {
    register({ extraHeaders: [["anthropic-beta", "context-1m"]] });
    await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nanthropic-beta: other\r\nContent-Length: 2\r\n\r\n{}`);
    const seen = upstream.requests[0]!.toString();
    expect(seen.match(/anthropic-beta/gi)?.length).toBe(1);
    expect(seen).toContain("anthropic-beta: other");
  });

  test("chunked request body → 411, never mangled into the next request", async () => {
    register();
    const resp = await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n`);
    expect(resp.toString()).toContain("411");
    expect(upstream.requests.length).toBe(0);
  });

  test("WebSocket upgrade → 426, never forwarded (client falls back to its HTTP transport)", async () => {
    // pi's ChatGPT/codex transport tries a WebSocket first; relaying the 101
    // and then failing to parse frames would hang it forever. Refusing the
    // upgrade drops it to the SSE POST Beagle can capture.
    register();
    const resp = await sendRaw(proxy.port,
      `GET /run/run-abc/codex/responses HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    expect(resp.toString()).toContain("426");
    expect(resp.toString()).not.toContain("101");
    expect(upstream.requests.length).toBe(0);
  });

  test("compressed request body is decoded for scan + capture, but relayed byte-exact", async () => {
    // pi's ChatGPT/codex transport zstd-compresses request bodies; without
    // decoding, the scanner and `beagle search` only see the opaque blob and a
    // planted secret goes undetected. gzip stands in here (always available);
    // zstd rides the same decodeBody path.
    register();
    const plain = '{"model":"m","input":"my secret is AKIAIOSFODNN7EXAMPLE"}';
    const gz = gzipSync(Buffer.from(plain));
    const raw = Buffer.concat([
      Buffer.from(
        `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\n` +
          `Content-Encoding: gzip\r\nContent-Length: ${gz.length}\r\n\r\n`,
      ),
      gz,
    ]);
    await new Promise<void>((resolve, reject) => {
      const { connect } = require("node:net") as typeof import("node:net");
      const sock = connect(proxy.port, "127.0.0.1", () => sock.write(raw));
      sock.on("data", () => setTimeout(() => sock.end(), 100));
      sock.on("close", () => resolve());
      sock.on("error", reject);
      setTimeout(() => sock.end(), 1500);
    });
    // scanner saw decoded plaintext
    expect(Buffer.from(scanned[0]!).toString()).toBe(plain);
    // captured request body stored decoded (so R7 search finds the secret)
    expect(Buffer.from(calls[0]!.request.bodyBytes).toString()).toBe(plain);
    // but the upstream received the ORIGINAL compressed bytes, byte-for-byte
    const fwd = upstream.requests[0]!;
    const he = fwd.indexOf("\r\n\r\n");
    expect(fwd.subarray(he + 4).equals(gz)).toBe(true);
  });

  test("unknown run id → 502, never forwarded", async () => {
    const resp = await sendRaw(proxy.port,
      `POST /run/nope/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    expect(resp.toString()).toContain("502");
    expect(upstream.requests.length).toBe(0);
  });

  test("registry rehydrates from the runs table after restart", () => {
    register();
    const registry2 = new RunRegistry(store);
    expect(registry2.resolve("run-abc")?.provider).toBe("anthropic");
  });

  test("scan dispatched with body bytes but never awaited (seam is a pure tap)", async () => {
    register();
    const body = '{"secret":"AKIAIOSFODNN7EXAMPLE"}';
    const resp = await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    // forward completed even though scan promise never resolves
    expect(resp.toString()).toContain('{"ok":true}');
    expect(scanned.length).toBe(1);
    expect(new TextDecoder().decode(scanned[0]!)).toBe(body);
  });

  test("captures call with auth header scrubbed, never the raw credential", async () => {
    register();
    const body = "{}";
    await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nX-Api-Key: sk-ant-supersecret\r\nContent-Length: 2\r\n\r\n${body}`);
    await Bun.sleep(50);
    expect(calls.length).toBe(1);
    const headers = calls[0]!.request.headers!;
    const auth = headers.find(([n]) => n.toLowerCase() === "x-api-key")!;
    expect(auth[1]).toMatch(/^\[AUTH:anthropic:[0-9a-f]{8}\]$/);
    expect(JSON.stringify(headers)).not.toContain("supersecret");
  });

  test("decodes gzip response bodies on the capture copy only", async () => {
    upstream.close();
    const payload = gzipSync('{"content":"decoded-text"}');
    upstream = await startFakeUpstream((_raw, sock) => {
      sock.write(
        `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-encoding: gzip\r\ncontent-length: ${payload.length}\r\n\r\n`,
      );
      sock.write(payload);
    });
    register({ upstream: `http://127.0.0.1:${upstream.port}` });
    const resp = await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    // client got the exact gzip bytes
    expect(resp.includes(payload)).toBe(true);
    await Bun.sleep(50);
    // capture got the decoded form
    expect(new TextDecoder().decode(calls[0]!.response.bodyBytes!)).toContain("decoded-text");
  });

  test("streams chunked responses incrementally (first chunk before upstream ends)", async () => {
    upstream.close();
    let sockRef: Socket | null = null;
    upstream = await startFakeUpstream((_raw, sock) => {
      sockRef = sock;
      sock.write(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
      );
      sock.write("6\r\nhello\n\r\n");
      // hold the stream open; second chunk after a delay
      setTimeout(() => { sock.write("6\r\nworld\n\r\n"); sock.write("0\r\n\r\n"); }, 100);
    });
    register({ upstream: `http://127.0.0.1:${upstream.port}` });

    const { connect } = await import("node:net");
    const firstChunkAt = await new Promise<number>((resolve, reject) => {
      const start = Date.now();
      const sock = connect(proxy.port, "127.0.0.1", () => {
        sock.write(`POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
      });
      let got = "";
      sock.on("data", (d) => {
        got += d.toString();
        if (got.includes("hello")) { resolve(Date.now() - start); sock.end(); }
      });
      sock.on("error", reject);
      setTimeout(() => reject(new Error("timeout")), 2000);
    });
    // first chunk arrived well before the 100ms-delayed second chunk
    expect(firstChunkAt).toBeLessThan(90);
  });

  test("keeps the raw SSE stream (event framing) for the fidelity view", async () => {
    upstream.close();
    upstream = await startFakeUpstream((_raw, sock) => {
      sock.write("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n");
      const e1 = 'event: content_block_delta\ndata: {"text":"hi"}\n\n';
      const e2 = 'event: message_stop\ndata: {}\n\n';
      sock.write(e1.length.toString(16) + "\r\n" + e1 + "\r\n");
      sock.write(e2.length.toString(16) + "\r\n" + e2 + "\r\n");
      sock.write("0\r\n\r\n");
    });
    register({ upstream: `http://127.0.0.1:${upstream.port}` });
    await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    for (let i = 0; i < 40 && calls.length === 0; i++) await Bun.sleep(20);
    const raw = calls[0]!.response.sseRaw;
    expect(raw).toBeDefined();
    const rawText = new TextDecoder().decode(raw!);
    // exact event framing preserved (not reassembled into plain text)
    expect(rawText).toContain("event: content_block_delta");
    expect(rawText).toContain("event: message_stop");
    expect(rawText).toContain('data: {"text":"hi"}');
  });

  test("non-streaming JSON response gets no sse_raw (body already is the raw bytes)", async () => {
    register();
    await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    await Bun.sleep(50);
    expect(calls[0]!.response.sseRaw).toBeUndefined();
  });

  test("marks capture truncated past the buffer cap, stream unaffected", async () => {
    proxy.close();
    proxy = new ProxyServer({
      registry,
      scan: () => new Promise(() => {}),
      onCall: (call) => calls.push(call),
      captureBufferCap: 10, // tiny cap
    });
    await proxy.listen(0);
    register();
    const resp = await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    expect(resp.toString()).toContain('{"ok":true}'); // client got everything
    await Bun.sleep(50);
    expect(calls[0]!.meta.captureState).toBe("truncated");
  });

  test("upstream 500 passes through unchanged", async () => {
    upstream.close();
    upstream = await startFakeUpstream((_raw, sock) => {
      const body = '{"error":{"type":"overloaded_error"}}';
      sock.write(`HTTP/1.1 529 Overloaded\r\ncontent-type: application/json\r\ncontent-length: ${body.length}\r\n\r\n${body}`);
    });
    register({ upstream: `http://127.0.0.1:${upstream.port}` });
    const resp = await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    expect(resp.toString()).toContain("529");
    expect(resp.toString()).toContain("overloaded_error");
  });

  test("client abort mid-stream propagates cancel upstream, keeps partial capture", async () => {
    upstream.close();
    let upstreamSock: Socket | null = null;
    let upstreamClosed = false;
    upstream = await startFakeUpstream((_raw, sock) => {
      upstreamSock = sock;
      sock.on("close", () => { upstreamClosed = true; });
      sock.write("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n");
      sock.write("8\r\npartial\n\r\n");
      // never finishes: an SSE stream held open
    });
    register({ upstream: `http://127.0.0.1:${upstream.port}` });

    const { connect } = await import("node:net");
    await new Promise<void>((resolve) => {
      const sock = connect(proxy.port, "127.0.0.1", () => {
        sock.write(`POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
      });
      sock.on("data", () => sock.destroy()); // abort as soon as bytes arrive
      sock.on("close", () => resolve());
    });
    await Bun.sleep(100);
    expect(upstreamClosed).toBe(true); // cancel propagated
    expect(calls.length).toBe(1);  // partial capture kept
    expect(calls[0]!.meta.captureState).toBe("truncated");
    expect(new TextDecoder().decode(calls[0]!.response.bodyBytes!)).toContain("partial");
    void upstreamSock;
  });

  test("a rejecting scan never breaks the forward path", async () => {
    proxy.close();
    proxy = new ProxyServer({
      registry,
      scan: () => Promise.reject(new Error("scanner exploded")),
      onCall: (call) => calls.push(call),
      captureBufferCap: 1 << 20,
    });
    await proxy.listen(0);
    register();
    const resp = await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    expect(resp.toString()).toContain('{"ok":true}');
  });

  test("keep-alive: sequential requests reuse one upstream connection", async () => {
    register();
    await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    expect(upstream.requests.length).toBe(2);
    expect(upstream.connections).toBe(1);
  });
});

describe("proxy hardening (malicious/compromised upstream)", () => {
  test("decodeBody caps decompression — a zip bomb keeps raw bytes instead of OOMing", () => {
    const bomb = gzipSync(Buffer.alloc(65 * 1024 * 1024, 0)); // decodes to 65 MB > 64 MB cap
    expect(decodeBody(new Uint8Array(bomb), "gzip")).toEqual(new Uint8Array(bomb)); // over cap → raw
    const ok = gzipSync(Buffer.from("hello")); // a normal body still decodes
    expect(Buffer.from(decodeBody(new Uint8Array(ok), "gzip")).toString()).toBe("hello");
  });

  test("response Set-Cookie / WWW-Authenticate are scrubbed before storage", () => {
    const s = scrubAuthHeaders(
      [["set-cookie", "session=abc"], ["www-authenticate", "Bearer x"], ["content-type", "text/plain"]],
      undefined,
      "openai",
    );
    expect(s.find(([n]) => n === "set-cookie")![1]).toContain("[AUTH:");
    expect(s.find(([n]) => n === "www-authenticate")![1]).toContain("[AUTH:");
    expect(s.find(([n]) => n === "content-type")![1]).toBe("text/plain"); // non-auth untouched
  });

  test("ResponseReader bounds an endless-header stream and won't let the socket be pooled", () => {
    const r = new ResponseReader(() => {});
    r.feed(Buffer.from("HTTP/1.1 200 OK\r\n"));
    for (let i = 0; i < 60 && !r.done; i++) r.feed(Buffer.from(`x-pad: ${"a".repeat(8192)}\r\n`));
    expect(r.done).toBe(true); // capped, not growing without bound
    expect(r.keepAlive).toBe(false); // → server.ts destroys instead of pooling
  });

  test("ResponseReader flags trailing (smuggled) bytes so the socket isn't reused", () => {
    const r = new ResponseReader(() => {});
    // a complete 2-byte response immediately followed by a forged second response
    r.feed(Buffer.from("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok" + "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nEVIL!"));
    expect(r.done).toBe(true);
    expect(r.keepAlive).toBe(false); // leftover bytes → pool-poisoning defense
  });

  test("ResponseReader skips an interim 100 Continue and reads the real response", () => {
    const body: Buffer[] = [];
    const r = new ResponseReader((b) => body.push(b));
    // 100 Continue (no body) then the real 200 — arriving together
    r.feed(Buffer.from("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi"));
    expect(r.status).toBe(200); // not 100
    expect(r.done).toBe(true);
    expect(Buffer.concat(body).toString()).toBe("hi"); // real body, not the interim head
  });

  test("ResponseReader skips an interim head that arrives in a separate chunk", () => {
    const r = new ResponseReader(() => {});
    r.feed(Buffer.from("HTTP/1.1 103 Early Hints\r\nlink: </s.css>\r\n\r\n"));
    expect(r.done).toBe(false); // still waiting for the real response
    r.feed(Buffer.from("HTTP/1.1 204 No Content\r\n\r\n"));
    expect(r.status).toBe(204);
    expect(r.done).toBe(true);
  });

  test("ResponseReader survives a flood of interim heads without recursing (no stack overflow)", () => {
    // A compromised upstream sending thousands of 100 Continue heads in one
    // burst must not blow the stack — the interim-skip iterates, it doesn't
    // recurse (which would only be safe on engines with proper tail calls).
    const r = new ResponseReader(() => {});
    const flood = "HTTP/1.1 100 Continue\r\n\r\n".repeat(20000);
    expect(() => r.feed(Buffer.from(flood + "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"))).not.toThrow();
    expect(r.status).toBe(200); // the real response after the flood
    expect(r.done).toBe(true);
  });

  test("ResponseReader completes a HEAD response at the head, ignoring content-length", () => {
    const body: Buffer[] = [];
    // HEAD echoes the GET's content-length but sends no body — without the
    // method hint the reader would wait for 1000 bytes that never come.
    const r = new ResponseReader((b) => body.push(b), "HEAD");
    r.feed(Buffer.from("HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n"));
    expect(r.done).toBe(true);
    expect(body.length).toBe(0);
  });
});
