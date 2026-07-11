import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createServer, type Server, type Socket } from "node:net";
import { gzipSync } from "node:zlib";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProxyServer, type CapturedExchange } from "../src/core/proxy/server";
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
  let exchanges: CapturedExchange[];
  let scanned: Uint8Array[];

  beforeEach(async () => {
    store = Store.open(mkdtempSync(join(tmpdir(), "beagle-proxy-")));
    registry = new RunRegistry(store);
    exchanges = [];
    scanned = [];
    upstream = await startFakeUpstream((_raw, sock) => {
      sock.write(OK_JSON('{"ok":true}'));
    });
    proxy = new ProxyServer({
      registry,
      scan: (bytes) => { scanned.push(bytes); return new Promise(() => {}); }, // never resolves
      onExchange: (ex) => exchanges.push(ex),
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

  test("captures exchange with auth header scrubbed, never the raw credential", async () => {
    register();
    const body = "{}";
    await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nX-Api-Key: sk-ant-supersecret\r\nContent-Length: 2\r\n\r\n${body}`);
    await Bun.sleep(50);
    expect(exchanges.length).toBe(1);
    const headers = exchanges[0]!.request.headers!;
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
    expect(new TextDecoder().decode(exchanges[0]!.response.bodyBytes!)).toContain("decoded-text");
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

  test("marks capture truncated past the buffer cap, stream unaffected", async () => {
    proxy.close();
    proxy = new ProxyServer({
      registry,
      scan: () => new Promise(() => {}),
      onExchange: (ex) => exchanges.push(ex),
      captureBufferCap: 10, // tiny cap
    });
    await proxy.listen(0);
    register();
    const resp = await sendRaw(proxy.port,
      `POST /run/run-abc/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}`);
    expect(resp.toString()).toContain('{"ok":true}'); // client got everything
    await Bun.sleep(50);
    expect(exchanges[0]!.meta.captureState).toBe("truncated");
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
    expect(exchanges.length).toBe(1);  // partial capture kept
    expect(exchanges[0]!.meta.captureState).toBe("truncated");
    expect(new TextDecoder().decode(exchanges[0]!.response.bodyBytes!)).toContain("partial");
    void upstreamSock;
  });

  test("a rejecting scan never breaks the forward path", async () => {
    proxy.close();
    proxy = new ProxyServer({
      registry,
      scan: () => Promise.reject(new Error("scanner exploded")),
      onExchange: (ex) => exchanges.push(ex),
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
