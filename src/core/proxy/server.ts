// Proxy server (design §6.1): loopback listener, /run/<uuid> strip, raw-byte
// forward through the pooled HTTP/1.1 client, read-once pump with a bounded
// capture buffer, and the pre-forward seam (v1: dispatch scan, don't await).
import { createServer, type Server, type Socket } from "node:net";
import { ulid } from "../store/ulid";
import { listenReady } from "../net/listen";
import type { Call } from "../call";
import { decodeBody, scrubAuthHeaders } from "../normalize/normalize";

// Hard ceiling on a single buffered request. Beagle buffers the whole request
// before forwarding, so an unbounded (or stalled) local request would grow
// memory without limit — this bounds it. 128 MiB is ~16× the largest plausible
// model request (a 1M-token context is single-digit MB), so it never trips a
// legitimate call; over it, reject with 413 rather than keep buffering.
const MAX_REQUEST_BYTES = 128 << 20;
import {
  ConnectionPool,
  ResponseReader,
  serializeRequest,
  type HeaderList,
} from "./http1";
import type { RunRegistry, ResolvedRun } from "./registry";

export interface ScanContext {
  /** Assigned at request start so alerts can reference the call before
   *  the response completes; onCall delivers the same id. */
  callId: string;
  endpoint: string;
  runId: string;
  provider: string;
  agent?: string;
  authValue?: string;
}

export interface CapturedCall extends Call {
  meta: Call["meta"] & { captureState: "ok" | "truncated" };
}

export interface ProxyOptions {
  registry: RunRegistry;
  scan: (bytes: Uint8Array, ctx: ScanContext) => Promise<unknown>;
  onCall: (call: CapturedCall) => void;
  captureBufferCap: number;
  /** Max bytes buffered for a single inbound request before a 413. Defaults to
   *  MAX_REQUEST_BYTES; injectable so tests can trip it without a 128 MiB body. */
  maxRequestBytes?: number;
}

interface ParsedRequest {
  method: string;
  path: string;
  headers: HeaderList;
  body: Buffer;
}

// Mid-stream failure after bytes were relayed: the client connection is
// dropped (like going direct), never patched with synthesized bytes.
class StreamAbortedError extends Error {}

export class ProxyServer {
  port = 0;
  private server: Server | null = null;
  private pool = new ConnectionPool();

  constructor(private opts: ProxyOptions) {}

  listen(port: number): Promise<void> {
    const server = createServer((sock) => this.handleConnection(sock));
    this.server = server;
    return listenReady(server, () => server.listen(port, "127.0.0.1")).then(() => {
      this.port = (server.address() as { port: number }).port;
    });
  }

  close(): void {
    this.server?.close();
    this.pool.closeAll();
  }

  private handleConnection(client: Socket): void {
    let buf: Buffer = Buffer.alloc(0);
    let busy = false;
    client.on("error", () => client.destroy());
    const maxReq = this.opts.maxRequestBytes ?? MAX_REQUEST_BYTES;
    client.on("data", (d: Buffer) => {
      if (buf.length + d.length > maxReq) {
        // Bound memory: refuse rather than keep concatenating an oversized or
        // stalled request (the client is local, but a bug shouldn't OOM us).
        client.end("HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\n\r\n");
        client.destroy();
        return;
      }
      buf = Buffer.concat([buf, d]);
      if (busy) return;
      const parsed = parseRequest(buf);
      if (parsed === null) return;
      if (parsed === "bad") {
        client.end("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
        return;
      }
      if (parsed === "length-required") {
        client.end("HTTP/1.1 411 Length Required\r\ncontent-length: 0\r\n\r\n");
        return;
      }
      buf = buf.subarray(parsed.consumed);
      busy = true;
      this.handleRequest(client, parsed.req)
        .catch((e) => {
          if (!(e instanceof StreamAbortedError) && !client.destroyed) {
            client.end("HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n");
          }
        })
        .finally(() => {
          busy = false;
          client.emit("data", Buffer.alloc(0)); // re-check buffered pipelined bytes
        });
    });
  }

  private async handleRequest(client: Socket, req: ParsedRequest): Promise<void> {
    const header = (name: string) => req.headers.find(([n]) => n.toLowerCase() === name)?.[1];
    // Beagle is an HTTP/1.1 request/response proxy; it does not bridge
    // WebSocket tunnels — their frames aren't the request/response pair the
    // scanner captures. Refuse the upgrade rather than relay the 101 and then
    // stall forever trying to parse frames as an HTTP body. A client that
    // speaks both (pi's ChatGPT/codex transport tries a WebSocket first, then
    // falls back to an SSE POST on connect failure) drops to the HTTP path
    // Beagle CAN capture; a WebSocket-only client sees a clean error, never a
    // silent hang.
    if (header("upgrade")?.toLowerCase().includes("websocket")) {
      client.end("HTTP/1.1 426 Upgrade Required\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
      return;
    }
    const m = req.path.match(/^\/run\/([^/]+)(\/.*)$/);
    const run = m ? this.opts.registry.resolve(m[1]!) : null;
    if (!run || !m) {
      const msg = "beagle: unknown run id — is the daemon that registered this run still the one running?";
      client.end(
        `HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain\r\ncontent-length: ${msg.length}\r\n\r\n${msg}`,
      );
      return;
    }
    const upstreamPath = m[2]!;
    const tsRequest = Date.now();
    const callId = ulid(tsRequest);

    // Rewrite authority; preserve everything else byte-for-byte, in order.
    const headers: HeaderList = req.headers.map(([n, v]) => (n.toLowerCase() === "host" ? [n, run.parsedUpstream.authority] : [n, v]));
    for (const [name, value] of run.extraHeaders ?? []) {
      if (!headers.some(([n]) => n.toLowerCase() === name.toLowerCase())) {
        headers.push([name, value]);
      }
    }

    // The request body can be compressed (pi's ChatGPT/codex transport sends
    // zstd; others gzip) — decode a capture copy so the scanner and R7's
    // "was this ever sent?" see plaintext, not an opaque blob that hides the
    // secret. The RELAY still forwards the original `req.body` byte-for-byte;
    // this decoded copy is used only for scanning and storage.
    const reqBody = decodeBody(new Uint8Array(req.body), header("content-encoding"));

    // ---- pre-forward seam (§7): dispatch scan, do NOT await (v1 tap) ----
    this.opts
      .scan(reqBody, {
        callId,
        endpoint: upstreamPath,
        runId: run.id,
        provider: run.provider,
        agent: run.agent,
        authValue: header((run.authLocation ?? "").toLowerCase()),
      })
      .catch(() => {}); // a scanner failure must never take down the forward path

    // ---- forward (retry once on a stale pooled connection) ----
    const captureCap = this.opts.captureBufferCap;
    const captured: Buffer[] = [];
    let capturedBytes = 0;
    let truncated = false;
    let relayStarted = false;
    let clientAborted = false;

    const reader = new ResponseReader((bodyChunk) => {
      if (capturedBytes + bodyChunk.length <= captureCap) {
        captured.push(Buffer.from(bodyChunk));
        capturedBytes += bodyChunk.length;
      } else {
        truncated = true; // capture sacrificed; client stream never throttled
      }
    }, req.method); // method: a HEAD response is bodyless despite content-length

    const attempt = (upstream: Socket) =>
      new Promise<void>((resolve, reject) => {
        const onData = (chunk: Buffer) => {
          relayStarted = true;
          if (!client.destroyed) {
            // Honor the client's backpressure: pause upstream while its buffer drains.
            if (!client.write(chunk)) {
              upstream.pause();
              client.once("drain", () => upstream.resume());
            }
          }
          reader.feed(chunk);
          if (reader.done) {
            cleanup();
            if (reader.keepAlive && !clientAborted) this.pool.release(run.parsedUpstream, upstream);
            else upstream.destroy();
            resolve();
          }
        };
        const onEnd = () => {
          reader.end();
          cleanup();
          if (reader.done) resolve();
          else reject(new Error("upstream closed mid-response"));
        };
        const onErr = (e: Error) => {
          cleanup();
          reject(e);
        };
        const onClientClose = () => {
          // Cancel propagates upstream, exactly what going direct would do;
          // partial capture is kept, marked truncated.
          clientAborted = true;
          truncated = true;
          cleanup();
          upstream.destroy();
          resolve();
        };
        const cleanup = () => {
          upstream.off("data", onData);
          upstream.off("end", onEnd);
          upstream.off("error", onErr);
          upstream.off("close", onEnd);
          client.off("close", onClientClose);
        };
        upstream.on("data", onData);
        upstream.on("end", onEnd);
        upstream.on("close", onEnd);
        upstream.on("error", onErr);
        client.on("close", onClientClose);
        upstream.write(serializeRequest(req.method, run.parsedUpstream.basePath + upstreamPath, headers, req.body));
      });

    try {
      await attempt(await this.pool.acquire(run.parsedUpstream));
    } catch (e) {
      if (relayStarted) {
        // Mid-response failure: pass the drop through, never synthesize bytes.
        client.destroy();
        throw new StreamAbortedError();
      }
      // Nothing relayed yet — likely a stale pooled connection; retry fresh once.
      await attempt(await this.pool.acquireFresh(run.parsedUpstream));
    }

    // ---- capture branch (off the relay path) ----
    const responseRaw = Buffer.concat(captured);
    const contentType = reader.headerValue("content-type") ?? "";
    // A streamed response: the raw event framing (event:/data: lines) is a
    // fidelity artifact the reassembled body hides, so keep it for Layer 2.
    // For a plain JSON body, bodyBytes already IS the raw bytes — don't
    // duplicate. (Content-encoded streams keep raw too; the decoded form is
    // in bodyBytes.)
    const isStream = contentType.toLowerCase().includes("event-stream");
    const call: CapturedCall = {
      id: callId,
      runId: run.id,
      source: "wire",
      agent: run.agent,
      provider: run.provider,
      endpoint: upstreamPath,
      request: {
        headers: scrubAuthHeaders(req.headers, run.authLocation, run.provider),
        bodyBytes: reqBody,
      },
      response: {
        status: reader.status,
        headers: reader.headers,
        bodyBytes: decodeBody(new Uint8Array(responseRaw), reader.headerValue("content-encoding")),
        sseRaw: isStream ? new Uint8Array(responseRaw) : undefined,
      },
      meta: {
        tsRequest,
        tsResponse: Date.now(),
        captureState: truncated ? "truncated" : "ok",
      },
    };
    this.opts.onCall(call);
  }
}

function parseRequest(
  buf: Buffer,
): { req: ParsedRequest; consumed: number } | "bad" | "length-required" | null {
  const headerEnd = buf.indexOf("\r\n\r\n");
  if (headerEnd === -1) return null;
  const lines = buf.subarray(0, headerEnd).toString("latin1").split("\r\n");
  const requestLine = (lines[0] ?? "").split(" ");
  if (requestLine.length !== 3) return "bad";
  const [method, path] = requestLine;
  const headers: HeaderList = [];
  for (const line of lines.slice(1)) {
    const i = line.indexOf(":");
    if (i <= 0) return "bad";
    headers.push([line.slice(0, i), line.slice(i + 1).trim()]);
  }
  // Chunked request bodies aren't supported (agents send content-length JSON
  // POSTs); without this check the chunk framing would be mis-parsed as the
  // next request. 411 tells the client to retry with a length.
  const te = headers.find(([n]) => n.toLowerCase() === "transfer-encoding")?.[1];
  if (te?.toLowerCase().includes("chunked")) return "length-required";
  const clHeader = headers.find(([n]) => n.toLowerCase() === "content-length")?.[1];
  const bodyLen = clHeader ? Number(clHeader) : 0;
  if (!Number.isInteger(bodyLen) || bodyLen < 0) return "bad";
  const total = headerEnd + 4 + bodyLen;
  if (buf.length < total) return null;
  return {
    req: {
      method: method!,
      path: path!,
      headers,
      body: Buffer.from(buf.subarray(headerEnd + 4, total)),
    },
    consumed: total,
  };
}
