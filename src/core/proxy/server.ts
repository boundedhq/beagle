// Proxy server (design §6.1): loopback listener, /run/<uuid> strip, raw-byte
// forward through the pooled HTTP/1.1 client, read-once pump with a bounded
// capture buffer, and the pre-forward seam (v1: dispatch scan, don't await).
import { createServer, type Server, type Socket } from "node:net";
import { ulid } from "../store/ulid";
import type { Exchange } from "../exchange";
import { decodeBody, scrubAuthHeaders } from "../normalize/normalize";
import {
  ConnectionPool,
  ResponseReader,
  serializeRequest,
  type HeaderList,
} from "./http1";
import type { RunRegistry, ResolvedRun } from "./registry";

export interface ScanContext {
  /** Assigned at request start so alerts can reference the exchange before
   *  the response completes; onExchange delivers the same id. */
  exchangeId: string;
  endpoint: string;
  runId: string;
  provider: string;
  agent?: string;
  authValue?: string;
}

export interface CapturedExchange extends Exchange {
  meta: Exchange["meta"] & { captureState: "ok" | "truncated" };
}

export interface ProxyOptions {
  registry: RunRegistry;
  scan: (bytes: Uint8Array, ctx: ScanContext) => Promise<unknown>;
  onExchange: (ex: CapturedExchange) => void;
  captureBufferCap: number;
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
    return new Promise((resolve) => {
      this.server = createServer((sock) => this.handleConnection(sock));
      this.server.listen(port, "127.0.0.1", () => {
        this.port = (this.server!.address() as { port: number }).port;
        resolve();
      });
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
    client.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (busy) return;
      const parsed = parseRequest(buf);
      if (parsed === null) return;
      if (parsed === "bad") {
        client.end("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
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
    const exchangeId = ulid(tsRequest);

    // Rewrite authority; preserve everything else byte-for-byte, in order.
    const headers: HeaderList = req.headers.map(([n, v]) =>
      n.toLowerCase() === "host" ? [n, run.parsedUpstream.authority] : [n, v],
    );
    for (const [name, value] of run.extraHeaders ?? []) {
      if (!headers.some(([n]) => n.toLowerCase() === name.toLowerCase())) {
        headers.push([name, value]);
      }
    }

    // ---- pre-forward seam (§7): dispatch scan, do NOT await (v1 tap) ----
    const authValue = req.headers.find(
      ([n]) => n.toLowerCase() === (run.authLocation ?? "").toLowerCase(),
    )?.[1];
    this.opts
      .scan(new Uint8Array(req.body), {
        exchangeId,
        endpoint: upstreamPath,
        runId: run.id,
        provider: run.provider,
        agent: run.agent,
        authValue,
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
    });

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
        upstream.write(serializeRequest(req.method, upstreamPath, headers, req.body));
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
    const ex: CapturedExchange = {
      id: exchangeId,
      runId: run.id,
      source: "wire",
      agent: run.agent,
      provider: run.provider,
      endpoint: upstreamPath,
      request: {
        headers: scrubAuthHeaders(req.headers, run.authLocation, run.provider),
        bodyBytes: new Uint8Array(req.body),
      },
      response: {
        status: reader.status,
        bodyBytes: decodeBody(new Uint8Array(responseRaw), reader.headerValue("content-encoding")),
      },
      meta: {
        tsRequest,
        tsResponse: Date.now(),
        captureState: truncated ? "truncated" : "ok",
      },
    };
    this.opts.onExchange(ex);
  }
}

function parseRequest(buf: Buffer): { req: ParsedRequest; consumed: number } | "bad" | null {
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
