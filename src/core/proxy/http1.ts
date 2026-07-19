// Low-level HTTP/1.1 upstream client (design §6.1). High-level fetch would
// canonicalize header case/order; here the bytes we write are exactly the
// bytes registered. Keep-alive pool is load-bearing for the 5 ms budget.
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";

export type HeaderList = Array<[string, string]>;

export interface Upstream {
  scheme: "http" | "https";
  host: string;
  port: number;
  authority: string; // host[:port] as written in the Host header
  basePath: string; // upstream path prefix ("" or "/v1"-style, no trailing /)
}

export function parseUpstream(url: string): Upstream {
  const u = new URL(url);
  const scheme = u.protocol === "https:" ? "https" : "http";
  const port = u.port ? Number(u.port) : scheme === "https" ? 443 : 80;
  const authority = u.port ? `${u.hostname}:${u.port}` : u.hostname;
  // Keep the upstream's own path prefix: OpenAI-family clients replace a base
  // that INCLUDES /v1 (or /backend-api/codex) and append only /responses, so
  // dropping it forwarded every such request to a 404.
  const basePath = u.pathname.replace(/\/+$/, "");
  return { scheme, host: u.hostname, port, authority, basePath };
}

export function serializeRequest(
  method: string,
  path: string,
  headers: HeaderList,
  body: Uint8Array,
): Buffer {
  let head = `${method} ${path} HTTP/1.1\r\n`;
  for (const [name, value] of headers) head += `${name}: ${value}\r\n`;
  head += "\r\n";
  return Buffer.concat([Buffer.from(head, "latin1"), body]);
}

// Incremental HTTP/1.1 response parser. Raw bytes are relayed elsewhere;
// this only finds the message boundary and de-chunks a capture copy.
export class ResponseReader {
  status = 0;
  headers: HeaderList = [];
  done = false;
  keepAlive = true;
  private buf: Buffer = Buffer.alloc(0);
  private stage: "head" | "body" = "head";
  private bodyMode: "length" | "chunked" | "eof" = "eof";
  private remaining = 0; // for length mode, bytes left; for chunked, bytes left in current chunk
  private chunkStage: "size" | "data" | "trailer" = "size";

  constructor(
    private onBody: (chunk: Buffer) => void,
    private method: string = "GET",
  ) {}

  headerValue(name: string): string | undefined {
    return this.headers.find(([n]) => n.toLowerCase() === name)?.[1];
  }

  feed(data: Buffer): void {
    if (this.done) return;
    this.buf = this.buf.length === 0 ? data : Buffer.concat([this.buf, data]);
    if (this.stage === "head") this.parseHead();
    if (this.stage === "body") this.parseBody();
    // Bound the pre-body buffer: a malicious upstream sending endless headers
    // (or a never-terminated chunk-size line) would grow buf without limit with
    // O(n²) concat. Body bytes are drained by onBody, so a real stream never
    // trips this; over the cap, abandon the response.
    if (!this.done && this.buf.length > 1 << 18) this.done = true;
    // Leftover bytes after a complete response are a smuggled/pipelined extra
    // response (or the overflow above): don't reuse this socket — server.ts
    // pools only when keepAlive stays true. Defeats keep-alive pool poisoning.
    if (this.done && this.buf.length > 0) this.keepAlive = false;
  }

  end(): void {
    // upstream closed the connection: EOF-delimited body is complete
    if (this.stage === "body" && this.bodyMode === "eof") this.done = true;
  }

  private parseHead(): void {
    // Loop (not recursion) over any interim 1xx heads: a compromised upstream
    // could send thousands in one burst, and `return this.parseHead()` would
    // only be safe on engines with proper tail calls (JSC has them, V8 does
    // not — don't make crash-safety depend on that). The pre-body buffer stays
    // bounded by feed()'s cap between chunks.
    let end = this.buf.indexOf("\r\n\r\n");
    let lines: string[] = [];
    let status = 0;
    for (;;) {
      if (end === -1) return;
      lines = this.buf.subarray(0, end).toString("latin1").split("\r\n");
      status = Number((lines[0] ?? "").split(" ")[1] ?? 0);
      // Interim 1xx (100 Continue, 103 Early Hints): a bodyless head that
      // precedes the real response. Drop it and read the next head — otherwise
      // the final response is mis-read as this one's body and the reader waits
      // for EOF (up to the socket timeout). 101 can't reach here: the proxy
      // refuses Upgrade requests before forwarding.
      if (status >= 100 && status < 200) {
        this.buf = this.buf.subarray(end + 4);
        end = this.buf.indexOf("\r\n\r\n");
        continue;
      }
      break;
    }
    this.status = status;
    for (const line of lines.slice(1)) {
      const i = line.indexOf(":");
      if (i > 0) this.headers.push([line.slice(0, i), line.slice(i + 1).trim()]);
    }
    this.buf = this.buf.subarray(end + 4);
    this.stage = "body";
    const conn = this.headerValue("connection")?.toLowerCase();
    this.keepAlive = conn !== "close";
    // A HEAD response carries no body, even with a content-length advertising
    // the GET size — completing here avoids waiting for bytes that never come.
    if (this.method === "HEAD") {
      this.done = true;
      return;
    }
    const te = this.headerValue("transfer-encoding");
    const cl = this.headerValue("content-length");
    if (te?.toLowerCase().includes("chunked")) {
      this.bodyMode = "chunked";
    } else if (cl !== undefined) {
      this.bodyMode = "length";
      this.remaining = Number(cl);
      if (this.remaining === 0) this.done = true;
    } else if (this.status === 204 || this.status === 304) {
      this.done = true;
    } else {
      this.bodyMode = "eof";
      this.keepAlive = false;
    }
  }

  private parseBody(): void {
    if (this.bodyMode === "length") {
      const take = Math.min(this.remaining, this.buf.length);
      if (take > 0) {
        this.onBody(this.buf.subarray(0, take));
        this.remaining -= take;
        this.buf = this.buf.subarray(take);
      }
      if (this.remaining === 0) this.done = true;
    } else if (this.bodyMode === "eof") {
      if (this.buf.length > 0) {
        this.onBody(this.buf);
        this.buf = Buffer.alloc(0) as Buffer;
      }
    } else {
      this.parseChunked();
    }
  }

  private parseChunked(): void {
    while (!this.done) {
      if (this.chunkStage === "size") {
        const nl = this.buf.indexOf("\r\n");
        if (nl === -1) return;
        const size = parseInt(this.buf.subarray(0, nl).toString("latin1").split(";")[0]!, 16);
        this.buf = this.buf.subarray(nl + 2);
        if (Number.isNaN(size)) { this.done = true; return; }
        if (size === 0) { this.chunkStage = "trailer"; continue; }
        this.remaining = size;
        this.chunkStage = "data";
      } else if (this.chunkStage === "data") {
        const take = Math.min(this.remaining, this.buf.length);
        if (take > 0) {
          this.onBody(this.buf.subarray(0, take));
          this.remaining -= take;
          this.buf = this.buf.subarray(take);
        }
        if (this.remaining > 0) return;
        if (this.buf.length < 2) return; // await trailing CRLF
        this.buf = this.buf.subarray(2);
        this.chunkStage = "size";
      } else {
        // trailers: complete on the final blank line
        const nl = this.buf.indexOf("\r\n");
        if (nl === -1) return;
        const line = this.buf.subarray(0, nl);
        this.buf = this.buf.subarray(nl + 2);
        if (line.length === 0) { this.done = true; return; }
      }
    }
  }
}

// Per-upstream keep-alive connection pool.
export class ConnectionPool {
  private idle = new Map<string, Socket[]>();

  acquire(up: Upstream): Promise<Socket> {
    const sock = this.idle.get(`${up.scheme}://${up.authority}`)?.pop();
    if (sock && !sock.destroyed) return Promise.resolve(sock);
    return this.acquireFresh(up);
  }

  acquireFresh(up: Upstream): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const s =
        up.scheme === "https"
          ? tlsConnect({ host: up.host, port: up.port, servername: up.host }, () => resolve(s))
          : netConnect(up.port, up.host, () => resolve(s));
      s.on("error", reject);
      // Slow-loris defense: a stalled upstream (or an idle pooled socket) that
      // goes fully silent is destroyed rather than tying up daemon state. The
      // window is generous (5 min) on purpose — it must sit well above a slow
      // reasoning model's think-before-first-token, or Beagle would abort a
      // legitimate in-flight request (breaking the agent it's meant to observe).
      s.setTimeout(300_000, () => s.destroy());
    });
  }

  release(up: Upstream, sock: Socket): void {
    if (sock.destroyed) return;
    for (const ev of ["data", "error", "close"]) sock.removeAllListeners(ev);
    sock.on("error", () => sock.destroy());
    const key = `${up.scheme}://${up.authority}`;
    const list = this.idle.get(key) ?? [];
    list.push(sock);
    this.idle.set(key, list);
  }

  closeAll(): void {
    for (const list of this.idle.values()) for (const s of list) s.destroy();
    this.idle.clear();
  }
}
