// Viewer server (design §6.8): serves the crown-jewels page, hardened as a
// unit — loopback bind, one-time bootstrap token → header credential,
// Origin/Host validation, strict CSP, POST-only mutations, fetch-SSE feed,
// idle shutdown when the last tab disconnects.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { Store } from "../core/store/store";
import { listExchanges } from "./feed-query";
import { buildDetail, leakSpansFor } from "./detail";
// Statics embedded at build time (ships-what's-in-repo, and the compiled
// binary has no filesystem view of the repo).
import indexHtmlRaw from "./static/index.html" with { type: "text" };
import appJs from "./static/app.js" with { type: "text" };
// bun-types types *.html imports as HTMLBundle; with { type: "text" } the
// runtime value is a plain string.
const indexHtml = indexHtmlRaw as unknown as string;
import styleCss from "./static/style.css" with { type: "text" };
import preactJs from "./static/vendor/preact.module.js" with { type: "text" };
import preactHooksJs from "./static/vendor/preact-hooks.module.js" with { type: "text" };
import htmJs from "./static/vendor/htm.module.js" with { type: "text" };

export interface ViewerOptions {
  stateDir: string;
  idleTimeoutMs?: number;
  /** Mutations ride through the daemon (single writer); absent → 501. */
  onPurge?: (kind: string) => void;
}

const STATIC_FILES: Record<string, { body: string; type: string }> = {
  "/": { body: indexHtml, type: "text/html; charset=utf-8" },
  "/app.js": { body: appJs, type: "text/javascript; charset=utf-8" },
  "/style.css": { body: styleCss, type: "text/css; charset=utf-8" },
  "/vendor/preact.module.js": { body: preactJs, type: "text/javascript" },
  "/vendor/preact-hooks.module.js": { body: preactHooksJs, type: "text/javascript" },
  "/vendor/htm.module.js": { body: htmJs, type: "text/javascript" },
};

// script-src allows exactly two things: same-origin module files and the
// inline import map, pinned by its content hash — still nothing external,
// still no other inline script.
function buildCsp(): string {
  const m = indexHtml.match(/<script type="importmap">([\s\S]*?)<\/script>/);
  const importMapHash = m
    ? `'sha256-${createHash("sha256").update(m[1]!).digest("base64")}'`
    : "";
  return [
    "default-src 'self'",
    `script-src 'self' ${importMapHash}`.trim(),
    "style-src 'self'",
    "connect-src 'self'",
    "img-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

const CSP = buildCsp();

// Constant-time string compare so a token/credential check can't be probed
// byte-by-byte via response timing (loopback lowers but doesn't remove risk).
function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export class ViewerServer {
  isRunning = false;
  private server: Server | null = null;
  private port = 0;
  private bootToken: string | null = null;
  private credential: string | null = null;
  private sseClients = new Set<ServerResponse>();
  private idleTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private opts: ViewerOptions) {}

  start(): Promise<string> {
    this.bootToken = randomBytes(24).toString("hex");
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.route(req, res));
      this.server.listen(0, "127.0.0.1", () => {
        this.port = (this.server!.address() as { port: number }).port;
        this.isRunning = true;
        this.armIdleTimer();
        resolve(`http://127.0.0.1:${this.port}/?boot=${this.bootToken}`);
      });
    });
  }

  /** Notified when the viewer shuts down (last tab closed / idle) so the host
   *  daemon can re-evaluate its own idle-exit. */
  onStop: (() => void) | null = null;

  stop(): void {
    const wasRunning = this.isRunning;
    for (const c of this.sseClients) c.end();
    this.sseClients.clear();
    this.server?.close();
    this.server?.closeAllConnections?.();
    this.isRunning = false;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (wasRunning) this.onStop?.();
  }

  /** Push a live event (new exchange, alert) to any open tabs. */
  broadcast(type: string, data: unknown): void {
    const frame = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const c of this.sseClients) c.write(frame);
  }

  // ---- routing ----

  private route(req: IncomingMessage, res: ServerResponse): void {
    if (!this.checkHostOrigin(req)) {
      res.writeHead(403).end("forbidden: non-local origin");
      return;
    }
    this.armIdleTimer();
    let path: string;
    try {
      path = decodeURIComponent((req.url ?? "/").split("?")[0]!);
    } catch {
      res.writeHead(400).end();
      return;
    }

    const staticFile = STATIC_FILES[path];
    if (staticFile && req.method === "GET") {
      res.writeHead(200, {
        "content-type": staticFile.type,
        "content-security-policy": CSP,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      });
      res.end(staticFile.body);
      return;
    }

    if (path === "/api/session" && req.method === "POST") {
      void this.readJson(req).then((body) => {
        const boot = (body as { boot?: string })?.boot;
        if (this.bootToken && typeof boot === "string" && constantTimeEqual(boot, this.bootToken)) {
          this.bootToken = null; // one-time: invalidated on use
          this.credential = randomBytes(32).toString("hex");
          this.json(res, 200, { credential: this.credential });
        } else {
          this.json(res, 401, { error: "invalid or already-used bootstrap token" });
        }
      });
      return;
    }

    if (path.startsWith("/api/")) {
      const token = req.headers["x-beagle-token"];
      if (
        !this.credential ||
        typeof token !== "string" ||
        !constantTimeEqual(token, this.credential)
      ) {
        this.json(res, 401, { error: "missing or invalid session credential" });
        return;
      }
      this.apiRoute(path, req, res);
      return;
    }

    res.writeHead(404).end();
  }

  private apiRoute(path: string, req: IncomingMessage, res: ServerResponse): void {
    // The SSE stream and purge hold no store handle: streaming pushes are
    // broadcast from the daemon, and purge routes to onPurge.
    if (path === "/api/stream" && req.method === "GET") {
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      res.write(": connected\n\n");
      this.sseClients.add(res);
      req.on("close", () => {
        this.sseClients.delete(res);
        this.armIdleTimer();
      });
      return;
    }
    if (path === "/api/purge" && req.method === "POST") {
      void this.readJson(req).then((body) => {
        const kind = String((body as { kind?: string })?.kind ?? "all");
        if (!this.opts.onPurge) return this.json(res, 501, { error: "purge runs via the daemon" });
        this.opts.onPurge(kind);
        this.json(res, 200, { ok: true });
      });
      return;
    }

    const store = this.openStore();
    if (!store) {
      this.json(res, 200, []);
      return;
    }
    // readJson is async: track whether the async branch owns closing the store.
    let deferredClose = false;
    try {
      if (path === "/api/feed" && req.method === "GET") {
        this.json(res, 200, listExchanges(store, 500));
      } else if (path.startsWith("/api/exchange/") && req.method === "GET") {
        const ex = store.getExchange(path.slice("/api/exchange/".length));
        if (!ex) return this.json(res, 404, { error: "no such exchange" });
        // Reassemble the response, structure the request, and recover the
        // secret strings to highlight (detail.ts, UI fixes 1 + 2).
        this.json(res, 200, buildDetail(ex, leakSpansFor(store, ex.id)));
      } else if (path === "/api/search" && req.method === "POST") {
        deferredClose = true;
        void this.readJson(req).then((body) => {
          try {
            const term = String((body as { term?: string })?.term ?? "");
            this.json(res, 200, term ? store.searchLiteral(term) : []);
          } finally {
            store.close();
          }
        });
      } else if (path === "/api/leaks" && req.method === "GET") {
        this.json(res, 200, store.listLeakEvents());
      } else {
        this.json(res, 404, { error: "no such endpoint" });
      }
    } finally {
      if (!deferredClose) store.close();
    }
  }

  // ---- helpers ----

  private checkHostOrigin(req: IncomingMessage): boolean {
    const host = req.headers.host ?? "";
    const localHost =
      host === `127.0.0.1:${this.port}` || host === `localhost:${this.port}`;
    if (!localHost) return false;
    const origin = req.headers.origin;
    if (origin !== undefined) {
      const okOrigins = [`http://127.0.0.1:${this.port}`, `http://localhost:${this.port}`];
      if (!okOrigins.includes(origin)) return false;
    }
    return true;
  }

  private openStore(): Store | null {
    try {
      return Store.openReadOnly(this.opts.stateDir);
    } catch {
      return null;
    }
  }

  private json(res: ServerResponse, status: number, data: unknown): void {
    res.writeHead(status, {
      "content-type": "application/json",
      "content-security-policy": CSP,
      "x-content-type-options": "nosniff",
    });
    res.end(JSON.stringify(data));
  }

  private readJson(req: IncomingMessage): Promise<unknown> {
    return new Promise((resolve) => {
      let buf = "";
      req.on("data", (d) => (buf += d));
      req.on("end", () => {
        try {
          resolve(JSON.parse(buf));
        } catch {
          resolve(null);
        }
      });
    });
  }

  private armIdleTimer(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    const ms = this.opts.idleTimeoutMs ?? 10 * 60_000;
    this.idleTimer = setTimeout(() => {
      // Listen only while someone is looking (R12).
      if (this.sseClients.size === 0) this.stop();
      else this.armIdleTimer();
    }, ms);
    this.idleTimer.unref?.();
  }
}
