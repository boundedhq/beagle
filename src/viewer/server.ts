// Viewer server (design §6.8): serves the crown-jewels page, hardened as a
// unit — loopback bind, one-time bootstrap token → header credential,
// Origin/Host validation, strict CSP, POST-only mutations, fetch-SSE feed,
// idle shutdown when the last tab disconnects.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { Store } from "../core/store/store";
import { listenReady } from "../core/net/listen";
import { feedStats, listCalls, listLeakEvents } from "./feed-query";
import { buildDetail, detailLeaks, detailMessages, leakSpansFor } from "./detail";
import { buildSessionTurns, listSessions, wireDeltaIndex } from "./session-view";
// Statics embedded at build time (ships-what's-in-repo, and the compiled
// binary has no filesystem view of the repo).
import indexHtmlRaw from "./static/index.html" with { type: "text" };
import appJs from "./static/app.js" with { type: "text" };
import renderJsonJs from "./static/render-json.module.js" with { type: "text" };
// bun-types types *.html imports as HTMLBundle; with { type: "text" } the
// runtime value is a plain string.
const indexHtml = indexHtmlRaw as unknown as string;
import styleCss from "./static/style.css" with { type: "text" };
import preactJs from "./static/vendor/preact.module.js" with { type: "text" };
import preactHooksJs from "./static/vendor/preact-hooks.module.js" with { type: "text" };
import htmJs from "./static/vendor/htm.module.js" with { type: "text" };

export interface ViewerOptions {
  stateDir: string;
  /** Grace before winding down while NO tab has connected yet (the "ran
   *  `beagle ui`, haven't opened the link" window). Default 10 min. */
  idleTimeoutMs?: number;
  /** Grace after the LAST tab closes before winding down. The server can't
   *  tell a real close from a transient drop — both surface as the SSE close
   *  event — so this ALSO bounds how long an *open* tab survives a network
   *  blip / laptop sleep / slow reload before the viewer tears down under it.
   *  Default 30s: rides out reloads, the client's ~1.5s auto-reconnect, and
   *  brief drops, while still releasing the daemon's "open dashboard" hold
   *  promptly. It isn't the shutdown bottleneck anyway — the daemon's own
   *  idle-exit grace only starts once the viewer stops and dominates the total,
   *  so a larger linger here costs ~nothing and is much safer. */
  lingerMs?: number;
  /** Mutations ride through the daemon (single writer); absent → 501. */
  onPurge?: (kind: string, sessionId?: string) => void;
}

const STATIC_FILES: Record<string, { body: string; type: string }> = {
  "/": { body: indexHtml, type: "text/html; charset=utf-8" },
  "/app.js": { body: appJs, type: "text/javascript; charset=utf-8" },
  "/render-json.module.js": { body: renderJsonJs, type: "text/javascript; charset=utf-8" },
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
    const server = createServer((req, res) => this.route(req, res));
    this.server = server;
    return listenReady(server, () => server.listen(0, "127.0.0.1")).then(() => {
      this.port = (server.address() as { port: number }).port;
      this.isRunning = true;
      this.armIdleTimer();
      return `http://127.0.0.1:${this.port}/?boot=${this.bootToken}`;
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

  /** Push a live event (new call, alert) to any open tabs. */
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
        // Last tab gone → wind down after a short linger, not the full idle
        // window: an open tab holds its SSE connection, so size 0 means nobody
        // is looking. A reload reconnects within the linger and cancels it.
        if (this.sseClients.size === 0) this.armLinger();
        else this.armIdleTimer();
      });
      return;
    }
    if (path === "/api/purge" && req.method === "POST") {
      void this.readJson(req).then((body) => {
        const b = body as { kind?: string; sessionId?: string };
        const kind = String(b?.kind ?? "all");
        const sessionId = typeof b?.sessionId === "string" ? b.sessionId : undefined;
        if (!this.opts.onPurge) return this.json(res, 501, { error: "purge runs via the daemon" });
        // Whitelist the destructive verbs — an unrecognized kind must be
        // rejected, never quietly widened into a full wipe downstream.
        if (kind !== "all" && kind !== "panic" && kind !== "session")
          return this.json(res, 400, { error: "unknown purge kind" });
        // A scoped purge without a target must never fall through to "all".
        if (kind === "session" && !sessionId)
          return this.json(res, 400, { error: "session purge needs a sessionId" });
        this.opts.onPurge(kind, sessionId);
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
        this.json(res, 200, listCalls(store, 500));
      } else if (path === "/api/stats" && req.method === "GET") {
        // whole-store totals for the header cards (the feed is a 500-row window)
        this.json(res, 200, feedStats(store));
      } else if (path.startsWith("/api/call/") && req.method === "GET") {
        const call = store.getCall(path.slice("/api/call/".length));
        if (!call) return this.json(res, 404, { error: "no such call" });
        // Reassemble the response, structure the request, and recover the
        // secret strings to highlight (detail.ts, UI fixes 1 + 2).
        const detail = buildDetail(call, leakSpansFor(store, call.id));
        if (call.source === "wire") {
          // Where does NEW content start? Diff against the nearest previous
          // wire call that parses (≤5 back — beyond that, no truthful claim,
          // newFrom stays null and the view makes no context/new split).
          // Same ordering as buildSessionTurns so both surfaces agree.
          const prevIds = store.queryAll<{ id: string }>(
            `SELECT id FROM exchanges WHERE session_id = ?1 AND source = 'wire'
               AND (ts_request < ?2 OR (ts_request = ?2 AND id < ?3))
             ORDER BY ts_request DESC, id DESC LIMIT 5`,
            [call.sessionId, call.tsRequest, call.id],
          );
          for (const { id } of prevIds) {
            const prev = store.getCall(id);
            if (!prev) continue;
            const prevMessages = detailMessages(prev); // messages only — no response re-parse
            if (prevMessages.length > 0) {
              detail.newFrom = wireDeltaIndex(detail.messages, prevMessages);
              break;
            }
          }
          // The response's content (tool args, echoed text) is scanned on the
          // NEXT request — surface those leaks so the response section can
          // highlight them (display-only; the event stays on the next call).
          const nextId = store.queryAll<{ id: string }>(
            `SELECT id FROM exchanges WHERE session_id = ?1 AND source = 'wire'
               AND (ts_request > ?2 OR (ts_request = ?2 AND id > ?3))
             ORDER BY ts_request ASC, id ASC LIMIT 1`,
            [call.sessionId, call.tsRequest, call.id],
          )[0];
          if (nextId) {
            const next = store.getCall(nextId.id);
            if (next) detail.responseLeaks = detailLeaks(next, leakSpansFor(store, next.id)); // leaks only
          }
        }
        this.json(res, 200, detail);
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
        this.json(res, 200, listLeakEvents(store));
      } else if (path === "/api/sessions" && req.method === "GET") {
        this.json(res, 200, listSessions(store, 200));
      } else if (path.startsWith("/api/session/") && req.method === "GET") {
        // the whole session as a chronological conversation (session-view.ts)
        this.json(res, 200, buildSessionTurns(store, path.slice("/api/session/".length)));
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
      // Known blind spot, accepted: a StoreVersionError here renders as an
      // empty store (200 []), not the clean version message the CLI gives.
      // Unreachable in the shipped topology — the viewer only runs inside the
      // daemon, which migrates the store before the viewer exists — so the
      // null keeps transient open races from 500ing a live dashboard.
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
    // Cap the body: /api/session runs this BEFORE the bootstrap token is
    // checked, so an unbounded reader lets any local process that finds the
    // loopback port stream gigabytes to exhaust memory. Viewer POSTs are tiny
    // (a token, a session id) — 256 KiB is orders of magnitude of headroom.
    return new Promise((resolve) => {
      let buf = "";
      let over = false;
      req.on("data", (d) => {
        if (over) return;
        buf += d;
        // Over the cap: stop retaining bytes and resolve null now (the caller
        // treats null as a bad request → 401/400). Further data is ignored, so
        // memory is bounded; we don't destroy the socket, so the handler can
        // still send its response.
        if (buf.length > 256 * 1024) {
          over = true;
          buf = "";
          resolve(null);
        }
      });
      req.on("end", () => {
        if (over) return;
        try {
          resolve(JSON.parse(buf));
        } catch {
          resolve(null);
        }
      });
    });
  }

  private armIdleTimer(): void {
    this.armWindDown(this.opts.idleTimeoutMs ?? 10 * 60_000);
  }

  // After the last tab closes, tear down after a brief grace instead of the
  // long pre-connection idle window — so closing the dashboard promptly stops
  // the viewer and releases the daemon's "open dashboard" hold. A page reload
  // reconnects (a new request re-arms the long timer) before this fires.
  private armLinger(): void {
    this.armWindDown(this.opts.lingerMs ?? 30_000);
  }

  private armWindDown(ms: number): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      // Listen only while someone is looking (R12).
      if (this.sseClients.size === 0) this.stop();
      else this.armIdleTimer();
    }, ms);
    this.idleTimer.unref?.();
  }
}
