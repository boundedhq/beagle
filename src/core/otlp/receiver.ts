// OTLP/HTTP receiver (design §6.2, Mode B). Minimal loopback endpoint that
// accepts json-only OTel logs, gated by a per-daemon token. Protobuf is
// rejected by construction — hand-decoding proto has no place in the zero-dep
// budget. Two routes: /v1/logs (agent OTel exports — Claude Code's and
// Codex's, discriminated by the payload's event schema) and /v1/hook (Claude
// Code's PostToolUse hook, carrying the tool-output content its export omits).
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { mapHookToCall, mapOtlpLogsToCalls, type OtelCall } from "../../parsers/otlp-map";
import { listenReady } from "../net/listen";

export interface OtlpReceiverOptions {
  token: string;
  agent?: string;
  provider?: string;
  onCalls: (calls: OtelCall[]) => void;
  maxBodyBytes?: number;
}

export class OtlpReceiver {
  boundAddress = "";
  private server: Server | null = null;
  private dumpSeq = 0;

  constructor(private opts: OtlpReceiverOptions) {}

  listen(port: number): Promise<number> {
    const server = createServer((req, res) => this.handle(req, res));
    this.server = server;
    return listenReady(server, () => server.listen(port, "127.0.0.1")).then(() => {
      const addr = server.address() as { port: number; address: string };
      this.boundAddress = addr.address;
      return addr.port;
    });
  }

  close(): void {
    this.server?.close();
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    const path = req.url ?? "";
    const isHook = path.startsWith("/v1/hook");
    if (req.method !== "POST" || !(path.startsWith("/v1/logs") || isHook)) {
      res.writeHead(404).end();
      return;
    }
    const ctype = (req.headers["content-type"] ?? "").toLowerCase();
    if (!ctype.includes("application/json")) {
      // json-only by construction (§6.2)
      res.writeHead(415).end("beagle OTLP receiver accepts application/json only");
      return;
    }
    const token = req.headers["x-beagle-run"];
    if (typeof token !== "string" || !this.tokenOk(token)) {
      res.writeHead(401).end();
      return;
    }
    const cap = this.opts.maxBodyBytes ?? 32 << 20;
    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    req.on("data", (d: Buffer) => {
      if (over) return;
      size += d.length;
      if (size > cap) {
        over = true;
        res.writeHead(413).end();
        req.destroy();
        return;
      }
      chunks.push(d);
    });
    req.on("end", () => {
      if (over) return;
      const raw = Buffer.concat(chunks);
      this.dumpRaw(isHook ? "hook" : "logs", raw);
      let payload: unknown;
      try {
        // Decode once from the assembled bytes — never coerce per chunk, which
        // would split multi-byte UTF-8 across boundaries and corrupt content.
        payload = JSON.parse(raw.toString("utf8"));
      } catch {
        res.writeHead(400).end("invalid json");
        return;
      }
      const ctx = {
        // "claude" — the CLI/config agent key, NOT "claude-code": exclusion
        // (config.excludedAgents) and the wire rows both key on the CLI name,
        // so a different label here would split the store and silently defeat
        // `beagle config exclude claude` for Mode B rows.
        agent: this.opts.agent ?? "claude",
        provider: this.opts.provider ?? "anthropic",
      };
      const calls = isHook
        ? [mapHookToCall(payload, ctx)].filter((c): c is OtelCall => c !== null)
        : mapOtlpLogsToCalls(payload, ctx);
      // Only deliver records whose embedded run token matches (defense in
      // depth: the header already gated the request).
      const verified = calls.filter((e) => !e.runToken || this.tokenOk(e.runToken));
      if (verified.length > 0) this.opts.onCalls(verified);
      // OTLP success envelope.
      res.writeHead(200, { "content-type": "application/json" }).end("{}");
    });
  }

  // Diagnostic escape hatch, off unless BEAGLE_OTLP_DUMP names a directory.
  // Writes every received body there verbatim, before parsing — the only way to
  // see what an agent's telemetry actually emits for a live interactive turn
  // (Mode B response-fidelity debugging). Best-effort and fully swallowed: a
  // dump failure must never disturb capture. Bodies may contain prompt/response
  // content, so this is opt-in and points wherever the operator chooses.
  private dumpRaw(route: string, bytes: Buffer): void {
    const dir = process.env.BEAGLE_OTLP_DUMP;
    if (!dir) return;
    try {
      mkdirSync(dir, { recursive: true });
      const seq = String(++this.dumpSeq).padStart(4, "0");
      writeFileSync(join(dir, `otlp-${seq}-${route}.json`), bytes);
    } catch {
      // diagnostic only — never surface into the capture path
    }
  }

  private tokenOk(candidate: string): boolean {
    const a = Buffer.from(candidate);
    const b = Buffer.from(this.opts.token);
    return a.length === b.length && timingSafeEqual(a, b);
  }
}
