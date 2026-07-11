// OTLP/HTTP receiver (design §6.2, Mode B). Minimal loopback endpoint that
// accepts json-only OTel logs, gated by a per-run token. Protobuf is rejected
// by construction — hand-decoding proto has no place in the zero-dep budget.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { mapOtlpLogsToExchanges, type OtelExchange } from "../../parsers/otlp-map";

export interface OtlpReceiverOptions {
  token: string;
  agent?: string;
  provider?: string;
  onExchanges: (exchanges: OtelExchange[]) => void;
  maxBodyBytes?: number;
}

export class OtlpReceiver {
  boundAddress = "";
  private server: Server | null = null;

  constructor(private opts: OtlpReceiverOptions) {}

  listen(port: number): Promise<number> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handle(req, res));
      this.server.listen(port, "127.0.0.1", () => {
        const addr = this.server!.address() as { port: number; address: string };
        this.boundAddress = addr.address;
        resolve(addr.port);
      });
    });
  }

  close(): void {
    this.server?.close();
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== "POST" || !(req.url ?? "").startsWith("/v1/logs")) {
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
      let payload: unknown;
      try {
        // Decode once from the assembled bytes — never coerce per chunk, which
        // would split multi-byte UTF-8 across boundaries and corrupt content.
        payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        res.writeHead(400).end("invalid json");
        return;
      }
      const exchanges = mapOtlpLogsToExchanges(payload, {
        agent: this.opts.agent ?? "claude-code",
        provider: this.opts.provider ?? "anthropic",
      });
      // Only deliver records whose embedded run token matches (defense in
      // depth: the header already gated the request).
      const verified = exchanges.filter((e) => !e.runToken || this.tokenOk(e.runToken));
      if (verified.length > 0) this.opts.onExchanges(verified);
      // OTLP success envelope.
      res.writeHead(200, { "content-type": "application/json" }).end("{}");
    });
  }

  private tokenOk(candidate: string): boolean {
    const a = Buffer.from(candidate);
    const b = Buffer.from(this.opts.token);
    return a.length === b.length && timingSafeEqual(a, b);
  }
}
