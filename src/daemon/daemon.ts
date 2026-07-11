// The daemon (design §6.7): owns the proxy listener, store writer, scanner
// host, session resolver, alert engine, control socket, and sweeper. The
// only writer; CLI and viewer read the store directly.
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Server } from "node:net";
import { AlertEngine, type AlertEvent } from "../core/alert/engine";
import { loadConfig, loadOrCreateInstallKey, type BeagleConfig } from "../core/config/config";
import type { Message } from "../core/exchange";
import { ProxyServer, type CapturedExchange, type ScanContext } from "../core/proxy/server";
import { RunRegistry, type RunRegistration } from "../core/proxy/registry";
import { SessionResolver, type Resolution } from "../core/session/resolver";
import { Store } from "../core/store/store";
import { ScanHost } from "../adapters/scan-host";
import { scrubAuthHeaders } from "../core/normalize/normalize";
import { Notifier } from "../notifier/notifier";
import { detectFormat, parseRequest, parseResponse, type Format, type ParsedRequest } from "../parsers/parsers";
import { startControlServer, type ControlRequest, type ControlResponse } from "./control";
import { ViewerServer } from "../viewer/server";

export interface DaemonOptions {
  stateDir: string;
  rulesPath?: string;
  rulesPinPath?: string;
  scanDeadlineMs?: number;
  alertSinkForTest?: (a: AlertEvent) => void;
}

interface PendingExchange {
  resolution: Resolution;
  parsed: ParsedRequest | null;
  format: Format;
  scanState: "ok" | "incomplete";
  createdTs: number;
}

// Pending entries whose capture never arrived (failed forward, abort before
// response) are dropped after this — the map must not grow unboundedly.
const PENDING_TTL_MS = 10 * 60_000;

const SWEEP_INTERVAL_MS = 15 * 60_000;

export class Daemon {
  proxyPort = 0;
  socketPath: string;

  private store!: Store;
  private config!: BeagleConfig;
  private registry!: RunRegistry;
  private resolver!: SessionResolver;
  private alertEngine!: AlertEngine;
  private scanHost!: ScanHost;
  private proxy!: ProxyServer;
  private control!: Server;
  private notifier = new Notifier();
  private viewer: ViewerServer | null = null;
  private pending = new Map<string, PendingExchange>();
  private paused = false;
  private sweeper: ReturnType<typeof setInterval> | null = null;

  private constructor(private opts: DaemonOptions) {
    this.socketPath = join(opts.stateDir, "control.sock");
  }

  static async start(opts: DaemonOptions): Promise<Daemon> {
    const d = new Daemon(opts);
    // One writer only: if a live daemon already owns this state dir, yield.
    const existing = await aliveDaemon(opts.stateDir);
    if (existing) {
      throw new Error(
        `a beagle daemon is already running (pid ${existing.pid}) — refusing to start a second writer`,
      );
    }
    d.store = Store.open(opts.stateDir);
    d.config = loadConfig(opts.stateDir);
    const installKey = loadOrCreateInstallKey(opts.stateDir);
    const rulesPath = opts.rulesPath ?? join(process.cwd(), "rules/beagle-rules.json");
    const pinPath = opts.rulesPinPath ?? join(process.cwd(), "rules/beagle-rules.sha256");
    d.scanHost = new ScanHost({
      rulesPath,
      rulesPin: existsSync(pinPath) ? readFileSync(pinPath, "utf8").trim() : undefined,
      hmacKey: installKey,
      deadlineMs: opts.scanDeadlineMs ?? 500,
    });
    d.registry = new RunRegistry(d.store);
    d.resolver = new SessionResolver(d.store);
    d.alertEngine = new AlertEngine(d.store, (a) => d.emitAlert(a));
    d.proxy = new ProxyServer({
      registry: d.registry,
      scan: (bytes, ctx) => d.scanPipeline(bytes, ctx),
      onExchange: (ex) => d.captureExchange(ex),
      captureBufferCap: 8 << 20,
    });
    await d.proxy.listen(0);
    d.proxyPort = d.proxy.port;
    d.control = await startControlServer(d.socketPath, (req) => d.handleControl(req));
    d.sweep();
    d.sweeper = setInterval(() => d.sweep(), SWEEP_INTERVAL_MS);
    d.sweeper.unref?.();
    writeFileSync(
      join(opts.stateDir, "daemon.json"),
      JSON.stringify({ pid: process.pid, proxyPort: d.proxyPort, socketPath: d.socketPath }),
      { mode: 0o600 },
    );
    return d;
  }

  async stop(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper);
    this.viewer?.stop();
    this.proxy.close();
    this.control.close();
    this.scanHost.close();
    this.store.close();
    rmSync(join(this.opts.stateDir, "daemon.json"), { force: true });
    rmSync(this.socketPath, { force: true });
  }

  // ---- pipeline ----

  private async scanPipeline(bytes: Uint8Array, ctx: ScanContext): Promise<void> {
    if (this.paused || this.config.excludedAgents.includes(ctx.agent ?? "")) return;
    const format = detectFormat(ctx.endpoint);
    const parsed = format === "unknown" ? null : parseRequest(format, bytes);
    // Session resolution is synchronous, before the first await: the capture
    // path (strictly later) relies on the pending entry existing.
    const resolution = this.resolver.resolve({
      agent: ctx.agent,
      provider: ctx.provider,
      runId: ctx.runId,
      ts: Date.now(),
      convId: parsed?.convId,
      prevResponseId: parsed?.prevResponseId,
      messages: parsed?.messages,
      systemPrompt: parsed?.system,
    });
    const entry: PendingExchange = {
      resolution, parsed, format, scanState: "ok", createdTs: Date.now(),
    };
    this.pending.set(ctx.exchangeId, entry);

    const result = await this.scanHost.scan(bytes, { authValue: ctx.authValue });
    if (result.state === "incomplete") {
      entry.scanState = "incomplete";
      this.store.updateExchangeScanState(ctx.exchangeId, "incomplete"); // no-op if not yet inserted
    }
    this.alertEngine.process(
      {
        id: ctx.exchangeId,
        sessionId: resolution.sessionId,
        agent: ctx.agent,
        provider: ctx.provider,
        model: parsed?.model,
      },
      result.findings,
    );
  }

  private captureExchange(ex: CapturedExchange): void {
    const stash = this.pending.get(ex.id);
    this.pending.delete(ex.id);
    if (this.paused || this.config.excludedAgents.includes(ex.agent ?? "")) return;
    const format = stash?.format ?? detectFormat(ex.endpoint);
    const parsed = stash?.parsed ?? null;
    const respParsed =
      format !== "unknown" && ex.response.bodyBytes
        ? parseResponse(format, ex.response.bodyBytes)
        : null;
    const resolution =
      stash?.resolution ??
      this.resolver.resolve({
        agent: ex.agent, provider: ex.provider, runId: ex.runId,
        ts: ex.meta.tsRequest, messages: parsed?.messages, systemPrompt: parsed?.system,
      });
    if (respParsed?.text || respParsed?.responseId) {
      const history: Message[] = [
        ...(parsed?.messages ?? []),
        ...(respParsed.text ? [{ role: "assistant", content: respParsed.text }] : []),
      ];
      this.resolver.recordResponse({
        sessionId: resolution.sessionId,
        messages: history.length > 0 ? history : undefined,
        responseId: respParsed.responseId,
      });
    }
    this.store.insertExchange({
      id: ex.id,
      sessionId: resolution.sessionId,
      runId: ex.runId,
      source: ex.source,
      agent: ex.agent,
      provider: ex.provider,
      model: parsed?.model ?? respParsed?.model,
      endpoint: ex.endpoint,
      tsRequest: ex.meta.tsRequest,
      tsResponse: ex.meta.tsResponse,
      status: ex.response.status,
      tokensIn: respParsed?.tokensIn,
      tokensOut: respParsed?.tokensOut,
      bytesReq: ex.request.bodyBytes.byteLength,
      bytesResp: ex.response.bodyBytes?.byteLength,
      summary: buildSummary(parsed, respParsed?.text),
      scanState: stash?.scanState ?? "ok",
      captureState: ex.meta.captureState,
      sessionTier: resolution.tier,
      requestBody: ex.request.bodyBytes,
      requestHeaders: ex.request.headers ?? null,
      responseBody: ex.response.bodyBytes ?? null,
      responseHeaders: ex.response.headers
        ? scrubAuthHeaders(ex.response.headers, undefined, ex.provider)
        : null,
      sseRaw: null,
      searchText: buildSearchText(parsed, respParsed?.text, ex),
    });
    this.viewer?.broadcast("exchange", {
      id: ex.id,
      sessionId: resolution.sessionId,
      agent: ex.agent,
      provider: ex.provider,
      model: parsed?.model ?? respParsed?.model,
      tsRequest: ex.meta.tsRequest,
      status: ex.response.status,
      tokensIn: respParsed?.tokensIn,
      tokensOut: respParsed?.tokensOut,
      bytesReq: ex.request.bodyBytes.byteLength,
      summary: buildSummary(parsed, respParsed?.text),
      scanState: stash?.scanState ?? "ok",
      captureState: ex.meta.captureState,
      sessionTier: resolution.tier,
      source: ex.source,
      hasLeak: false, // the alert event corrects this if a leak lands
    });
  }

  private emitAlert(a: AlertEvent): void {
    this.viewer?.broadcast("alert", a);
    if (this.opts.alertSinkForTest) {
      this.opts.alertSinkForTest(a);
      return;
    }
    this.notifier.notify({ title: a.title, body: a.body });
    process.stderr.write(this.notifier.terminalLine({ title: a.title, body: a.body }) + "\n");
  }

  private sweep(): void {
    this.store.sweep({
      payloadWindowMs: this.config.payloadWindowDays * 24 * 3600_000,
      eventWindowMs: this.config.eventWindowDays * 24 * 3600_000,
      sizeCapBytes: this.config.sizeCapMB * (1 << 20),
    });
    const cutoff = Date.now() - PENDING_TTL_MS;
    for (const [id, entry] of this.pending) {
      if (entry.createdTs < cutoff) this.pending.delete(id);
    }
  }

  // ---- control ----

  private async handleControl(req: ControlRequest): Promise<ControlResponse> {
    switch (req.cmd) {
      case "ping":
        return { ok: true, data: { pid: process.pid, proxyPort: this.proxyPort } };
      case "register-run": {
        this.registry.register(req.args as unknown as RunRegistration);
        return { ok: true };
      }
      case "pause":
        this.paused = true;
        return { ok: true };
      case "resume":
        this.paused = false;
        return { ok: true };
      case "status":
        return {
          ok: true,
          data: {
            paused: this.paused,
            proxyPort: this.proxyPort,
            exchanges: this.store.countExchanges(),
            leaks: this.store.countLeakEvents(),
          },
        };
      case "purge": {
        const args = (req.args ?? {}) as { kind?: string; sessionId?: string; ts?: number };
        if (args.kind === "all") this.store.purge({ kind: "all" });
        else if (args.kind === "panic") this.store.panicPurge();
        else if (args.kind === "session" && args.sessionId)
          this.store.purge({ kind: "session", sessionId: args.sessionId });
        else if (args.kind === "before" && args.ts)
          this.store.purge({ kind: "before", ts: args.ts });
        else return { ok: false, error: "unknown purge spec" };
        return { ok: true };
      }
      case "ui": {
        if (!this.viewer?.isRunning) {
          this.viewer = new ViewerServer({
            stateDir: this.opts.stateDir,
            onPurge: (kind) => {
              if (kind === "panic") this.store.panicPurge();
              else this.store.purge({ kind: "all" });
            },
          });
          const url = await this.viewer.start();
          return { ok: true, data: { url } };
        }
        // A viewer is already up: mint a fresh one-time URL by restarting it.
        this.viewer.stop();
        this.viewer = new ViewerServer({ stateDir: this.opts.stateDir });
        return { ok: true, data: { url: await this.viewer.start() } };
      }
      case "shutdown":
        setTimeout(() => void this.stop().then(() => process.exit(0)), 10);
        return { ok: true };
      default:
        return { ok: false, error: `unknown command: ${req.cmd}` };
    }
  }
}

async function aliveDaemon(stateDir: string): Promise<{ pid: number } | null> {
  try {
    const info = JSON.parse(
      readFileSync(join(stateDir, "daemon.json"), "utf8"),
    ) as { pid: number; socketPath: string };
    const { controlRequest } = await import("./control");
    const r = await controlRequest(info.socketPath, { cmd: "ping" }, 500);
    return r.ok ? { pid: info.pid } : null;
  } catch {
    return null;
  }
}

function buildSummary(parsed: ParsedRequest | null, responseText?: string): string {
  if (!parsed) return "unparsed exchange (raw view available)";
  const lastUser = [...parsed.messages].reverse().find((m) => m.role === "user");
  const head = lastUser ? firstLine(lastUser.content, 80) : `${parsed.messages.length} messages`;
  const tail = responseText ? ` → ${firstLine(responseText, 60)}` : "";
  return head + tail;
}

function firstLine(s: string, max: number): string {
  const line = s.split("\n")[0] ?? "";
  return line.length > max ? line.slice(0, max - 1) + "…" : line;
}

function buildSearchText(
  parsed: ParsedRequest | null,
  responseText: string | undefined,
  ex: CapturedExchange,
): string {
  // Parsed text where a parser ran (finds secrets that appear \"-escaped in
  // raw JSON); decoded raw text otherwise (R8 / schema note).
  if (parsed) {
    const parts = [parsed.system ?? "", ...parsed.messages.map((m) => m.content)];
    if (responseText) parts.push(responseText);
    return parts.join("\n");
  }
  const dec = new TextDecoder("utf-8", { fatal: false });
  return (
    dec.decode(ex.request.bodyBytes) +
    "\n" +
    (ex.response.bodyBytes ? dec.decode(ex.response.bodyBytes) : "")
  );
}
