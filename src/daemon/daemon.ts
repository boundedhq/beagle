// The daemon (design §6.7): owns the proxy listener, store writer, scanner
// host, session resolver, alert engine, control socket, and sweeper. The
// only writer; CLI and viewer read the store directly.
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { Server, Socket } from "node:net";
import { AlertEngine, type AlertEvent } from "../core/alert/engine";
import { loadConfig, saveConfig, loadOrCreateInstallKey, type BeagleConfig } from "../core/config/config";
import type { Message } from "../core/exchange";
import { ProxyServer, type CapturedExchange, type ScanContext } from "../core/proxy/server";
import { RunRegistry, type RunRegistration } from "../core/proxy/registry";
import { SessionResolver, type Resolution } from "../core/session/resolver";
import { Store } from "../core/store/store";
import { ScanHost } from "../adapters/scan-host";
import type { Finding } from "../core/scanner/engine";
import { redactBody, redactValues } from "../transform/redact";
import { scrubAuthHeaders } from "../core/normalize/normalize";
import { Notifier } from "../notifier/notifier";
import { detectFormat, extractActions, parseRequest, parseResponse, type Format, type ParsedRequest, type ToolAction } from "../parsers/parsers";
import { startControlServer, type ControlRequest, type ControlResponse } from "./control";
import { ViewerServer } from "../viewer/server";
import { OtlpReceiver } from "../core/otlp/receiver";
import type { OtelExchange } from "../parsers/otlp-map";
// Embedded at build time so the compiled binary needs no repo checkout.
// (bun-types types *.json as a parsed object; with { type: "text" } the
// runtime value is the raw string — required for the sha256 pin to verify.)
import embeddedRulesRaw from "../../rules/beagle-rules.json" with { type: "text" };
import embeddedRulesPin from "../../rules/beagle-rules.sha256" with { type: "text" };
const embeddedRules = embeddedRulesRaw as unknown as string;

export interface DaemonOptions {
  stateDir: string;
  rulesJson?: string; // override for tests; defaults to the embedded corpus
  rulesPin?: string;
  scanDeadlineMs?: number;
  alertSinkForTest?: (a: AlertEvent) => void;
  /** Never idle-exit — set for the service-installed daemon (§6.7), inferred
   *  from BEAGLE_SERVICE=1 when unset. */
  persistent?: boolean;
  /** Idle grace before an ephemeral daemon (no live leases, no open viewer)
   *  exits. Default 2 min. */
  idleTimeoutMs?: number;
  /** Production run-mode daemon exits the process on idle; tests set false. */
  exitProcessOnIdle?: boolean;
}

interface PendingExchange {
  resolution: Resolution;
  parsed: ParsedRequest | null;
  format: Format;
  scanState: "ok" | "incomplete";
  findings: Finding[];
  scanDone: Promise<void>;
  createdTs: number;
}

// Pending entries whose capture never arrived (failed forward, abort before
// response) are dropped after this — the map must not grow unboundedly.
const PENDING_TTL_MS = 10 * 60_000;

const SWEEP_INTERVAL_MS = 15 * 60_000;

const DEFAULT_IDLE_MS = 2 * 60_000;

export class Daemon {
  proxyPort = 0;
  socketPath: string;
  isRunning = false;

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
  private otlp: OtlpReceiver | null = null;
  otlpPort = 0;
  private otlpToken = "";
  private pending = new Map<string, PendingExchange>();
  private paused = false;
  private sweeper: ReturnType<typeof setInterval> | null = null;
  private leases = 0;
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private persistent = false;
  // Last time the pipeline saw traffic. The idle check consults this so a
  // daemon actively relaying (even with a lost/failed lease) never stops
  // mid-agent-session — leases are the primary signal, this is the backstop.
  private lastActivityTs = Date.now();

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
    d.store = Store.openOrRecover(opts.stateDir);
    d.config = loadConfig(opts.stateDir);
    const installKey = loadOrCreateInstallKey(opts.stateDir);
    d.scanHost = new ScanHost({
      rulesJson: opts.rulesJson ?? embeddedRules,
      rulesPin: opts.rulesPin ?? embeddedRulesPin.trim(),
      hmacKey: installKey,
      deadlineMs: opts.scanDeadlineMs ?? 500,
    });
    d.registry = new RunRegistry(d.store);
    d.resolver = new SessionResolver(d.store);
    d.alertEngine = new AlertEngine(d.store, (a) => d.emitAlert(a));
    d.proxy = new ProxyServer({
      registry: d.registry,
      scan: (bytes, ctx) => d.scanPipeline(bytes, ctx),
      onExchange: (ex) => void d.captureExchange(ex).catch(() => {}),
      captureBufferCap: 8 << 20,
    });
    await d.proxy.listen(0);
    d.proxyPort = d.proxy.port;
    // A per-daemon-session token, minted into the agent's OTEL headers — never
    // the install key (which must not leave the machine).
    d.otlpToken = randomBytes(24).toString("hex");
    d.otlp = new OtlpReceiver({
      token: d.otlpToken,
      onExchanges: (exs) => d.ingestOtel(exs),
    });
    d.otlpPort = await d.otlp.listen(0);
    d.control = await startControlServer(d.socketPath, (req, sock) => d.handleControl(req, sock));
    d.sweep();
    d.sweeper = setInterval(() => d.sweep(), SWEEP_INTERVAL_MS);
    d.sweeper.unref?.();
    writeFileSync(
      join(opts.stateDir, "daemon.json"),
      JSON.stringify({
        pid: process.pid, proxyPort: d.proxyPort, socketPath: d.socketPath,
        otlpPort: d.otlpPort, otlpToken: d.otlpToken,
      }),
      { mode: 0o600 },
    );
    d.isRunning = true;
    d.persistent = opts.persistent ?? process.env.BEAGLE_SERVICE === "1";
    // Arm the idle timer at startup: a daemon nobody ever leases (or whose
    // spawning `beagle run` died before leasing) still winds down.
    d.armIdleExit();
    return d;
  }

  async stop(): Promise<void> {
    if (!this.isRunning) return;
    this.isRunning = false;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (this.sweeper) clearInterval(this.sweeper);
    this.viewer?.stop();
    this.otlp?.close();
    this.proxy.close();
    this.control.close();
    this.scanHost.close();
    this.store.close();
    rmSync(join(this.opts.stateDir, "daemon.json"), { force: true });
    rmSync(this.socketPath, { force: true });
  }

  // ---- pipeline ----

  private async scanPipeline(bytes: Uint8Array, ctx: ScanContext): Promise<void> {
    this.lastActivityTs = Date.now();
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
    let resolveScan!: () => void;
    const scanDone = new Promise<void>((r) => (resolveScan = r));
    const entry: PendingExchange = {
      resolution, parsed, format, scanState: "ok", findings: [], scanDone,
      createdTs: Date.now(),
    };
    this.pending.set(ctx.exchangeId, entry);

    const result = await this.scanHost.scan(bytes, { authValue: ctx.authValue });
    entry.findings = result.findings;
    if (result.state === "incomplete") {
      entry.scanState = "incomplete";
      this.store.updateExchangeScanState(ctx.exchangeId, "incomplete"); // no-op if not yet inserted
    }
    resolveScan();
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

  private async captureExchange(ex: CapturedExchange): Promise<void> {
    const stash = this.pending.get(ex.id);
    // redact-on-capture (R11): await the scan verdict and substitute the raw
    // secret BEFORE the first write, so no raw value ever lands in the WAL.
    if (this.config.redactOnCapture && stash) {
      await stash.scanDone;
    }
    this.pending.delete(ex.id);
    if (this.paused || this.config.excludedAgents.includes(ex.agent ?? "")) return;
    const format = stash?.format ?? detectFormat(ex.endpoint);
    const parsed = stash?.parsed ?? null;
    const respBytes = ex.response.bodyBytes ?? ex.response.sseRaw;
    const respParsed = format !== "unknown" && respBytes ? parseResponse(format, respBytes) : null;
    const respActions = format !== "unknown" && respBytes ? extractActions(format, respBytes) : [];
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

    // redact-on-capture: substitute secret spans in the persisted body. If the
    // scan came back incomplete we can't trust the spans, so we hold the raw
    // value out entirely and mark it (never write raw-and-hope, §4).
    let requestBody: Uint8Array | null = ex.request.bodyBytes;
    let responseBody: Uint8Array | null = ex.response.bodyBytes ?? null;
    let sseRaw: Uint8Array | null = ex.response.sseRaw ?? null;
    let searchText = buildSearchText(parsed, respParsed?.text, ex);
    // True only when the stored body was actually rewritten (viewer highlight).
    let redacted = false;
    if (this.config.redactOnCapture && stash) {
      if (stash.scanState === "incomplete") {
        redacted = true;
        requestBody = new TextEncoder().encode("[REDACTION INCOMPLETE: scan did not verify this body]");
        responseBody = null;
        sseRaw = null; // the raw stream could hold the unverified value
        searchText = "";
      } else if (stash.findings.length > 0) {
        redacted = true;
        const scrubbed = redactBody(ex.request.bodyBytes, stash.findings);
        requestBody = scrubbed.bytes;
        // Scrub the same secret values from the response AND the raw stream, in
        // case the model echoed a leaked key back (request-side redaction alone
        // would miss it).
        responseBody = redactValues(responseBody, scrubbed.values);
        // A content-encoded raw stream is compressed bytes — a literal scrub
        // can't find the secret in it, so keeping it would silently retain an
        // echoed value. Drop it; the decoded (scrubbed) body remains.
        const contentEncoded = ex.response.headers?.some(
          ([n, v]) =>
            n.toLowerCase() === "content-encoding" &&
            v.trim() !== "" &&
            v.trim().toLowerCase() !== "identity",
        );
        sseRaw = contentEncoded ? null : redactValues(sseRaw, scrubbed.values);
        searchText =
          new TextDecoder().decode(requestBody) +
          "\n" +
          (responseBody ? new TextDecoder().decode(responseBody) : "");
      }
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
      summary: buildSummary(parsed, respParsed?.text, respActions),
      scanState: stash?.scanState ?? "ok",
      captureState: ex.meta.captureState,
      sessionTier: resolution.tier,
      redacted,
      requestBody,
      requestHeaders: ex.request.headers ?? null,
      responseBody,
      responseHeaders: ex.response.headers
        ? scrubAuthHeaders(ex.response.headers, undefined, ex.provider)
        : null,
      sseRaw,
      searchText,
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
      summary: buildSummary(parsed, respParsed?.text, respActions),
      scanState: stash?.scanState ?? "ok",
      captureState: ex.meta.captureState,
      sessionTier: resolution.tier,
      source: ex.source,
      hasLeak: false, // the alert event corrects this if a leak lands
    });
  }

  // Mode B ingest (design §6.2): OTel-reported exchanges run the identical
  // scanner/session/alert/store path — source='otel' is the only difference,
  // surfaced as the agent-reported badge (R7).
  private async ingestOtel(exchanges: OtelExchange[]): Promise<void> {
    this.lastActivityTs = Date.now();
    for (const ex of exchanges) {
      if (this.paused || this.config.excludedAgents.includes(ex.agent ?? "")) continue;
      const resolution = this.resolver.resolve({
        agent: ex.agent,
        provider: ex.provider,
        runId: ex.runId,
        ts: ex.meta.tsRequest,
        convId: ex.convId,
        messages: ex.request.messages,
      });
      const scanResult = await this.scanHost.scan(ex.request.bodyBytes, {});
      // Keep session chaining state current, same as the wire path — so a
      // Mode B session without an explicit id still chains across turns.
      if (ex.request.messages?.length || ex.response.text) {
        this.resolver.recordResponse({
          sessionId: resolution.sessionId,
          messages: [
            ...(ex.request.messages ?? []),
            ...(ex.response.text ? [{ role: "assistant", content: ex.response.text }] : []),
          ],
          responseId: ex.convId,
        });
      }
      this.store.insertExchange({
        id: ex.id,
        sessionId: resolution.sessionId,
        runId: ex.runId,
        source: "otel",
        agent: ex.agent,
        provider: ex.provider,
        model: ex.model,
        endpoint: ex.endpoint,
        tsRequest: ex.meta.tsRequest,
        tsResponse: ex.meta.tsResponse,
        status: 200,
        tokensIn: ex.meta.tokensIn,
        tokensOut: ex.meta.tokensOut,
        bytesReq: ex.request.bodyBytes.byteLength,
        bytesResp: ex.response.bodyBytes?.byteLength,
        summary: buildSummary(
          { model: ex.model, messages: ex.request.messages ?? [] } as ParsedRequest,
          ex.response.text,
        ),
        scanState: scanResult.state,
        captureState: "ok",
        sessionTier: resolution.tier,
        requestBody: ex.request.bodyBytes,
        requestHeaders: null,
        responseBody: ex.response.bodyBytes ?? null,
        responseHeaders: null,
        sseRaw: null,
        searchText:
          (ex.request.messages?.map((m) => m.content).join("\n") ?? "") + "\n" + (ex.response.text ?? ""),
      });
      this.alertEngine.process(
        {
          id: ex.id,
          sessionId: resolution.sessionId,
          agent: ex.agent,
          provider: ex.provider,
          model: ex.model,
        },
        scanResult.findings,
      );
      this.viewer?.broadcast("exchange", {
        id: ex.id,
        sessionId: resolution.sessionId,
        agent: ex.agent,
        provider: ex.provider,
        model: ex.model,
        tsRequest: ex.meta.tsRequest,
        status: 200,
        tokensIn: ex.meta.tokensIn,
        tokensOut: ex.meta.tokensOut,
        bytesReq: ex.request.bodyBytes.byteLength,
        summary: buildSummary(
          { model: ex.model, messages: ex.request.messages ?? [] } as ParsedRequest,
          ex.response.text,
        ),
        scanState: scanResult.state,
        captureState: "ok",
        sessionTier: resolution.tier,
        source: "otel",
        hasLeak: false,
      });
    }
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

  // Ephemeral run-mode daemon (§6.7): once it owns no live runs and hosts no
  // open viewer, wind down after a grace period so a "nothing changed" trial
  // run leaves no background process behind. The service-installed daemon
  // (persistent) never does this.
  private armIdleExit(): void {
    if (this.persistent || !this.isRunning) return;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (this.leases > 0 || this.viewer?.isRunning) return;
    const idleMs = this.opts.idleTimeoutMs ?? DEFAULT_IDLE_MS;
    this.idleTimer = setTimeout(() => {
      const recentTraffic = Date.now() - this.lastActivityTs < idleMs;
      if (this.leases > 0 || this.viewer?.isRunning || recentTraffic) {
        // Something reappeared — or the proxy is actively relaying (a lost
        // lease must never let us stop mid-agent-session). Re-check later.
        this.idleTimer = null;
        this.armIdleExit();
        return;
      }
      void this.stop().then(() => {
        if (this.opts.exitProcessOnIdle !== false) process.exit(0);
      });
    }, idleMs);
    this.idleTimer.unref?.();
  }

  private makeViewer(): ViewerServer {
    const v = new ViewerServer({
      stateDir: this.opts.stateDir,
      onPurge: (kind) => {
        if (kind === "panic") this.store.panicPurge();
        else this.store.purge({ kind: "all" });
      },
    });
    v.onStop = () => this.armIdleExit(); // viewer closed → maybe wind down
    return v;
  }

  // ---- control ----

  private async handleControl(req: ControlRequest, socket: Socket): Promise<ControlResponse> {
    switch (req.cmd) {
      case "ping":
        return { ok: true, data: { pid: process.pid, proxyPort: this.proxyPort } };
      case "lease": {
        // The caller holds this connection for a watched agent's lifetime;
        // count it as a live run so the daemon doesn't idle-exit. Closing the
        // socket (or the caller crashing) releases it automatically.
        this.leases++;
        if (this.idleTimer) { clearTimeout(this.idleTimer); this.idleTimer = null; }
        socket.once("close", () => {
          this.leases = Math.max(0, this.leases - 1);
          this.armIdleExit();
        });
        return { ok: true, data: { leased: true } };
      }
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
      case "set-config": {
        const args = (req.args ?? {}) as Partial<BeagleConfig>;
        if (typeof args.redactOnCapture === "boolean") this.config.redactOnCapture = args.redactOnCapture;
        if (Array.isArray(args.excludedAgents)) this.config.excludedAgents = args.excludedAgents;
        saveConfig(this.opts.stateDir, this.config);
        return { ok: true, data: this.config };
      }
      case "status":
        return {
          ok: true,
          data: {
            paused: this.paused,
            proxyPort: this.proxyPort,
            otlpPort: this.otlpPort,
            otlpToken: this.otlpToken,
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
        // An open viewer keeps the daemon alive; when it later shuts down
        // (last tab / idle) we re-evaluate idle-exit.
        if (this.idleTimer) { clearTimeout(this.idleTimer); this.idleTimer = null; }
        this.viewer?.stop();
        this.viewer = this.makeViewer();
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

// A plain-English "what the turn did" line (R7). Leads with the assistant's
// actions (tool calls) or reply — never the raw user message, which for a
// leak turn would echo the secret into the always-visible feed.
function buildSummary(
  parsed: ParsedRequest | null,
  responseText?: string,
  actions?: ToolAction[],
): string {
  if (actions && actions.length > 0) return summarizeActions(actions);
  if (responseText) return firstLine(responseText, 100);
  if (!parsed) return "unparsed exchange (raw view available)";
  const lastUser = [...parsed.messages].reverse().find((m) => m.role === "user");
  return lastUser ? firstLine(lastUser.content, 100) : `${parsed.messages.length} messages`;
}

// Map coding-agent tools to verbs and group repeats: "read 3 files, ran `npm test`".
function summarizeActions(actions: ToolAction[]): string {
  const verb = (t: string): string => {
    const l = t.toLowerCase();
    if (l.includes("bash") || l.includes("shell") || l.includes("exec")) return "ran";
    if (l === "read" || l.includes("readfile") || l.includes("cat")) return "read";
    if (l.includes("write") || l.includes("edit") || l.includes("replace")) return "edited";
    if (l.includes("grep") || l.includes("glob") || l.includes("search") || l.includes("find")) return "searched";
    if (l.includes("web") || l.includes("fetch")) return "fetched";
    return t;
  };
  const parts: string[] = [];
  const files: string[] = [];
  for (const a of actions) {
    const v = verb(a.tool);
    if (v === "ran" && a.detail) parts.push(`ran \`${firstLine(a.detail, 40)}\``);
    else if (v === "read" && a.detail) files.push(a.detail.split("/").pop() ?? a.detail);
    else if (a.detail) parts.push(`${v} \`${a.detail.split("/").pop() ?? a.detail}\``);
    else parts.push(v);
  }
  if (files.length === 1) parts.unshift(`read ${files[0]}`);
  else if (files.length > 1) parts.unshift(`read ${files.length} files`);
  return parts.slice(0, 3).join(", ") || `${actions.length} tool calls`;
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
