// The daemon (design §6.7): owns the proxy listener, store writer, scanner
// host, session resolver, alert engine, control socket, and sweeper. The
// only writer; CLI and viewer read the store directly.
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { Server, Socket } from "node:net";
import { AlertEngine, type AlertEvent } from "../core/alert/engine";
import { loadConfig, saveConfig, loadOrCreateInstallKey, type BeagleConfig } from "../core/config/config";
import type { Message } from "../core/call";
import { ProxyServer, type CapturedCall, type ScanContext } from "../core/proxy/server";
import { RunRegistry, type RunRegistration } from "../core/proxy/registry";
import { SessionResolver, type Resolution } from "../core/session/resolver";
import { Store } from "../core/store/store";
import { ScanHost } from "../adapters/scan-host";
import type { Finding } from "../core/scanner/engine";
import { applyCaptureRedaction, redactValues, redactValuesInText } from "../transform/redact";
import { scrubAuthHeaders } from "../core/normalize/normalize";
import { Notifier } from "../notifier/notifier";
import { detectFormat, extractActions, parseRequest, parseResponse, type Format, type ParsedRequest, type ToolAction } from "../parsers/parsers";
import { startControlServer, type ControlRequest, type ControlResponse } from "./control";
import { ViewerServer } from "../viewer/server";
import { OtlpReceiver } from "../core/otlp/receiver";
import { BEAGLE_VERSION } from "../core/version";
import type { OtelCall } from "../parsers/otlp-map";
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
  /** Override the pending-entry TTL (default 10 min) — tests only. */
  pendingTtlMs?: number;
  /** Override the sweep cadence (default 15 min) — tests only. */
  sweepIntervalMs?: number;
}

interface PendingCall {
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

// Skip markers outlive pending entries by design: a marker is ~40 bytes (id +
// timestamp) where a pending entry holds a parsed body, so the memory argument
// for a short TTL doesn't apply — and expiring one early would let a paused-
// time call be captured after all if its response outlived the marker.
const SKIPPED_TTL_MS = 24 * 3600_000;

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
  private pending = new Map<string, PendingCall>();
  // Calls whose request was skipped (paused / excluded agent) — the capture
  // must drop these even if the daemon was resumed or the agent un-excluded
  // before the response landed. Swept alongside `pending`.
  private skipped = new Map<string, number>();
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
      onCall: (call) => void d.captureCall(call).catch(() => {}),
      captureBufferCap: 8 << 20,
    });
    await d.proxy.listen(0);
    d.proxyPort = d.proxy.port;
    // A per-daemon-session token, minted into the agent's OTEL headers — never
    // the install key (which must not leave the machine).
    d.otlpToken = randomBytes(24).toString("hex");
    d.otlp = new OtlpReceiver({
      token: d.otlpToken,
      onCalls: (exs) => d.ingestOtel(exs),
    });
    d.otlpPort = await d.otlp.listen(0);
    d.control = await startControlServer(d.socketPath, (req, sock) => d.handleControl(req, sock));
    d.sweep();
    d.sweeper = setInterval(() => d.sweep(), opts.sweepIntervalMs ?? SWEEP_INTERVAL_MS);
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
    if (this.paused || this.config.excludedAgents.includes(ctx.agent ?? "")) {
      // The skip decision is per-call, made here: these bytes are never
      // scanned, so the call must not be captured even if the state flips
      // back mid-flight (§4 — never store an unscanned body as verified).
      this.skipped.set(ctx.callId, Date.now());
      return;
    }
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
    const entry: PendingCall = {
      resolution, parsed, format, scanState: "ok", findings: [], scanDone,
      createdTs: Date.now(),
    };
    this.pending.set(ctx.callId, entry);

    const result = await this.scanHost.scan(bytes, { authValue: ctx.authValue });
    entry.findings = result.findings;
    if (result.state === "incomplete") {
      entry.scanState = "incomplete";
      this.store.updateCallScanState(ctx.callId, "incomplete"); // no-op if not yet inserted
    }
    resolveScan();
    this.alertEngine.process(
      {
        id: ctx.callId,
        sessionId: resolution.sessionId,
        agent: ctx.agent,
        provider: ctx.provider,
        model: parsed?.model,
      },
      result.findings,
    );
  }

  private async captureCall(call: CapturedCall): Promise<void> {
    if (this.skipped.delete(call.id)) return; // request-time skip is final
    const stash = this.pending.get(call.id);
    // redact-on-capture (R11): await the scan verdict and substitute the raw
    // secret BEFORE the first write, so no raw value ever lands in the WAL.
    if (this.config.redactOnCapture && stash) {
      await stash.scanDone;
    }
    this.pending.delete(call.id);
    if (this.paused || this.config.excludedAgents.includes(call.agent ?? "")) return;
    const format = stash?.format ?? detectFormat(call.endpoint);
    const parsed = stash?.parsed ?? null;
    const respBytes = call.response.bodyBytes ?? call.response.sseRaw;
    const respParsed = format !== "unknown" && respBytes ? parseResponse(format, respBytes) : null;
    const respActions = format !== "unknown" && respBytes ? extractActions(format, respBytes) : [];
    const resolution =
      stash?.resolution ??
      this.resolver.resolve({
        agent: call.agent, provider: call.provider, runId: call.runId,
        ts: call.meta.tsRequest, messages: parsed?.messages, systemPrompt: parsed?.system,
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

    // A missing stash means these bytes were never scanned (request skipped
    // while paused, pending entry TTL-swept mid-flight, scan pipeline died) —
    // never claim "ok" for a body no scan verified (§4).
    const scanState: "ok" | "incomplete" = stash?.scanState ?? "incomplete";
    // redact-on-capture (§4/R11): see applyCaptureRedaction for the policy.
    // Run it whenever scanState is unverified even if the stash is gone, so a
    // never-scanned body is held out, not stored raw-and-hoped.
    const redaction = this.config.redactOnCapture
      ? applyCaptureRedaction({
          incomplete: scanState === "incomplete",
          requestBytes: call.request.bodyBytes,
          requestFindings: stash?.findings ?? [],
          responseBody: call.response.bodyBytes ?? null,
        })
      : null;
    const requestBody = redaction ? redaction.requestBody : call.request.bodyBytes;
    const responseBody = redaction ? redaction.responseBody : (call.response.bodyBytes ?? null);
    let sseRaw: Uint8Array | null = call.response.sseRaw ?? null;
    let searchText = buildSearchText(parsed, respParsed?.text, call);
    if (redaction?.heldOut) {
      sseRaw = null; // the raw stream could hold the unverified value
      searchText = "";
    } else if (redaction?.redacted) {
      // A content-encoded raw stream is compressed bytes — a literal scrub
      // can't find the secret in it, so keeping it would silently retain an
      // echoed value. Drop it; the decoded (scrubbed) body remains.
      const contentEncoded = call.response.headers?.some(
        ([n, v]) =>
          n.toLowerCase() === "content-encoding" &&
          v.trim() !== "" &&
          v.trim().toLowerCase() !== "identity",
      );
      sseRaw = contentEncoded ? null : redactValues(sseRaw, redaction.values);
      searchText =
        new TextDecoder().decode(requestBody) +
        "\n" +
        (responseBody ? new TextDecoder().decode(responseBody) : "");
    }
    const summary = redaction?.heldOut
      ? "[REDACTION INCOMPLETE: content withheld]"
      : buildSummary(parsed, respParsed?.text, respActions, redaction?.values ?? []);

    this.store.insertCall({
      id: call.id,
      sessionId: resolution.sessionId,
      runId: call.runId,
      source: call.source,
      agent: call.agent,
      provider: call.provider,
      model: parsed?.model ?? respParsed?.model,
      endpoint: call.endpoint,
      tsRequest: call.meta.tsRequest,
      tsResponse: call.meta.tsResponse,
      status: call.response.status,
      tokensIn: respParsed?.tokensIn,
      tokensOut: respParsed?.tokensOut,
      bytesReq: call.request.bodyBytes.byteLength,
      bytesResp: call.response.bodyBytes?.byteLength,
      summary,
      scanState,
      captureState: call.meta.captureState,
      sessionTier: resolution.tier,
      redacted: redaction?.redacted ?? false,
      requestBody,
      requestHeaders: call.request.headers ?? null,
      responseBody,
      responseHeaders: call.response.headers
        ? scrubAuthHeaders(call.response.headers, undefined, call.provider)
        : null,
      sseRaw,
      searchText,
    });
    this.viewer?.broadcast("call", {
      id: call.id,
      sessionId: resolution.sessionId,
      agent: call.agent,
      provider: call.provider,
      model: parsed?.model ?? respParsed?.model,
      tsRequest: call.meta.tsRequest,
      status: call.response.status,
      tokensIn: respParsed?.tokensIn,
      tokensOut: respParsed?.tokensOut,
      bytesReq: call.request.bodyBytes.byteLength,
      summary,
      scanState,
      captureState: call.meta.captureState,
      sessionTier: resolution.tier,
      source: call.source,
      hasLeak: false, // the alert event corrects this if a leak lands
    });
  }

  // Mode B ingest (design §6.2): OTel-reported calls run the identical
  // scanner/session/alert/store path — source='otel' is the only difference,
  // surfaced as the agent-reported badge (R7).
  private async ingestOtel(calls: OtelCall[]): Promise<void> {
    this.lastActivityTs = Date.now();
    for (const call of calls) {
      if (this.paused || this.config.excludedAgents.includes(call.agent ?? "")) continue;
      const resolution = this.resolver.resolve({
        agent: call.agent,
        provider: call.provider,
        runId: call.runId,
        ts: call.meta.tsRequest,
        convId: call.convId,
        messages: call.request.messages,
      });
      const scanResult = await this.scanHost.scan(call.request.bodyBytes, {});
      // Keep session chaining state current, same as the wire path — so a
      // Mode B session without an explicit id still chains across turns.
      if (call.request.messages?.length || call.response.text) {
        this.resolver.recordResponse({
          sessionId: resolution.sessionId,
          messages: [
            ...(call.request.messages ?? []),
            ...(call.response.text ? [{ role: "assistant", content: call.response.text }] : []),
          ],
          responseId: call.convId,
        });
      }
      // redact-on-capture (§4/R11): Mode B rows must not be a redaction hole
      // just because they arrived via the receiver. One asymmetry with the
      // wire path: a wire request carries the full history, so an echoed
      // secret always co-occurs with a scanned request-side copy — but Mode B
      // batch-splitting can deliver a response-only call. Scan the response
      // too, for redaction only: inbound content never alerts (the outbound
      // leak fired with the batch that carried the prompt).
      const respScan =
        this.config.redactOnCapture && call.response.bodyBytes?.byteLength
          ? await this.scanHost.scan(call.response.bodyBytes, {})
          : null;
      const redaction = this.config.redactOnCapture
        ? applyCaptureRedaction({
            incomplete: scanResult.state === "incomplete" || respScan?.state === "incomplete",
            requestBytes: call.request.bodyBytes,
            requestFindings: scanResult.findings,
            responseBody: call.response.bodyBytes ?? null,
            responseFindings: respScan?.findings,
          })
        : null;
      let searchText =
        (call.request.messages?.map((m) => m.content).join("\n") ?? "") + "\n" + (call.response.text ?? "");
      // searchText and summary both derive from the display messages (already
      // flattened plain text, not raw JSON), so both scrub by value — not by
      // the scanned-byte offsets, which don't index this text.
      if (redaction) searchText = redaction.heldOut ? "" : redactValuesInText(searchText, redaction.values);
      const summary = redaction?.heldOut
        ? "[REDACTION INCOMPLETE: content withheld]"
        : buildSummary(
            { model: call.model, messages: call.request.messages ?? [] } as ParsedRequest,
            call.response.text,
            undefined,
            redaction?.values ?? [],
          );
      const scanState = redaction?.heldOut ? "incomplete" : scanResult.state;
      this.store.insertCall({
        id: call.id,
        sessionId: resolution.sessionId,
        runId: call.runId,
        source: "otel",
        agent: call.agent,
        provider: call.provider,
        model: call.model,
        endpoint: call.endpoint,
        tsRequest: call.meta.tsRequest,
        tsResponse: call.meta.tsResponse,
        status: 200,
        tokensIn: call.meta.tokensIn,
        tokensOut: call.meta.tokensOut,
        bytesReq: call.request.bodyBytes.byteLength,
        bytesResp: call.response.bodyBytes?.byteLength,
        summary,
        scanState,
        captureState: "ok",
        sessionTier: resolution.tier,
        redacted: redaction?.redacted ?? false,
        requestBody: redaction ? redaction.requestBody : call.request.bodyBytes,
        requestHeaders: null,
        responseBody: redaction ? redaction.responseBody : (call.response.bodyBytes ?? null),
        responseHeaders: null,
        sseRaw: null,
        searchText,
      });
      this.alertEngine.process(
        {
          id: call.id,
          sessionId: resolution.sessionId,
          agent: call.agent,
          provider: call.provider,
          model: call.model,
        },
        scanResult.findings,
      );
      this.viewer?.broadcast("call", {
        id: call.id,
        sessionId: resolution.sessionId,
        agent: call.agent,
        provider: call.provider,
        model: call.model,
        tsRequest: call.meta.tsRequest,
        status: 200,
        tokensIn: call.meta.tokensIn,
        tokensOut: call.meta.tokensOut,
        bytesReq: call.request.bodyBytes.byteLength,
        summary,
        scanState,
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
    const cutoff = Date.now() - (this.opts.pendingTtlMs ?? PENDING_TTL_MS);
    for (const [id, entry] of this.pending) {
      if (entry.createdTs < cutoff) this.pending.delete(id);
    }
    const skipCutoff = Date.now() - SKIPPED_TTL_MS;
    for (const [id, ts] of this.skipped) {
      if (ts < skipCutoff) this.skipped.delete(id);
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
        // Report the running daemon's version so an upgraded CLI can detect a
        // stale daemon (old binary still serving after an upgrade) and warn.
        return { ok: true, data: { pid: process.pid, proxyPort: this.proxyPort, version: BEAGLE_VERSION } };
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
            calls: this.store.countCalls(),
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
  secretValues?: Array<{ value: string; type: string }>,
): string {
  // Redact-on-capture (R11): the summary derives from the same raw messages
  // the body redaction already scrubbed, so it must scrub too. Before
  // truncation — a secret cut by the 100-char cap no longer literal-matches,
  // and a post-hoc scrub of the finished line would leak its prefix.
  if (secretValues && secretValues.length > 0) {
    const scrub = (s: string) => redactValuesInText(s, secretValues);
    if (responseText !== undefined) responseText = scrub(responseText);
    actions = actions?.map((a) => (a.detail ? { ...a, detail: scrub(a.detail) } : a));
    if (parsed) parsed = { ...parsed, messages: parsed.messages.map((m) => ({ ...m, content: scrub(m.content) })) };
  }
  if (actions && actions.length > 0) return summarizeActions(actions);
  if (responseText) return firstLine(responseText, 100);
  if (!parsed) return "unparsed call (raw view available)";
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
  call: CapturedCall,
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
    dec.decode(call.request.bodyBytes) +
    "\n" +
    (call.response.bodyBytes ? dec.decode(call.response.bodyBytes) : "")
  );
}
