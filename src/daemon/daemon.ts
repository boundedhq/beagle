// The daemon (design §6.7): owns the proxy listener, store writer, scanner
// host, session resolver, alert engine, control socket, and sweeper. The
// only writer; CLI and viewer read the store directly.
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { Server, Socket } from "node:net";
import { AlertEngine, type AlertEvent, type CallMeta } from "../core/alert/engine";
import { loadConfig, saveConfig, loadOrCreateInstallKey, type BeagleConfig } from "../core/config/config";
import type { Message } from "../core/call";
import { ProxyServer, type CapturedCall, type ScanContext } from "../core/proxy/server";
import { RunRegistry, type RunRegistration } from "../core/proxy/registry";
import { SessionResolver, type Resolution } from "../core/session/resolver";
import { Store } from "../core/store/store";
import { ScanHost, dropIdentityFieldNoise } from "../adapters/scan-host";
import type { Finding } from "../core/scanner/engine";
import { applyCaptureRedaction, clampRedacted, derivedScanText, derivedSplitAt, redactDerivedParts, redactRawStream, redactValuesInText, secretKeys } from "../transform/redact";
import { scrubAuthHeaders } from "../core/normalize/normalize";
import { Notifier, type AlertMessage } from "../notifier/notifier";
import { buildAlertMessage } from "../notifier/alert-copy";
import { detectFormat, extractActions, parseRequest, parseResponse, DISPLAY_RESULT_CAP, type DisplayMessage, type Format, type ParsedRequest, type ToolAction } from "../parsers/parsers";
import { startControlServer, type ControlRequest, type ControlResponse } from "./control";
import { ViewerServer } from "../viewer/server";
import { OtlpReceiver } from "../core/otlp/receiver";
import { BEAGLE_VERSION } from "../core/version";
import type { OtelCall } from "../parsers/otlp-map";
import { CodexRolloutWatcher } from "../adapters/codex-rollout-tailer";
// Embedded at build time so the compiled binary needs no repo checkout.
// (bun-types types *.json as a parsed object; with { type: "text" } the
// runtime value is the raw string — required for the sha256 pin to verify.)
import embeddedRulesRaw from "../../rules/beagle-rules.json" with { type: "text" };
import embeddedRulesPin from "../../rules/beagle-rules.sha256" with { type: "text" };
const embeddedRules = embeddedRulesRaw as unknown as string;

// What every alert surface (dashboard banner, OS notification, terminal, test
// sink) receives: the core's structured facts plus the rendered human copy.
export type EmittedAlert = AlertEvent & AlertMessage;

export interface DaemonOptions {
  stateDir: string;
  rulesJson?: string; // override for tests; defaults to the embedded corpus
  rulesPin?: string;
  scanDeadlineMs?: number;
  alertSinkForTest?: (a: EmittedAlert) => void;
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
  /** Point the Codex rollout watcher at a fixed sessions root (default: resolve
   *  from CODEX_HOME / ~/.codex) — tests only. */
  codexRolloutRootForTest?: string;
}

// One derived-text redaction outcome (Daemon.redactDerived). `values` are in
// the DERIVED form, for scrubbing text built from these parts that is not one
// of them — the summary's quoted ask, a truncated transcript copy.
interface DerivedRedaction {
  /** The request-derived parts, redacted. */
  outbound: string[];
  /** The response-derived parts, redacted — the reply then one per action.
   *  Handed back for the summary, the only surface that quotes the answer.
   *  Scrubbing it by `values` instead is NOT equivalent: redactValuesInText
   *  floors at 8 chars and connection-string reports a password on its own, so
   *  a four-char one survives the scrub and only the spans remove it. */
  inbound: string[];
  values: Array<{ value: string; type: string }>;
  /** Outbound-half findings whose value also sits VERBATIM in the request body,
   *  with `start`/`end` remapped to that body occurrence — a real highlight. */
  anchoredFindings: Finding[];
  /** Outbound-half findings the body does not contain in that form. Span-less:
   *  their offsets index the derived text, which is not what the viewer slices. */
  leakFindings: Finding[];
  /** Scan didn't verify the derived text: the caller withholds it. */
  incomplete: boolean;
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
  // Reads Codex rollout files to recover the assistant answer its OTel export
  // omits, stitching it onto the turn row. Driven by ingestOtel (Codex activity).
  private codexRollout: CodexRolloutWatcher | null = null;
  otlpPort = 0;
  private otlpToken = "";
  private pending = new Map<string, PendingCall>();
  // Detached pipeline work (scan / capture / Mode B ingest) still holding a
  // store write. stop() drains this before closing the store — closing under
  // a mid-flight write loses the row and throws "Database has closed".
  private inflight = new Set<Promise<void>>();
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
      scan: (bytes, ctx) => d.track(d.scanPipeline(bytes, ctx)),
      onCall: (call) => void d.track(d.captureCall(call)),
      captureBufferCap: 8 << 20,
    });
    // A per-daemon-session token, minted into the agent's OTEL headers — never
    // the install key (which must not leave the machine).
    d.otlpToken = randomBytes(24).toString("hex");
    d.otlp = new OtlpReceiver({
      token: d.otlpToken,
      onCalls: (exs) => void d.track(d.ingestOtel(exs)),
    });
    // The tailer's answers re-enter the same ingest path (tracked for the drain).
    d.codexRollout = new CodexRolloutWatcher({
      emit: (calls) => void d.track(d.ingestOtel(calls)),
      sessionsRoot: opts.codexRolloutRootForTest,
    });
    try {
      // Any bind can fail (EADDRINUSE, etc.). Close everything already open
      // so a failed start doesn't strand the store handle, scanner worker, or
      // an earlier listener — the process may retry or exit cleanly.
      await d.proxy.listen(0);
      d.proxyPort = d.proxy.port;
      d.otlpPort = await d.otlp.listen(0);
      d.control = await startControlServer(d.socketPath, (req, sock) => d.handleControl(req, sock));
    } catch (e) {
      d.proxy.close();
      d.otlp.close();
      d.scanHost.close();
      d.store.close();
      throw e;
    }
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

  // Concurrent callers must await the SAME drain, not race it: `stop()` is
  // bound to both SIGINT and SIGTERM (cli/main.ts) and is also reached from
  // idle-exit and the shutdown command, each doing `stop().then(process.exit)`.
  // A second caller returning early — as it would on the isRunning guard alone
  // — exits the process out from under the first caller's in-flight write,
  // which is the loss this drain exists to prevent. A double Ctrl-C is enough.
  stop(): Promise<void> {
    return (this.stopping ??= this.doStop());
  }
  private stopping: Promise<void> | null = null;

  private async doStop(): Promise<void> {
    if (!this.isRunning) return;
    this.isRunning = false;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (this.sweeper) clearInterval(this.sweeper);
    this.viewer?.stop();
    this.otlp?.close();
    this.codexRollout?.stop(); // stop the pollers before draining in-flight ingests
    this.proxy.close();
    this.control.close();
    // Listeners are closed (no new work starts — the pipeline entry points
    // also check isRunning); drain what's already in flight before closing
    // the scanner and store it writes to.
    while (this.inflight.size > 0) await Promise.all([...this.inflight]);
    this.scanHost.close();
    this.store.close();
    rmSync(join(this.opts.stateDir, "daemon.json"), { force: true });
    rmSync(this.socketPath, { force: true });
  }

  // ---- pipeline ----

  /** Register detached pipeline work for the stop() drain. Never rejects —
   *  a pipeline failure must not surface as an unhandled rejection. */
  private track(work: Promise<unknown>): Promise<void> {
    const settled = work.then(
      () => void this.inflight.delete(settled),
      () => void this.inflight.delete(settled),
    );
    this.inflight.add(settled);
    return settled;
  }

  private async scanPipeline(bytes: Uint8Array, ctx: ScanContext): Promise<void> {
    if (!this.isRunning) return;
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
      // The resolver uses systemPrompt only for the fuzzy compaction-link.
      // A stateless one-shot (title-gen: identical system + opening message in
      // EVERY conversation) must not fuzzy-link, or each one glues itself onto
      // the oldest look-alike session — withhold the fuzzy signal.
      systemPrompt: parsed?.oneShot ? undefined : parsed?.system,
    });
    let resolveScan!: () => void;
    const scanDone = new Promise<void>((r) => (resolveScan = r));
    const entry: PendingCall = {
      resolution, parsed, format, scanState: "ok", findings: [], scanDone,
      createdTs: Date.now(),
    };
    this.pending.set(ctx.callId, entry);

    const result = await this.scanHost.scan(bytes, { authValue: ctx.authValue });
    // Protocol identity fields (prompt_cache_key & co) are expected entropy,
    // not credentials — drop the generic-detector noise before it reaches
    // redaction or the alert engine.
    result.findings = dropIdentityFieldNoise(bytes, result.findings);
    try {
      entry.findings = result.findings;
      if (result.state === "incomplete") {
        entry.scanState = "incomplete";
        this.store.updateCallScanState(ctx.callId, "incomplete"); // no-op if not yet inserted
      }
    } finally {
      // captureCall awaits scanDone with no timeout, so this must resolve on
      // every path: a store error above would otherwise wedge that capture
      // forever — and now that stop() drains in-flight work, wedge shutdown
      // with it. Resolving early is safe; findings/scanState are already set.
      resolveScan();
    }
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
    // Tell open dashboards a leak landed — WHATEVER the tier. The loud alert
    // frame fires only for fresh structured events, so without this a
    // possible-tier finding updates nothing and the header/feed sit stale
    // until a manual reload (the sessions tab, fetching fresh on every click,
    // would disagree with both).
    if (result.findings.length > 0) this.viewer?.broadcast("leak", { callId: ctx.callId });
  }

  // Scan a call's DERIVED display strings on their own and offset-redact them
  // (design §4/R11). The body scan can't stand in for this: the scanner reads
  // raw bytes while display_messages, the summary and the Mode B half of
  // searchText render a TRANSFORMED view, and where the transform changes more
  // than escaping a value-scrub keyed off the raw match structurally cannot
  // reach it — see redactDerivedParts. Runs on EVERY call, not only ones the
  // body scan flagged: a secret split across two adjacent content blocks is
  // manufactured by the join, so the body scan finding nothing proves nothing.
  //
  // `outbound` is the request-derived text and `inbound` the response-derived
  // text, in that order and never interleaved, because only the outbound half
  // alerts — a secret in the model's answer came FROM the provider, the same
  // asymmetry the response-body scan holds. A finding straddling the boundary
  // is counted outbound: fail-safe on an ambiguous span.
  //
  // `bodyValues` are the secrets the body scan already reported for this call,
  // and a derived finding matching one is dropped from the alert set: a secret
  // found in the bytes AND in their rendering is ONE thing sent once.
  // leak_events.occurrences answers "how many times did this go out", so
  // counting a call twice for owning two views of one value would inflate the
  // number the user reads. Matched by secretKeys, not by the scanner's
  // fingerprint — an escaped body and its decoded rendering hash differently.
  // What that can NOT relate is a body match carrying JSON structure the
  // display dropped (a key split across two messages): the two values are
  // genuinely different strings, so such a call alerts twice. Over-alerting on
  // a leak that already alerts — see the spanning-PEM case in
  // tests/otlp-daemon.test.ts.
  //
  // `echoAt` is the offset in the joined text where outbound parts that merely
  // RE-RENDER an earlier part begin (a tool result's `detail` restates its own
  // call's arguments). Such a part is redacted like any other — that is the
  // point of listing it — but a finding in it is dropped from the alert set
  // when an earlier part already reported the same value, by the same
  // one-value-one-occurrence rule as `bodyValues` above. Only findings AT or
  // after it dedup this way: an echo can decode one escaping level further than
  // the part it echoes, so a secret readable only there is genuinely reachable
  // only there, and still alerts.
  //
  // `bodyText` is the decoded request body, used to RE-ANCHOR a derived finding
  // whose value happens to sit verbatim in those bytes. Measured on real
  // captured traffic, that is the common case rather than the exception: the
  // reason the body scan missed such a value is usually that JSON escaping
  // pushed the rule's context out of reach (generic-api-key allows
  // `["':=\s]{1,5}` between keyword and value — a body's `\": \"` is six chars
  // and misses where the unescaped `": "` matches), not that the display
  // manufactured a string the body never held. Those findings earn a body
  // highlight; only a genuinely manufactured one stays span-less.
  //
  // WHERE THIS TAKES EFFECT, stated plainly because the reach is narrower than
  // it looks: any derived finding at all produces a redacted part, so with
  // redact-on-capture ON — the default — the row reads `redacted`, and
  // extractLeaks highlights placeholders and ignores spans entirely
  // (viewer/detail.ts). The span is consulted ONLY with redact-on-capture off,
  // where the stored body is the raw bytes these offsets were computed against.
  //
  // That gate is load-bearing, not an oversight, and the obvious "fix" — having
  // extractLeaks union span-recovered values into the placeholder branch —
  // would be a bug: on a redacted row the body has been rewritten underneath
  // these offsets, so slicing by them returns a fragment of whatever now sits
  // there. A span is only ever used against bytes it still fits.
  //
  // HIGHLIGHT ONLY — never feed these offsets to redactBody. They come from a
  // text SEARCH, not from the regex's own `d`-flag indices, and the engine
  // holds the opposite invariant for anything that splices: a search returns
  // the first occurrence of the value, which for a repeated value need not be
  // the occurrence a rule matched (mongodb://root:root@host reported the
  // username's span and shipped the password — the bug that put the `d` flag
  // in compileRules). Recovering the VALUE is insensitive to which occurrence
  // wins, because every occurrence is the same string; splicing is not.
  // applyCaptureRedaction is deliberately still handed the body scan's findings
  // alone. If a later change masks derived-only values in the body too, it must
  // carry its own exact offsets rather than reuse these.
  private async redactDerived(
    outbound: string[],
    inbound: string[],
    bodyValues: Array<{ value: string; type: string }>,
    bodyText: string,
    echoAt = Infinity,
  ): Promise<DerivedRedaction> {
    const clean: DerivedRedaction = {
      outbound, inbound, values: [], anchoredFindings: [], leakFindings: [], incomplete: false,
    };
    const parts = [...outbound, ...inbound];
    const text = derivedScanText(parts);
    if (text.trim() === "") return clean;
    const bytes = new TextEncoder().encode(text);
    const result = await this.scanHost.scan(bytes, {});
    // Unverified derived text is withheld by the caller, never stored and
    // hoped over — the same rule the body halves follow (§4).
    if (result.state === "incomplete") return { ...clean, incomplete: true };
    const findings = dropIdentityFieldNoise(bytes, result.findings);
    if (findings.length === 0) return clean;
    const red = redactDerivedParts(parts, findings);
    const outboundEnd = derivedSplitAt(outbound);
    const known = new Set(bodyValues.flatMap((v) => secretKeys(v.value)));
    // Keyed ONCE per outbound finding, because every check below wants the same
    // keys and secretKeys JSON-parses: the shape this module budgets for is a
    // conversation saturating every rule's finding cap (see redactDerivedParts),
    // where keying twice is thousands of redundant parses on the single writer.
    // Inbound findings are dropped first — they can never alert, so they are
    // never keyed at all. The matched value rides along for the same reason:
    // the re-anchor below needs the raw slice, and `keys` are the normalized
    // forms, not it.
    const keyed = findings
      .filter((f) => f.start < outboundEnd)
      .map((f) => {
        const value = text.slice(f.start, f.end);
        return { f, value, keys: secretKeys(value) };
      });
    // What the pre-echo parts report, so the echo half can't re-report it.
    // Built BEFORE the `known` test, not after: when a body value and its
    // rendering are two escaping levels apart, the pre-echo finding is dropped
    // as already-known while the echo's further-decoded form is NOT in `known`
    // — so it is exactly the dropped finding that has to suppress it.
    const reported = new Set(
      echoAt === Infinity ? [] : keyed.filter((k) => k.f.start < echoAt).flatMap((k) => k.keys),
    );
    const anchoredFindings: Finding[] = [];
    const leakFindings: Finding[] = [];
    // Memoised per VALUE, on the same budget argument as `keyed` above: the way
    // a conversation reaches the finding cap is one secret recurring through a
    // long history, so the cap is hit with a handful of distinct values and
    // thousands of findings. A miss scans the whole body, so searching per
    // finding costs ~1s of the single writer's time on a saturated 1.5 MB
    // request where searching per distinct value costs ~5ms (measured).
    // Residual: values that are all distinct AND all derived-only degrade back
    // to a search each, which no memo can help — that needs a prompt built to
    // defeat the body rule thousands of times over, and it stalls capture
    // rather than misreporting anything.
    const anchors = new Map<string, number>();
    for (const { f, value, keys } of keyed) {
      if (keys.some((k) => known.has(k))) continue; // the body scan already reported it
      if (f.start >= echoAt && keys.some((k) => reported.has(k))) continue; // an earlier part did
      // indexOf, not a re-scan: the question is only "do these exact bytes
      // appear in the body", and the first occurrence is enough — extractLeaks
      // de-dups by value and needs one correct offset to recover it.
      let at = anchors.get(value);
      if (at === undefined) {
        at = value === "" ? -1 : bodyText.indexOf(value);
        anchors.set(value, at);
      }
      if (at >= 0) anchoredFindings.push({ ...f, start: at, end: at + value.length });
      else leakFindings.push(f);
    }
    return {
      outbound: red.parts.slice(0, outbound.length),
      inbound: red.parts.slice(outbound.length),
      values: red.values,
      anchoredFindings,
      leakFindings,
      incomplete: false,
    };
  }

  // Alert a call's derived-only findings — the leaks the body scan structurally
  // could not see (the display joined two content blocks into a key that is not
  // in the scanned bytes, or JSON escaping pushed the rule's context out of
  // reach). Fires at capture rather than pre-forward: late, but the alternative
  // was silence. Only findings the body scan didn't already report get here
  // (redactDerived drops the rest), so a secret visible in both views stays one
  // event with one occurrence.
  //
  // Two passes because alertEngine.process takes the span flag per CALL, not per
  // finding: re-anchored values carry real body offsets and highlight, the rest
  // are span-less because their offsets index the derived text. Returns how many
  // were reported, for the caller's leak frame.
  //
  // Each pass is attempted even if the other throws — process() opens a store
  // transaction per finding, so it can. Splitting one call into two would
  // otherwise mean a failure in the first loses EVERY finding in the second,
  // and the span-less half is the higher-value one: a secret the body scan
  // structurally cannot see, which this pass is the only chance to report. One
  // pass failing must cost only that pass. The error still escapes afterwards,
  // to the same pipeline tracker that caught it before.
  private alertDerived(meta: CallMeta, derived: DerivedRedaction): number {
    let failed = false;
    let failure: unknown;
    const pass = (findings: Finding[], bodySpans: boolean) => {
      if (findings.length === 0) return;
      try {
        this.alertEngine.process(meta, findings, bodySpans);
      } catch (e) {
        if (!failed) [failed, failure] = [true, e];
      }
    };
    // Anchored FIRST, and the order is load-bearing: leak_occurrences is keyed
    // (event_id, exchange_id) and written INSERT OR IGNORE, so whichever pass
    // reaches a pair first decides whether it stores the span or NULL. Two
    // findings can share a fingerprint while their raw slices differ — the
    // fingerprint decodes escapes and strips whitespace, indexOf matches the
    // raw slice — and there the real span has to win over the span-less one.
    pass(derived.anchoredFindings, true);
    pass(derived.leakFindings, false);
    if (failed) throw failure;
    return derived.anchoredFindings.length + derived.leakFindings.length;
  }

  private async captureCall(call: CapturedCall): Promise<void> {
    if (!this.isRunning) return; // late delivery during shutdown — store may be closing
    if (this.skipped.delete(call.id)) return; // request-time skip is final
    const stash = this.pending.get(call.id);
    // Await the scan verdict BEFORE the first write, unconditionally: with
    // redact-on-capture it gates the body substitution (R11); without it the
    // summary's findings-based scrub still needs final findings — a response
    // that beats the scan would otherwise store a raw secret in the
    // permanently-visible feed line. Capture is off the relay path, so the
    // wait costs the agent nothing; the scan itself is deadline-bounded.
    if (stash) {
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
        ts: call.meta.tsRequest, messages: parsed?.messages,
        // Same one-shot fuzzy suppression as the primary resolve site above.
        systemPrompt: parsed?.oneShot ? undefined : parsed?.system,
      });
    if (respParsed?.text || respParsed?.responseId) {
      const history: Message[] = [
        ...(parsed?.messages ?? []),
        ...(respParsed.text ? [{ role: "assistant", content: respParsed.text }] : []),
      ];
      this.resolver.recordResponse({
        sessionId: resolution.sessionId,
        messages: history.length > 0 ? history : undefined,
        // A cache-keyed conversation's identity IS the client's key (stored as
        // the session's conv_id at create). conv_id is a single column, so a
        // response id must not overwrite it — the next call looks up the KEY,
        // and a clobbered conv_id would fracture the conversation into one
        // session per turn. Chained clients (no key) record ids as before.
        responseId: parsed?.convId ? undefined : respParsed.responseId,
      });
    }

    // A missing stash means these bytes were never scanned (request skipped
    // while paused, pending entry TTL-swept mid-flight, scan pipeline died) —
    // never claim "ok" for a body no scan verified (§4).
    let scanState: "ok" | "incomplete" = stash?.scanState ?? "incomplete";
    // redact-on-capture (§4/R11): see applyCaptureRedaction for the policy.
    // Run it whenever scanState is unverified even if the stash is gone, so a
    // never-scanned body is held out, not stored raw-and-hoped.
    // Scan the response too, for REDACTION ONLY — never an alert. A "leak" is a
    // secret going OUT (the request); a secret in the model's response came FROM
    // the provider, so alerting on it would misattribute it to the agent. But it
    // still must not sit raw at rest, and the pre-forward pass only scanned the
    // request — so scan the response here purely to mask it. Deliberately
    // symmetric with the Mode B ingest path (inbound content never alerts).
    const respScan =
      this.config.redactOnCapture && call.response.bodyBytes?.byteLength
        ? await this.scanHost.scan(call.response.bodyBytes, {})
        : null;
    // Responses echo protocol identity fields (a /responses reply repeats
    // prompt_cache_key) — same noise filter before redaction masks them.
    if (respScan) respScan.findings = dropIdentityFieldNoise(call.response.bodyBytes!, respScan.findings);
    // The readable projection of this call, scanned on its own (see
    // redactDerived). The outbound half's CONTENTS are exactly what
    // buildSearchText joins; the inbound half is what the summary quotes back
    // from the response, whose parsers flatten and re-serialize just as freely.
    const contentParts = [parsed?.system ?? "", ...(parsed?.messages ?? []).map((m) => m.content)];
    // A result card labels itself with its ORIGINATING call's detail — the shell
    // command, the path — so `detail` is stored display text as surely as
    // `content` is, and it is its own part here for the same reason every other
    // one is: only offsets into the text a finding was actually scanned over can
    // redact it. A value scrub is not a substitute — the floor is 8 chars and
    // connection-string captures the bare password — which is why the transcript
    // used to render a command in cleartext beside a body and a sibling content
    // that both read [REDACTED:…]. Appended AFTER the contents, so every content
    // offset (and the search text built from them) is byte-identical to before.
    //
    // That append order also decides who loses MAX_FINDINGS_PER_RULE, and it is
    // always this half: the rule scans left to right, so the contents claim the
    // budget first and the details get what is left. 300 tool calls each
    // carrying a sub-floor password = 300 content matches + 200 detail matches,
    // and the last 100 details render in cleartext beside a fully-redacted
    // content, body and index, on a row that reads scanState "ok". Strictly
    // better than the value scrub this replaced (which floored out ALL 300),
    // but do not read "it is a part now" as "it is always covered". Interleaving
    // the runs would spread the starvation instead of concentrating it — at the
    // cost of the byte-identical content offsets the line above depends on.
    const detailParts = (parsed?.messages ?? []).map((m) => m.detail ?? "");
    const requestText = call.request.bodyBytes ? new TextDecoder().decode(call.request.bodyBytes) : "";
    const bodyValues = findingValues(requestText, stash?.findings);
    const derived = await this.redactDerived(
      [...contentParts, ...detailParts],
      // [reply, then detail+args PER ACTION in order]. `args` is a scanned part
      // and not merely value-scrubbed because it is not a verbatim slice of the
      // bytes: for anthropic-messages it is JSON.stringify(b.input), a
      // RE-SERIALIZATION, so `AKIA…` in the scanned body renders as
      // `AKIA…` here. No rule matched the escaped bytes, so no span covers it
      // and no matched value exists to scrub by — only scanning this string
      // reaches it. It is also the tool card's BODY (app.js draws
      // `args ?? detail`), so an unmasked args wins over a masked detail.
      [
        respParsed?.text ?? "",
        ...respActions.flatMap((a) => [a.detail ?? "", a.args ?? ""]),
      ],
      bodyValues,
      requestText,
      derivedSplitAt(contentParts), // details echo their own call's arguments
    );
    // The outbound half splits back into the two runs it was built from, so
    // each is indexed by its own arithmetic rather than one shared offset.
    const outContents = derived.outbound.slice(0, contentParts.length);
    const outDetails = derived.outbound.slice(contentParts.length);
    // Positional, mirroring what redactDerived was handed just above. Each half
    // now carries two runs and they are indexed DIFFERENTLY, so read the
    // construction rather than pattern-matching one offset onto the other:
    //   outbound = [system, ...content per message, ...detail per message]
    //              → content at i + 1, detail at i of the second run
    //   inbound  = [reply, ...detail+args INTERLEAVED per action]
    //              → detail at 1 + 2i, args at 2 + 2i
    // Outbound appends its runs (so content offsets stay byte-identical);
    // inbound interleaves its pair. Lifted out ONCE here for the two readers
    // that need the redacted messages — the summary below and the persisted
    // transcript after it — so the offsets are stated in one place. (Mode B
    // builds its outbound half with NO system part and no details, so there a
    // message is at i.)
    const redactedMessages = (parsed?.messages ?? []).map((m, i) => {
      const out: DisplayMessage = { ...m, content: outContents[i + 1]! };
      // Absent stays absent: assigning "" would add a field the parser never
      // set, and a result card renders its label on presence.
      if (out.detail !== undefined) out.detail = outDetails[i]!;
      return out;
    });
    // The summary QUOTES these strings into the feed line, so it is handed the
    // span-redacted copies rather than left to re-scrub the raw ones by value.
    // A value scrub cannot close this on its own: redactValuesInText floors at
    // 8 chars, and connection-string's secretGroup captures the password ALONE,
    // so `postgres://svc:pw12@db.internal/app` yields a FOUR-char value — under
    // the floor, spliced out of the body and the raw stream by span, and
    // printed in full on the one line the user cannot avoid reading. Of the
    // surfaces BUILT FROM THESE PARTS, the summary was the last one still
    // scrubbing by value.
    //
    // One boundary that leaves, so nobody reads this as a guarantee: spans only
    // cover what the scan REPORTED. The engine stops at MAX_FINDINGS_PER_RULE
    // and still returns "ok", so match 501 of a rule is invisible to every pass
    // — spans and value scrub alike.
    //
    // `detail` used to be a second one: not a part, so no span reached it, and
    // the value scrub standing in for one left everything under the 8-char
    // floor above raw in the stored transcript — the same four-char password,
    // in the field right beside the content it was masked out of. It is a part
    // now (see detailParts above), so a span reaches it wherever the scan
    // reported one — which makes it a SHARER of the cap boundary above rather
    // than an exception to it, and the half that hits it first. A NEW display
    // field would inherit the original hole verbatim: the spread carries it and
    // nothing scans it. Add it to the parts, not to a scrub.
    const summaryParsed = parsed && { ...parsed, messages: redactedMessages };
    // Pairs, so the detail for action i sits at 1 + 2i (its args follows).
    const summaryActions = respActions.map((a, i) => ({ ...a, detail: derived.inbound[1 + 2 * i]! }));
    // An unverified transcript is an unverified call: the row must not read
    // "ok" for text no scan checked. It rides the same `incomplete` flag as the
    // body halves, so the whole call is held out rather than only the derived
    // surfaces — that discards a body the pre-forward scan DID verify, and it
    // is the trade taken deliberately: one fail-safe rule beats a second,
    // subtly different withholding path. Reachable only if the transcript scan
    // breaches its deadline where the (larger) body scan did not.
    if (derived.incomplete) scanState = "incomplete";
    const redaction = this.config.redactOnCapture
      ? applyCaptureRedaction({
          incomplete: scanState === "incomplete" || respScan?.state === "incomplete",
          requestBytes: call.request.bodyBytes,
          requestFindings: stash?.findings ?? [],
          responseBody: call.response.bodyBytes ?? null,
          responseFindings: respScan?.findings,
          // What the DERIVED scan found and the body scan did not. Its offsets
          // index the transcript, so they can never splice these bytes (see
          // extraValues); the value is what carries over, and it carries over
          // because the derived text is a rendering of this body — the usual
          // reason a rule matches one and not the other is escaping, and the
          // value then sits here verbatim. Without this the row said
          // `redacted: true` over a request body still holding the key.
          extraValues: derived.values,
        })
      : null;
    const requestBody = redaction ? redaction.requestBody : call.request.bodyBytes;
    const responseBody = redaction ? redaction.responseBody : (call.response.bodyBytes ?? null);
    let sseRaw: Uint8Array | null = call.response.sseRaw ?? null;
    // Redacted parts when redact-on-capture is on, raw ones otherwise — the
    // same line the other stored surfaces hold (only the always-visible summary
    // scrubs regardless of the setting).
    // Contents only: a detail is a substring of its own call message's rendered
    // arguments, so indexing it would add nothing but a duplicate hit.
    let searchText = buildSearchText(parsed, call, redaction ? outContents : contentParts);
    if (redaction?.heldOut) {
      sseRaw = null; // the raw stream could hold the unverified value
      searchText = "";
    } else if (redaction?.redacted) {
      // The header says this stream is encoded, and we do not decode it here to
      // find out otherwise — so nothing below can be trusted to have read what
      // is in it, and keeping it could silently retain an echoed value. Drop it
      // on the header's word alone (fail-safe: the cost is a fidelity view, the
      // alternative is cleartext); the decoded, scrubbed body remains. Note the
      // same-bytes check below does NOT subsume this: decodeBody falls back to
      // the raw compressed bytes when it cannot decompress, and then the stream
      // and the scanned body match while neither pass can read either.
      const contentEncoded = call.response.headers?.some(
        ([n, v]) =>
          n.toLowerCase() === "content-encoding" &&
          v.trim() !== "" &&
          v.trim().toLowerCase() !== "identity",
      );
      // Otherwise the stream IS the bytes the response scan read, so redact it
      // from that scan's spans and keep the value pass for echoes — see
      // redactRawStream for why a value pass alone was not enough here, and for
      // the same-bytes check that decides between spans and withholding. No
      // extra scan: the offsets are already paid for.
      sseRaw = contentEncoded
        ? null
        : redactRawStream(sseRaw, call.response.bodyBytes ?? null, respScan?.findings ?? [], redaction.values);
      // Outbound only (see buildSearchText): index the request, not the response.
      searchText = new TextDecoder().decode(requestBody);
    }
    const summary = redaction?.heldOut
      ? "[REDACTION INCOMPLETE: content withheld]"
      : buildSummary(summaryParsed, derived.inbound[0], summaryActions, [
          // A BACKSTOP now, not the defense: the parts above already arrive
          // offset-redacted. What still reaches it is redactDerivedParts'
          // overlap skip — a finding sharing bytes with an already-spliced one
          // is recorded as a value rather than spliced twice — and an
          // incomplete derived scan, which hands its parts back RAW.
          //
          // Read that second case honestly. With redact-on-capture ON it never
          // gets here: scanState goes incomplete above and the whole call is
          // withheld. With it OFF nothing withholds it, so this pass is all
          // the summary gets — 8-char floor included, which means a value as
          // short as the one this fix is about would still survive THERE. That
          // is the same raw-fidelity trade every other surface makes in that
          // mode (the body beside it is stored raw too), and the row carries
          // scanState "incomplete" so the reader is told. Runs whatever the
          // setting: the feed line is always visible, so it must never depend
          // on redact-on-capture to do its scrubbing.
          ...(redaction?.values ?? []),
          ...bodyValues,
          ...derived.values,
        ]);
    // A wire row normally persists NO transcript: the viewer re-parses the
    // stored body, which is byte-exact, so re-deriving is faithful and free.
    // Derived redaction breaks that. A secret the display MANUFACTURES by
    // joining content blocks is not in the body at all, so nothing the body
    // redaction could do would stop the viewer rebuilding it at read time —
    // masked in the summary and the index, and rendered whole in the transcript
    // beside them. Persist the redacted projection for those rows and let it
    // win over the re-parse (viewer/detail.ts).
    //
    // STORED layout is [system, ...messages, reply?, ...response calls], with
    // index 0 ALWAYS the system prompt (empty when the request had none) — that
    // fixed head is what lets the viewer lift it back out unambiguously, even
    // from a body whose own messages carry a "system" role, and the tail is
    // marked by a `kind` the parsers never emit.
    //
    // It is NOT the derived array reshaped: that one carries a detail per
    // message in a trailing run of its own, which has no entry here. The halves
    // were lifted back out separately above precisely so this list can keep its
    // own shape instead of inheriting the scan's.
    //
    // Every `detail` here — a request message's and a response call's alike —
    // arrives span-redacted from its own part, so the value scrub below is no
    // longer what stands in for a missing span. It is the seam pass: a body
    // value the DERIVED scan never reported at any offset in this projection
    // (the finding cap). Belt and braces, the same pairing the Mode B search
    // text uses.
    //
    // NOT gated on `redaction`, unlike the stored bodies and the search index.
    // Turning redact-on-capture off buys the raw view of BYTES THAT WERE ON THE
    // WIRE — and a secret a join manufactures was never on the wire in that
    // form; the reassembly builds it at read time out of parts that are
    // individually innocent. So the setting has no raw copy to protect here,
    // and leaving this NULL only meant the viewer rebuilt the secret instead.
    // The always-visible summary already draws exactly this line above ("Runs
    // whatever the setting"). The raw panes still show every byte as received,
    // which is what the setting is actually for.
    let displayMessages: DisplayMessage[] | null = null;
    if (!redaction?.heldOut && derived.values.length > 0 && parsed) {
      // Built inside the branch: persisting a projection is the exception, so
      // the common row must not pay to assemble a value list it never reads.
      const values = [...derived.values, ...(redaction?.values ?? []), ...bodyValues];
      displayMessages = [
        { role: "system", content: outContents[0]! },
        ...redactedMessages.map((m) =>
          m.detail ? { ...m, detail: redactValuesInText(m.detail, values) } : m,
        ),
        // The REPLY is stored too, as a trailing kind:"response" entry, because
        // the viewer re-derives it the same way and for the same reason:
        // parseResponse REASSEMBLES a streamed answer, so a key the provider
        // split across two text_delta frames is in no single frame of the
        // stored body and the re-parse rebuilds it whole however well those
        // bytes are masked. The summary already reads derived.inbound[0]; this
        // is the surface that still re-derived it. `kind` is the writer's own
        // marker, never a value the parsers produce, so a stored reply is as
        // unambiguous as the system prompt at index 0.
        ...(respParsed?.text !== undefined
          ? [{ role: "assistant", kind: "response" as const, content: derived.inbound[0] ?? "" }]
          : []),
        // The reply's TOOL CALLS, same marker trick and same reason. The viewer
        // re-runs extractActions over the stored body, which JSON-parses it —
        // decoding the very escapes that hid the value from the scanner — so
        // both halves of each card rebuild a string no rule ever matched in
        // those bytes. args rides `content` (it is the card's body); detail
        // keeps its own. Placeholder discovery covers BOTH fields now — see
        // storedText — so the placement is the card's shape talking, not a
        // constraint of what gets scanned for markers.
        ...respActions.map((a, i) => ({
          role: "assistant",
          kind: "response-call" as const,
          tool: a.tool,
          callId: a.callId,
          detail: derived.inbound[1 + 2 * i]!,
          content: derived.inbound[2 + 2 * i]!,
        })),
      ];
    }

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
      // Derived findings count: the summary and the search index ARE stored
      // content, and a manufactured secret rewrites them while leaving the body
      // untouched — a row that read "not redacted" would deny a rewrite that
      // happened. Only when redact-on-capture is ON, though: with it off the
      // derived surfaces keep their raw text (just the always-visible summary
      // scrubs), and claiming otherwise would mislabel the row.
      redacted: redaction ? redaction.redacted || derived.values.length > 0 : false,
      // Persist the parser's one-shot verdict: the sessions list badges a
      // session as a utility turn from DATA, never by sniffing content later.
      oneShot: parsed?.oneShot ?? false,
      requestBody,
      requestHeaders: call.request.headers ?? null,
      responseBody,
      responseHeaders: call.response.headers
        ? scrubAuthHeaders(call.response.headers, undefined, call.provider)
        : null,
      sseRaw,
      displayMessages,
      searchText,
    });
    const derivedLeaks = this.alertDerived(
      {
        id: call.id,
        sessionId: resolution.sessionId,
        agent: call.agent,
        provider: call.provider,
        model: parsed?.model ?? respParsed?.model,
      },
      derived,
    );
    if (derivedLeaks > 0) this.viewer?.broadcast("leak", { callId: call.id });
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
      // Honest at broadcast time: with redact-on-capture (the default) the
      // scan has already completed by here, so the findings are final. The
      // "leak" frame refreshes the feed for any straggler orderings.
      hasLeak: (stash?.findings.length ?? 0) > 0 || derivedLeaks > 0,
    });
  }

  // Mode B ingest (design §6.2): OTel-reported calls run the identical
  // scanner/session/alert/store path — source='otel' is the only difference,
  // surfaced as the agent-reported badge (R7).
  private async ingestOtel(calls: OtelCall[]): Promise<void> {
    if (!this.isRunning) return; // late delivery during shutdown — store may be closing
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
      // Same protocol-identity noise filter as the wire path.
      scanResult.findings = dropIdentityFieldNoise(call.request.bodyBytes, scanResult.findings);
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
      // The self-report's readable projection, scanned on its own (see
      // redactDerived). Mode B needs this most: its display messages come from
      // flattenPromptText, which JSON.parse's a serialized message list and
      // joins adjacent content blocks with NOTHING between them — the one
      // transform that can manufacture a secret the scanned bytes never held.
      const messages = call.request.messages ?? [];
      const requestText = new TextDecoder().decode(call.request.bodyBytes);
      const bodyValues = findingValues(requestText, scanResult.findings);
      const derived = await this.redactDerived(
        messages.map((m) => String(m.content)),
        [call.response.text ?? ""],
        bodyValues,
        requestText,
      );
      const redaction = this.config.redactOnCapture
        ? applyCaptureRedaction({
            incomplete:
              scanResult.state === "incomplete" || respScan?.state === "incomplete" || derived.incomplete,
            requestBytes: call.request.bodyBytes,
            requestFindings: scanResult.findings,
            responseBody: call.response.bodyBytes ?? null,
            responseFindings: respScan?.findings,
            // The wire path's note applies verbatim: a derived-only finding is
            // in no body-scan span, so only its VALUE can reach these bytes.
            // Mode B is where the two views diverge most — the scanned body is
            // the prompt attribute, which for a resumed conversation is a
            // serialized message list whose escapes the display drops.
            extraValues: derived.values,
          })
        : null;
      // OUTBOUND ONLY, the same invariant buildSearchText holds for the wire
      // path: a `beagle search` hit is proof the string was SENT.
      // call.response.text is the model's answer and is deliberately NOT
      // indexed, or a sentence only ever generated by the model would be
      // reported as sent. The answer still reaches the UI through the summary
      // and the stored response body.
      //
      // That outbound surface is the SCANNED BYTES, not the display messages.
      // A display message is a TRUNCATED view of it: a tool result keeps only
      // the first DISPLAY_RESULT_CAP chars of the output and drops the tool
      // INPUT entirely (otlp-map's buildCodexCall / mapHookToCall). Indexing
      // that copy meant a secret past the cap — or one that only ever appeared
      // in a command's arguments — was scanned, alerted and redacted, while
      // `beagle search` answered "never sent": a false negative on the one
      // question search exists to answer definitively. Search covers the whole
      // scanned surface now rather than a truncated slice of it. Offset-redacted
      // bytes, the copy the findings' spans index (the wire path does this too,
      // see the redacted branch above), so the value scrub below no-ops on this
      // half.
      let searchText = new TextDecoder().decode(redaction ? redaction.requestBody : call.request.bodyBytes);
      // Plus a user message whose flattening actually changed the text: it
      // holds flattenPromptText's plain-text form of a prompt that may sit
      // \"-escaped as JSON in those bytes — the same parsed-AND-raw tradeoff
      // buildSearchText documents for the wire path, paid only when the two
      // differ. And the tool NAME, which a Claude Code turn reports as its own
      // attribute (buildTurnCall's scanned body is inputs-only) though it rode
      // the real outbound request. Never a tool message's CONTENT: that is the
      // truncated prefix the bytes above already cover in full.
      //
      // The flattened form appended here is the DERIVED-REDACTED one when
      // redact-on-capture is on: it is the copy the derived scan's offsets
      // index, and the only copy in which a secret the flattening manufactured
      // exists at all.
      messages.forEach((m, i) => {
        const flat = redaction ? derived.outbound[i]! : String(m.content);
        const tool = (m as DisplayMessage).tool; // a parser label; core's Message carries none
        if (m.role === "user" && flat && !searchText.includes(flat)) searchText += "\n" + flat;
        else if (tool && !searchText.includes(tool)) searchText += "\n" + tool;
      });
      // The bytes half above is offset-redacted; the appended half arrives
      // already offset-redacted from the derived scan. This scrub is the
      // belt-and-braces pass for the seam between them — the raw values (and
      // their JSON-decoded forms) against text neither offset set indexes.
      if (redaction) searchText = redaction.heldOut ? "" : redactValuesInText(searchText, redaction.values);
      // Span-redacted parts, for the reason the wire path spells out: the feed
      // line must not be the one surface still trusting a value scrub that
      // floors at 8 chars. Positional against what redactDerived was handed
      // above — and note this outbound half has NO system part, so a message
      // is at i, not the wire path's i + 1. Kept separate from the transcript's
      // copy below, which honours redact-on-capture where this must not.
      const summaryMessages = messages.map((m, i) => ({ ...m, content: derived.outbound[i]! }));
      const summary = redaction?.heldOut
        ? "[REDACTION INCOMPLETE: content withheld]"
        : buildSummary(
            { model: call.model, messages: summaryMessages } as ParsedRequest,
            derived.inbound[0],
            undefined,
            [
              // The same backstop the wire path keeps, reaching the same two
              // cases and carrying the same 8-char limit — see there.
              ...(redaction?.values ?? []),
              ...bodyValues,
              ...derived.values,
            ],
          );
      const scanState =
        redaction?.heldOut || derived.incomplete ? "incomplete" : scanResult.state;
      // One answer for the row, shared by both writers below (the stitch and
      // the insert) so they cannot drift. Derived findings count: the summary,
      // the transcript and the search index ARE stored content, and a
      // manufactured secret rewrites them while leaving the body untouched — a
      // row reading "not redacted" would deny a rewrite that happened. Gated on
      // redact-on-capture: with it off those surfaces keep their raw text (only
      // the always-visible summary scrubs), so claiming otherwise would
      // mislabel the row.
      const redacted = redaction ? redaction.redacted || derived.values.length > 0 : false;
      // Persist the self-report's structure: Mode B bodies are scan text, not
      // provider JSON, so the viewer can't re-parse them the way it does wire
      // bodies. Content comes back OFFSET-redacted from the derived scan, which
      // is the only thing that reaches a secret this projection manufactured or
      // re-escaped; a value scrub against the raw matches never could.
      //
      // The cap lands HERE, after redaction, and not in the mappers that build
      // these messages: truncating first cut the tail off a secret straddling
      // the cap, and the scrub that followed — matching the whole value —
      // sailed past the raw prefix it left behind in the transcript.
      const displayMessages = redaction?.heldOut
        ? null
        : messages.map((m, i) => {
            const content = redaction ? derived.outbound[i]! : String(m.content);
            return {
              // Keep display labels (tool/kind) — only the content is scrubbed.
              // Sound ONLY because these labels carry no content: the wire path
              // spreads the same way and had to give `detail` its own derived
              // part to stop it riding through raw. A Mode B mapper that starts
              // setting `detail` (otlp-map sets none today) reopens that hole.
              ...m,
              role: m.role,
              content:
                (m as DisplayMessage).kind === "result"
                  ? clampRedacted(content, DISPLAY_RESULT_CAP)
                  : content,
            };
          });
      // Cross-batch turn stitching: Claude Code flushes the prompt in one OTLP
      // batch and the response seconds later in another. A response-only
      // partial rejoins its stored turn row instead of landing as a detached
      // answer the feed can't line up with its question.
      //
      // STRICTLY response-only (no messages, zero request bytes) is required,
      // and the emptiness check is what makes skipping the rest of the loop
      // safe: this branch `continue`s past alertEngine.process, so a partial
      // carrying ANY outbound content (a tool_input — a real leak surface)
      // must fall through to its own row and its own alert pass. Do not relax
      // this to merge tool-bearing batches without moving alerting first; a
      // secret in a tool input would stop firing. A turn whose answer shares a
      // batch with its tool_result therefore stays two rows by design.
      //
      // Held-out redaction also falls through: its "[REDACTION INCOMPLETE]"
      // placeholder must not overwrite the turn row's real summary.
      // Rollout-sourced answers (origin='codex-rollout') are inbound-only and
      // ATTACH-OR-DROP — never a standalone row (design §6.1a): on an attach
      // miss (race) or held-out scan we drop, avoiding an answer-with-no-question
      // row and a duplicate on daemon restart. (Keeping the answer out of the
      // outbound search index — design §6.1b — is now structural: since PR #92,
      // attachOtelResponse never touches the FTS index for any stitch.)
      const fromRollout = call.origin === "codex-rollout";
      const responseOnly =
        Boolean(call.promptId) &&
        !call.request.messages?.length &&
        call.request.bodyBytes.byteLength === 0 &&
        Boolean(call.response.text);
      if (
        responseOnly &&
        !redaction?.heldOut &&
        this.store.attachOtelResponse({
          sessionId: resolution.sessionId,
          promptKey: call.promptId!,
          tsResponse: call.meta.tsResponse ?? call.meta.tsRequest,
          model: call.model,
          tokensIn: call.meta.tokensIn,
          tokensOut: call.meta.tokensOut,
          // Read like a turn that arrived in ONE batch: `"question" → answer`
          // (buildSummary's wire order). Without this the stitched row would
          // show only the answer, dropping the question the row is about.
          // Both halves come from already-scrubbed text — `summary` went
          // through buildSummary's secretValues pass and the stored summary
          // was scrubbed when its row was written; never re-derive from the
          // raw call.response.text here, which would undo the redaction.
          composeSummary: (existing) =>
            existing ? `"${firstLine(existing, 40)}" → ${firstLine(summary, 80)}` : summary,
          redacted,
          responseBody: redaction ? redaction.responseBody : (call.response.bodyBytes ?? null),
        })
      ) {
        continue;
      }
      // Attach failed (or was skipped for heldOut): a rollout answer drops here
      // instead of falling through to insertCall as an orphan/duplicate row.
      if (responseOnly && fromRollout) continue;
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
        redacted,
        requestBody: redaction ? redaction.requestBody : call.request.bodyBytes,
        requestHeaders: null,
        responseBody: redaction ? redaction.responseBody : (call.response.bodyBytes ?? null),
        responseHeaders: null,
        sseRaw: null,
        displayMessages: displayMessages?.length ? displayMessages : null,
        searchText,
        promptKey: call.promptId,
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
      // A secret the flattening MANUFACTURED is not in the scanned bytes, so
      // scanResult can't see it and this is the only pass that fires for it.
      const derivedLeaks = this.alertDerived(
        {
          id: call.id,
          sessionId: resolution.sessionId,
          agent: call.agent,
          provider: call.provider,
          model: call.model,
        },
        derived,
      );
      // Same silent leak frame as the wire path — possible-tier findings must
      // refresh open dashboards too.
      if (scanResult.findings.length + derivedLeaks > 0) {
        this.viewer?.broadcast("leak", { callId: call.id });
      }
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
        // Both scans completed above — final.
        hasLeak: scanResult.findings.length + derivedLeaks > 0,
      });
      // A real (non-rollout) Codex OTel call means that conversation is live —
      // ensure a rollout tailer for it. Triggered here, AFTER the turn row is
      // written, so the tailer's answer attaches instead of racing the insert.
      // This is both the trigger and the authorization to read that one
      // session's file (design §5).
      if (call.agent === "codex" && call.convId && call.origin !== "codex-rollout") {
        this.codexRollout?.onActivity(call.convId);
      }
    }
  }

  private emitAlert(a: AlertEvent): void {
    // Core emits the facts; the human wording is built HERE, once, and every
    // surface (dashboard banner, OS notification, terminal, test sink) gets
    // the same enriched event — facts plus copy.
    const msg = buildAlertMessage(a);
    const alert: EmittedAlert = { ...a, ...msg };
    this.viewer?.broadcast("alert", alert);
    if (this.opts.alertSinkForTest) {
      this.opts.alertSinkForTest(alert);
      return;
    }
    this.notifier.notify(msg);
    // Terminal backstop ONLY when stderr is a real terminal (foreground
    // `beagle daemon`). A detached/service daemon's stderr is redirected to
    // daemon.log — writing leak-alert metadata (secret type, destination,
    // agent) there would leave a shadow leak ledger that survives
    // `beagle purge`. The OS notification is the real delivery; `beagle leaks`
    // is the purge-able alert history.
    if (process.stderr.isTTY) {
      process.stderr.write(this.notifier.terminalLine(msg) + "\n");
    }
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
      onPurge: (kind, sessionId) => {
        if (kind === "panic") this.store.panicPurge();
        // Scoped delete of one session (the dashboard's per-session control).
        // No id → do nothing, never fall back to wiping everything.
        else if (kind === "session") { if (sessionId) this.store.purge({ kind: "session", sessionId }); }
        else if (kind === "all") this.store.purge({ kind: "all" });
        // Any other kind is a no-op: an unrecognized value must never be
        // treated as "delete everything".
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
        if (args.agentRunMode && typeof args.agentRunMode === "object") this.config.agentRunMode = args.agentRunMode;
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
            leases: this.leases,
            // Pipeline work not yet finished. One entry per batch, so 0 means
            // every call in every delivered batch is scanned, stored, and
            // alerted — the quiesce signal tests need to assert exact counts
            // without racing, and a real "is it still working?" diagnostic.
            inflight: this.inflight.size,
            viewerOpen: this.viewer?.isRunning ?? false,
            persistent: this.persistent,
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
      case "shutdown": {
        // Authoritative lease re-check (the CLI's client-side check is a
        // stale read-then-act — a run could have leased since). Refuse a
        // graceful stop while capturing; `force` overrides.
        const forceStop = (req.args as { force?: boolean } | undefined)?.force === true;
        if (this.leases > 0 && !forceStop) {
          return { ok: false, error: `capturing ${this.leases} live session${this.leases === 1 ? "" : "s"}` };
        }
        // Same guard as idle-exit: an in-process (test) daemon must stop
        // cleanly without taking the host process down with it.
        setTimeout(
          () => void this.stop().then(() => { if (this.opts.exitProcessOnIdle !== false) process.exit(0); }),
          10,
        );
        return { ok: true };
      }
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

// Secret values recovered from the scan findings (string offsets into the
// scanned text) — the summary scrubs with these even when redact-on-capture
// is off, because the feed line is always visible.
function findingValues(
  text: string,
  findings?: Array<{ start: number; end: number; secretType: string }>,
): Array<{ value: string; type: string }> {
  if (!findings?.length || !text) return [];
  return findings
    .map((f) => ({ value: text.slice(f.start, f.end), type: f.secretType }))
    .filter((v) => v.value !== "");
}

// A plain-English "what happened" line (R7), in wire order: what the request
// sent (short, bounded) → what came back (actions or reply). One line, both
// directions, same reading order as the ⇢/⇠ views; the quoted ask is capped at
// 40 chars either way.
//
// Both daemon call sites pass text the derived scan has ALREADY offset-redacted
// — a value scrub can't be the feed line's only defense, because it floors at
// 8 chars and connection-string reports a password on its own. `secretValues`
// is the backstop behind that. It runs unconditionally, so the feed line
// scrubs whatever redact-on-capture says — but the floor is its limit, and
// both passes only ever see what the scan reported. The wire call site names
// the paths where those limits still show.
export function buildSummary(
  parsed: ParsedRequest | null,
  responseText?: string,
  actions?: ToolAction[],
  secretValues?: Array<{ value: string; type: string }>,
): string {
  // Redact-on-capture (R11): the summary derives from the same raw messages
  // the body redaction already scrubbed, so it must scrub too. Before EVERY
  // truncation — a secret cut by a cap no longer literal-matches, and a
  // post-hoc scrub of the finished line would leak its prefix. That holds for
  // firstLine's caps below AND for the tool detail, which is why toolAction no
  // longer clamps at parse time: that clamp ran before this scrub could see it.
  if (secretValues && secretValues.length > 0) {
    const scrub = (s: string) => redactValuesInText(s, secretValues);
    if (responseText !== undefined) responseText = scrub(responseText);
    actions = actions?.map((a) => (a.detail ? { ...a, detail: scrub(a.detail) } : a));
    if (parsed) parsed = { ...parsed, messages: parsed.messages.map((m) => ({ ...m, content: scrub(m.content) })) };
  }
  // Wire order: what the request sent, then what came back — the same
  // reading direction as every ⇢/⇠ surface. The sent half leads because it
  // is short and BOUNDED (a 40-char quoted ask or "N x results"), so the
  // response keeps the rest of the line; the response half still budgets
  // (2 actions / 80 chars) when both render. Skipped for one-shots — their
  // summaries feed sessionTitle's JSON unwrap untouched.
  const sent = parsed?.oneShot ? "" : sentPart(parsed?.messages);
  const got =
    actions && actions.length > 0
      ? summarizeActions(actions, sent !== "")
      : responseText
        ? firstLine(responseText, sent ? 80 : 100)
        : null;
  if (got !== null) {
    return clampLine(sent ? `${sent} → ${got}` : got, SUMMARY_CAP);
  }
  if (!parsed) return "unparsed call (raw view available)";
  if (parsed.messages.length === 0) return "(no message content)";
  // Prefer the last user message; else summarize the last message of ANY role.
  // Mode B records are often tool-output-only (role "tool") or assistant-only —
  // their content should show ("ToolSearch: …"), not a bare "N messages" count.
  const pick = [...parsed.messages].reverse().find((m) => m.role === "user") ?? parsed.messages.at(-1)!;
  return clampLine(firstLine(pick.content, 100), SUMMARY_CAP);
}

// The assembled line's own bound. Each half already clamps, but the halves
// COMPOSE — an ask plus three tool details is four independent run-pasts, which
// stacked to 274 chars of real placeholder (541 for one forged in captured
// content) and quietly walked back the "summary became unbounded" fix. Clamping
// once here keeps that invariant statable again: SUMMARY_CAP, plus at most a
// SINGLE placeholder run-past.
//
// 200 sits above the ~162 a summary of recognized verbs reaches, so ordinary
// rows pass through untouched — but NOT every placeholder-free row does, and
// the claim is worth stating honestly: verb() returns an unrecognized tool's
// name verbatim and `tool` arrives unbounded, so a turn full of long MCP names
// can cross 200 on name length alone and lose the trailing `+N` inside the cut.
// That is the cap doing its job rather than a silent one — the ellipsis it
// leaves is the same "there was more" signal `+N` carries.
const SUMMARY_CAP = 200;

// The request's newest content, judged from its trailing messages only (the
// daemon has no previous-call diff): a trailing user message, or a trailing
// run of tool results. Content is already scrubbed by the caller.
// The request's newest content as the summary's LEADING half: a trailing run
// of tool results ("3 webfetch results") or the trailing user ask (quoted,
// capped at 40). The results check comes FIRST: Anthropic's protocol carries
// tool results inside user-ROLE messages (kind stamps them at parse) —
// quoting those as the user's ask would caption tool output as human words.
// Tool names are parse-sanitized identifiers, so the title/splitter regexes
// can recognize the shape. Content is already scrubbed by the caller.
function sentPart(messages?: DisplayMessage[]): string {
  if (!messages?.length) return "";
  const last = messages.at(-1)!;
  let results = 0;
  const tools = new Set<string>();
  for (let i = messages.length - 1; i >= 0 && messages[i]!.kind === "result"; i--) {
    results++;
    tools.add(messages[i]!.tool ?? "tool");
  }
  if (results > 0) {
    const name = tools.size === 1 ? [...tools][0]! : "tool";
    return `${results} ${name} result${results === 1 ? "" : "s"}`;
  }
  if (last.role === "user") return `"${firstLine(last.content, 40)}"`;
  return "";
}

// Map coding-agent tools to verbs and group repeats: "read 3 files, ran `npm test`".
function summarizeActions(actions: ToolAction[], compact = false): string {
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
    // EVERY branch goes through firstLine: `detail` arrives unclamped from the
    // parser (deliberately — a parse-time clamp cut secrets in half before the
    // scrub could match them, see toolAction), so this is the only thing
    // bounding what lands in the stored summary and rides every feed frame. A
    // basename or a bare path is not self-limiting: one 500 KB tool argument
    // put 500 KB — newlines and all — into a column meant for one line.
    if (v === "ran" && a.detail) parts.push(`ran \`${firstLine(a.detail, 40)}\``);
    else if (v === "read" && a.detail) files.push(firstLine(a.detail.split("/").pop() ?? a.detail, 40));
    else if (a.detail) {
      // URLs keep their head (host says more than a trailing path segment);
      // paths keep their tail (the filename).
      const label = a.detail.includes("://") ? a.detail : (a.detail.split("/").pop() || a.detail);
      parts.push(`${v} \`${firstLine(label, 40)}\``);
    }
    else parts.push(v);
  }
  if (files.length === 1) parts.unshift(`read ${files[0]}`);
  else if (files.length > 1) parts.unshift(`read ${files.length} files`);
  // No silent caps: overflow shows as "+N". Compact mode (a sent-suffix will
  // follow) budgets the lead to 2 actions so both halves fit one feed line.
  const cap = compact ? 2 : 3;
  const shown = parts.slice(0, cap).join(", ");
  const extra = parts.length - Math.min(parts.length, cap);
  if (!shown) return `${actions.length} tool calls`;
  return extra > 0 ? `${shown} +${extra}` : shown;
}

// Bound a single line to `max` for display. Every caller clamps text
// buildSummary already redacted (the scrub runs before EVERY truncation,
// above), so on a leak row a placeholder straddling `max` is the NORMAL case —
// and a bare slice leaves `my key [RED…`, which reads as a corrupted
// transcript and drops the secret TYPE the placeholder exists to name.
// clampRedacted runs past the closing bracket instead; the ellipsis stays for
// the genuinely-truncated case.
//
// The overshoot is bounded by clampRedacted's own ceiling: 39 chars for a real
// placeholder (the longest rule id is 21), 128 for one a captured tool result
// forged in its content. That is why the quoted-ask regexes in
// commands.ts/app.js bound that half at 200 rather than 40 — see the note
// there — and why the assembled line clamps once more at SUMMARY_CAP.
function clampLine(line: string, max: number): string {
  if (line.length <= max) return line;
  const clamped = clampRedacted(line, max - 1);
  // Running past to the end dropped nothing — an ellipsis would be a lie.
  if (clamped.length >= line.length) return line;
  // The outer SUMMARY_CAP pass can land right after a half's own ellipsis;
  // one mark already says "truncated", and `……` just reads as a typo.
  return clamped.endsWith("…") ? clamped : clamped + "…";
}

function firstLine(s: string, max: number): string {
  return clampLine(s.split("\n")[0] ?? "", max);
}

function buildSearchText(parsed: ParsedRequest | null, call: CapturedCall, outboundParts: string[]): string {
  // OUTBOUND ONLY. `beagle search` answers "was this string SENT" (README:
  // "did that internal hostname ever leave?"), so a hit is definitive proof it
  // left the machine. Indexing the provider's RESPONSE would report a
  // model-generated string as "sent" when the user never sent it. This also
  // matches R7's request-scoped leak model: response content only matters once
  // it's echoed back in the NEXT request — which is itself indexed here.
  // Parsed text where a parser ran (finds secrets that appear \"-escaped in
  // raw JSON); decoded raw request bytes otherwise (R8 / schema note).
  // `outboundParts` is [system, ...message contents] — the caller's copy,
  // already offset-redacted by the derived scan, so a secret spanning two
  // messages is masked here exactly where that scan found it.
  //
  // Joined with a plain newline, NOT derivedScanText: that separates parts with
  // a NUL so no rule can match across the join, which is right for the scan and
  // wrong for the index. The masking already happened at the PART level, so the
  // index needs no offset agreement with the scan text — only readable content.
  if (parsed) return outboundParts.join("\n");
  return new TextDecoder("utf-8", { fatal: false }).decode(call.request.bodyBytes);
}
