// Host side of the worker-hosted scanner (design §6.3). The worker is what
// makes the ReDoS deadline enforceable: on breach, terminate + respawn, and
// the scan reports 'incomplete' — fail-safe, never a silent "clean".
import type { Finding, ScanCtx } from "../core/scanner/engine";
import type { RuleSpec } from "../core/scanner/rules";

export interface ScanResult {
  state: "ok" | "incomplete";
  findings: Finding[];
}

// Protocol identity fields carry expected high-entropy plumbing — opencode's
// prompt_cache_key IS its session id (the value Beagle groups sessions by),
// not a credential. The generic entropy detector fires on it because the
// field NAME supplies its context keyword ("…key"). Drop possible-tier
// findings that overlap such a field; structured detectors (a real AWS key
// pasted anywhere, even inside the field) still fire.
//
// Deliberately ONLY keyword-bearing field names: the generic rule cannot
// anchor on names like previous_response_id or session_id (no keyword), so
// listing them would never prevent a false positive — it would only suppress
// real findings in pasted content that happens to be shaped like those
// fields. Extend only when a new keyword-bearing protocol field is observed.
// (Linear regex — disjoint alternatives, anchored on the literal name — safe
// to run here in the daemon, outside the scan worker's ReDoS sandbox.)
const IDENTITY_FIELD_RE = /"prompt_cache_key"\s*:\s*"(?:[^"\\]|\\.)*"/g;

export function dropIdentityFieldNoise(bytes: Uint8Array, findings: Finding[]): Finding[] {
  if (!findings.some((f) => f.tier === "possible")) return findings;
  // Same decode as the scanner (engine.scan): spans index this exact string.
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const ranges: Array<[number, number]> = [];
  IDENTITY_FIELD_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = IDENTITY_FIELD_RE.exec(text)) !== null) ranges.push([m.index, m.index + m[0].length]);
  if (ranges.length === 0) return findings;
  // Overlap, not containment: a generic match's span starts at its context
  // keyword, which can sit just before the field's opening quote.
  return findings.filter(
    (f) => f.tier !== "possible" || !ranges.some(([s, e]) => f.start < e && f.end > s),
  );
}

export interface ScanHostOptions {
  /** Rule file CONTENT (not a path): the caller owns loading/embedding, so
   *  the compiled binary needs no filesystem access for rules. */
  rulesJson: string;
  rulesPin?: string;
  hmacKey: Uint8Array;
  deadlineMs: number;
  extraRulesForTest?: RuleSpec[];
}

interface Pending {
  resolve: (r: ScanResult) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class ScanHost {
  private worker: Worker | null = null;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private closed = false;

  constructor(private opts: ScanHostOptions) {}

  scan(bytes: Uint8Array, ctx: ScanCtx): Promise<ScanResult> {
    if (this.closed) return Promise.resolve({ state: "incomplete", findings: [] });
    const worker = this.ensureWorker();
    const id = this.nextId++;
    // Stage into a fresh buffer (the caller's may be a shared view), then
    // hand it to the worker as a transferable — the transfer itself is free.
    const buf = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(buf).set(bytes);
    return new Promise((resolve) => {
      const timer = setTimeout(() => this.onDeadline(id), this.opts.deadlineMs);
      this.pending.set(id, { resolve, timer });
      worker.postMessage({ kind: "scan", id, bytes: buf, ctx }, [buf]);
    });
  }

  close(): void {
    this.closed = true;
    this.worker?.terminate();
    this.worker = null;
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.resolve({ state: "incomplete", findings: [] });
      this.pending.delete(id);
    }
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    // Compiled binary: entrypoints land in $bunfs under their paths relative
    // to the entries' common root (src/), and Worker strings resolve against
    // that root — URL-based resolution fails there. Dev/test: resolve
    // relative to this module. Both verified in tests/build.test.ts.
    const isCompiled = import.meta.url.includes("$bunfs");
    const entry = isCompiled
      ? "./adapters/scan-worker-entry.ts"
      : new URL("./scan-worker-entry.ts", import.meta.url).href;
    const worker = new Worker(entry);
    worker.onmessage = (event: MessageEvent<{ kind: string; id: number; findings: Finding[] }>) => {
      const { id, findings } = event.data;
      const p = this.pending.get(id);
      if (!p) return;
      clearTimeout(p.timer);
      this.pending.delete(id);
      p.resolve({ state: "ok", findings });
    };
    worker.onerror = (e) => {
      // Never die silently: a dead scanner means every scan reports
      // incomplete — say why, once per worker incarnation.
      process.stderr.write(
        `beagle: scanner worker error — scans will report incomplete: ${String((e as ErrorEvent).message ?? e).slice(0, 300)}\n`,
      );
      this.failAll();
    };
    worker.postMessage({
      kind: "init",
      rulesJson: this.opts.rulesJson,
      rulesPin: this.opts.rulesPin,
      extraRules: this.opts.extraRulesForTest,
      hmacKey: this.opts.hmacKey,
    });
    this.worker = worker;
    return worker;
  }

  private onDeadline(id: number): void {
    void id; // the breaching scan fails with the rest of the batch
    // A stuck regex can't be interrupted in-thread; kill the whole worker.
    this.worker?.terminate();
    this.worker = null; // respawned lazily on the next scan
    this.failAll();
  }

  private failAll(): void {
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.resolve({ state: "incomplete", findings: [] });
      this.pending.delete(id);
    }
  }
}
