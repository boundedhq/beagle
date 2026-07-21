// Daemon-side reader for Codex's rollout logs. On Codex OTel activity for a
// conversation, the watcher locates that session's rollout file and a per-file
// tailer polls it, emitting each assistant answer as a response-only OtelCall
// the daemon stitches onto the turn row (store.attachOtelResponse). Lives in
// adapters (fs + timers). Pairing/keying is in ../parsers/codex-rollout (pure).
// See docs/codex-rollout-response-capture-design.md.
import { createHash } from "node:crypto";
import { closeSync, lstatSync, openSync, readdirSync, readSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { ulid } from "../core/store/ulid";
import { RolloutPairing, type RolloutAnswer } from "../parsers/codex-rollout";
import type { OtelCall } from "../parsers/otlp-map";

const POLL_MS = 1500; // ~the OTel batch cadence, so the answer stitches a beat after its turn's batch
const RETRY_WINDOW_MS = 6000; // re-emit a recent answer until its turn row exists (race recovery)
// Close a tailer after this long with no new lines and no OTel activity.
// Generous on purpose: a long tool-free generation emits no content events
// (codex.sse_event maps to zero calls, so nothing reaches noteActivity) and
// writes no rollout lines until the answer completes — at 30s that retired the
// tailer mid-generation, and the answer surfaced only on the next content
// event, or never if the user quit first.
const RETIRE_MS = 120000;
// The locate walk is the expensive part of a tailer (the whole date-partitioned
// tree when nothing matches), so retries are bounded: a few fast attempts cover
// the file appearing a beat after the first OTel event, then the cadence backs
// off, then it stops for good. Unbounded, a conversation whose rollout never
// appears (service daemon with a different CODEX_HOME, history logging off)
// kept OTel activity flowing and re-walked the tree every poll for the life of
// the session.
const LOCATE_FAST_ATTEMPTS = 4; // first attempts run on the poll cadence
const LOCATE_BACKOFF_MAX_MS = 30000; // cap between backed-off attempts
const LOCATE_MAX_ATTEMPTS = 12; // then stop locating (≈3 min of coverage)

/** ~/.codex/sessions, honoring CODEX_HOME. The daemon inherits the launching
 *  shell's env (commands.ts spreads process.env into the daemon spawn), so a
 *  per-run CODEX_HOME reaches here in the common `beagle run` path; a service
 *  daemon with a different env falls back to ~/.codex (fail-open — §5.2/§7). */
export function codexSessionsRoot(): string {
  return join(process.env.CODEX_HOME || join(homedir(), ".codex"), "sessions");
}

// Locate a conversation's rollout by filename suffix. The sessions tree is
// date-partitioned (YYYY/MM/DD, zero-padded, so lexicographic order IS date
// order) and unbounded over time — visit names newest-first and stop once a
// directory's subtree has matched: the live file for a conversation is always
// in the most recent day that has one (`codex resume` starts a fresh rollout
// dated now, it never appends to an old day's file). Only a no-match walk
// still visits the whole tree, and poll() caps how many of those run.
function locateRollout(root: string, convId: string): string | null {
  const suffix = `-${convId}.jsonl`;
  let bestPath: string | null = null;
  let bestMtime = -Infinity;
  let done = false;
  const walk = (dir: string): void => {
    let names: string[];
    try {
      names = readdirSync(dir).sort();
    } catch {
      return; // unreadable dir — skip
    }
    for (let i = names.length - 1; i >= 0 && !done; i--) {
      const name = names[i]!;
      const full = join(dir, name);
      let st: ReturnType<typeof lstatSync>;
      try {
        // lstat, not stat: never follow a symlink into a directory, so a stray
        // symlink loop under the sessions tree can't recurse without bound.
        st = lstatSync(full);
      } catch {
        continue; // raced unlink — ignore
      }
      if (st.isDirectory()) walk(full);
      else if (st.isFile() && name.startsWith("rollout-") && name.endsWith(suffix) && st.mtimeMs > bestMtime) {
        bestPath = full;
        bestMtime = st.mtimeMs;
      }
    }
    // Everything in this directory has been seen; if any of it matched, older
    // siblings up the whole stack can only be staler files — stop the walk.
    if (bestPath) done = true;
  };
  walk(root);
  return bestPath;
}

// `fallbackTs` stands in for a timestamp-less rollout line: the file's
// last-write time when the answer was discovered, frozen across re-emits. A
// live now() here would defeat the store's stale-attach bound (ts_request <=
// tsResponse) — every re-emit would look freshly produced and could claim a
// newer identical-prompt turn's row. The poll clock would fail the same way
// one step later, on a RECREATED tailer (its first poll is "now" no matter
// how old the answers are); mtime is old at recreation, so it is the one
// stamp that keeps historical answers refusable there too.
function buildResponseCall(convId: string, ans: RolloutAnswer, fallbackTs: number): OtelCall {
  const ts = ans.tsMs ?? fallbackTs;
  return {
    id: ulid(ts),
    runId: "otel",
    source: "otel",
    origin: "codex-rollout",
    agent: "codex",
    provider: "openai",
    endpoint: "otel:codex:rollout_response",
    request: { bodyBytes: new Uint8Array(), messages: [] }, // response-only
    response: { text: ans.answer, bodyBytes: new TextEncoder().encode(ans.answer) },
    meta: { tsRequest: ts, tsResponse: ts },
    convId,
    promptId: ans.promptKey,
  };
}

export interface TailerOptions {
  convId: string;
  /** Explicit file (tests). In production omit it and pass sessionsRoot — the
   *  tailer locates the file on its own poll cadence (so a beat-late file is
   *  retried without re-walking the tree on every OTel event). */
  filePath?: string;
  sessionsRoot?: string;
  emit: (calls: OtelCall[]) => void;
  onRetire?: () => void;
  pollMs?: number;
  retryWindowMs?: number;
  retireMs?: number;
  now?: () => number; // injectable clock (tests)
}

export class CodexRolloutTailer {
  private timer: ReturnType<typeof setInterval> | null = null;
  private filePath: string | null;
  /** `index:promptKey:answerHash` → first-seen ms. Content-addressed, not
   *  index-only: after a truncate/rewrite the same slot can hold a DIFFERENT
   *  answer, which must read as new (index-only keys left it forever
   *  "already seen" — never emitted), while re-parsing identical content
   *  (rewrite, re-locate) must not re-emit it outside its retry window. */
  private readonly firstSeen = new Map<string, number>();
  /** Same content key → the file's mtime at discovery: the stand-in production
   *  time for a timestamp-less line (see buildResponseCall). Kept apart from
   *  firstSeen, which must stay the POLL time — reusing mtime there would age
   *  a recreated tailer's answers straight past the retry window and kill the
   *  back-fill emit. Survives resets with firstSeen: re-read identical content
   *  keeps its original discovery stamp. */
  private readonly tsFallback = new Map<string, number>();
  private answers: Array<{ ans: RolloutAnswer; key: string }> = []; // grows with the file; rebuilt on reset
  private pairing = new RolloutPairing();
  private readOffset = 0; // file bytes consumed (into parsed lines or carry)
  private carry: Buffer = Buffer.alloc(0); // partial trailing line, as BYTES — a UTF-8 char can split across reads
  private locateAttempts = 0;
  private nextLocateAt = 0; // clock gate for backed-off locate retries
  private lastSize = -1;
  private lastChange: number;
  private lastActivity: number;
  private readonly now: () => number;

  constructor(private readonly opts: TailerOptions) {
    this.filePath = opts.filePath ?? null;
    this.now = opts.now ?? Date.now;
    this.lastChange = this.now();
    this.lastActivity = this.now();
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.poll(), this.opts.pollMs ?? POLL_MS);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Note fresh OTel activity for this conversation — defers retirement. */
  noteActivity(): void {
    this.lastActivity = this.now();
  }

  poll(): void {
    if (!this.filePath && !this.locate()) {
      this.checkRetire();
      return;
    }
    let st: ReturnType<typeof statSync>;
    try {
      st = statSync(this.filePath!);
    } catch {
      // File gone or unreadable — deleted, or `codex resume` superseded it with
      // a fresh rollout for the same conversation. Drop the binding and
      // re-locate (with a fresh locate budget) instead of aging toward
      // retirement while the conversation may still be live under a new file.
      this.filePath = null;
      this.resetReadState();
      this.locateAttempts = 0;
      this.nextLocateAt = 0;
      this.checkRetire();
      return;
    }
    const size = st.size;
    const now = this.now();
    // The rollout is append-only, so read only when — and only WHAT — it grew:
    // the tailer polls for the whole session, and re-reading a multi-MB log
    // every tick was O(N²) sync work on the daemon's one thread. Retries below
    // still run from the cached `answers`.
    if (size !== this.lastSize) {
      this.lastChange = now; // any size change is liveness — codex is writing
      if (size < this.lastSize) this.resetReadState(); // truncated/rewritten — reparse from byte 0
      if (!this.readNewBytes(size)) {
        this.checkRetire(now); // read raced a change/failed — retried next poll
        return;
      }
      this.lastSize = size;
    }

    // Emit each answer once when first seen, and re-emit it within the retry
    // window so a raced answer (its turn row not yet written) lands once the
    // row appears. attach is idempotent — a re-emit for an already-answered
    // turn simply drops in the daemon (design §5.1/§6.1a), and one racing a
    // NEWER identical-prompt turn row (same text re-typed, or any historical
    // answer a recreated tailer re-reads) is refused by the store's
    // stale-attach bound rather than claiming that turn's row.
    const window = this.opts.retryWindowMs ?? RETRY_WINDOW_MS;
    const due: OtelCall[] = [];
    for (const { ans, key } of this.answers) {
      let seen = this.firstSeen.get(key);
      if (seen === undefined) {
        seen = now;
        this.firstSeen.set(key, seen);
        // Floored: ulid()'s base32 digits come from `t % 32`, garbage on a
        // fractional ms (mtimeMs is a float).
        this.tsFallback.set(key, Math.floor(st.mtimeMs));
      }
      if (now - seen <= window) due.push(buildResponseCall(this.opts.convId, ans, this.tsFallback.get(key) ?? seen));
    }
    if (due.length) this.opts.emit(due);
    this.checkRetire(now);
  }

  /** Bounded locate: true if the file is now bound. See the LOCATE_* rationale. */
  private locate(): boolean {
    const now = this.now();
    if (this.locateAttempts >= LOCATE_MAX_ATTEMPTS || now < this.nextLocateAt) return false;
    this.locateAttempts++;
    if (this.locateAttempts >= LOCATE_FAST_ATTEMPTS) {
      const backoff = (this.opts.pollMs ?? POLL_MS) * 2 ** (this.locateAttempts - LOCATE_FAST_ATTEMPTS + 1);
      this.nextLocateAt = now + Math.min(backoff, LOCATE_BACKOFF_MAX_MS);
    }
    this.filePath = locateRollout(this.opts.sessionsRoot ?? codexSessionsRoot(), this.opts.convId);
    return this.filePath !== null;
  }

  /** Forget everything read from the current binding (a new file, or the old
   *  one truncated/rewritten): the parse restarts from byte 0. firstSeen
   *  SURVIVES — its keys are content-addressed, so re-parsed identical answers
   *  stay settled while new content at a reused slot still emits. */
  private resetReadState(): void {
    this.pairing = new RolloutPairing();
    this.answers = [];
    this.readOffset = 0;
    this.carry = Buffer.alloc(0);
    this.lastSize = -1;
  }

  /** Read [readOffset, size) and fold its complete lines into `answers`.
   *  False if the read failed — state is untouched, the poll retries. */
  private readNewBytes(size: number): boolean {
    if (size <= this.readOffset) return true;
    let buf: Buffer;
    try {
      const fd = openSync(this.filePath!, "r");
      try {
        buf = Buffer.alloc(size - this.readOffset);
        let got = 0;
        while (got < buf.length) {
          const n = readSync(fd, buf, got, buf.length - got, this.readOffset + got);
          if (n <= 0) break; // EOF early: the file changed under us — keep what we got
          got += n;
        }
        if (got < buf.length) buf = buf.subarray(0, got);
      } finally {
        closeSync(fd);
      }
    } catch {
      return false;
    }
    this.readOffset += buf.length;
    const chunk = this.carry.length ? Buffer.concat([this.carry, buf]) : buf;
    // Split at the last newline: complete lines parse now, the partial tail is
    // carried to the next read. Split as BYTES, not text — decoding the halves
    // of a UTF-8 character separately would corrupt it (\n can never be a byte
    // of a multi-byte character, so the split itself is always char-safe).
    const nl = chunk.lastIndexOf(0x0a);
    this.carry = Buffer.from(chunk.subarray(nl + 1)); // copy — don't pin the big chunk
    if (nl >= 0) this.ingest(chunk.subarray(0, nl + 1).toString("utf8"));
    this.tryFlushCarry();
    return true;
  }

  /** Rollout lines are newline-terminated (verified against real files), but
   *  if a finished line ever lands without one, don't sit on its answer until
   *  the next write: consume the carry now iff it already decodes losslessly
   *  and parses as a JSON object line. A mid-write partial fails one of those
   *  checks and stays carried. */
  private tryFlushCarry(): void {
    if (!this.carry.length) return;
    const text = this.carry.toString("utf8");
    if (!text.startsWith("{") || text.includes("\uFFFD")) return; // not a whole line / split UTF-8 char
    try {
      JSON.parse(text);
    } catch {
      return;
    }
    this.carry = Buffer.alloc(0);
    this.ingest(text);
  }

  private ingest(text: string): void {
    for (const ans of this.pairing.push(text)) {
      const hash = createHash("sha256").update(ans.answer).digest("hex").slice(0, 16);
      this.answers.push({ ans, key: `${this.answers.length}:${ans.promptKey}:${hash}` });
    }
  }

  private checkRetire(now = this.now()): void {
    const retireMs = this.opts.retireMs ?? RETIRE_MS;
    if (now - this.lastChange > retireMs && now - this.lastActivity > retireMs) {
      this.stop();
      this.opts.onRetire?.();
    }
  }
}

export interface WatcherOptions {
  emit: (calls: OtelCall[]) => void;
  sessionsRoot?: string;
  pollMs?: number;
  retryWindowMs?: number;
  retireMs?: number;
  now?: () => number;
}

/** Owns one tailer per active Codex conversation. `onActivity` is driven by the
 *  daemon whenever it ingests a (non-rollout) Codex OTel call — that is both the
 *  trigger and the authorization to read that one conversation's file. */
export class CodexRolloutWatcher {
  private readonly tailers = new Map<string, CodexRolloutTailer>();
  private stopped = false;

  constructor(private readonly opts: WatcherOptions) {}

  onActivity(convId: string): void {
    // An ingestOtel that was in flight at shutdown drains AFTER stop() and may
    // reach here; without this guard it would spawn a poll interval that
    // outlives the daemon. (stop() runs before the inflight drain in doStop.)
    if (this.stopped) return;
    const existing = this.tailers.get(convId);
    if (existing) {
      existing.noteActivity();
      return;
    }
    // One tailer per conversation; it locates and reads the file itself (the
    // file may not exist yet at the first OTel event — the tailer retries).
    const tailer = new CodexRolloutTailer({
      convId,
      sessionsRoot: this.opts.sessionsRoot,
      emit: this.opts.emit,
      onRetire: () => this.tailers.delete(convId),
      pollMs: this.opts.pollMs,
      retryWindowMs: this.opts.retryWindowMs,
      retireMs: this.opts.retireMs,
      now: this.opts.now,
    });
    this.tailers.set(convId, tailer);
    tailer.start();
    tailer.poll(); // read immediately rather than wait a full interval
  }

  stop(): void {
    this.stopped = true;
    for (const tailer of this.tailers.values()) tailer.stop();
    this.tailers.clear();
  }
}
