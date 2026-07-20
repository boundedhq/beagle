// Daemon-side reader for Codex's rollout logs. On Codex OTel activity for a
// conversation, the watcher locates that session's rollout file and a per-file
// tailer polls it, emitting each assistant answer as a response-only OtelCall
// the daemon stitches onto the turn row (store.attachOtelResponse). Lives in
// adapters (fs + timers). Pairing/keying is in ../parsers/codex-rollout (pure).
// See docs/codex-rollout-response-capture-design.md.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { ulid } from "../core/store/ulid";
import { answersFromText, type RolloutAnswer } from "../parsers/codex-rollout";
import type { OtelCall } from "../parsers/otlp-map";

const POLL_MS = 1500; // ~the OTel batch cadence, so the answer stitches a beat after its turn's batch
const RETRY_WINDOW_MS = 6000; // re-emit a recent answer until its turn row exists (race recovery)
const RETIRE_MS = 30000; // close a tailer after this long with no new lines and no OTel activity

/** ~/.codex/sessions, honoring CODEX_HOME. The daemon inherits the launching
 *  shell's env (commands.ts spreads process.env into the daemon spawn), so a
 *  per-run CODEX_HOME reaches here in the common `beagle run` path; a service
 *  daemon with a different env falls back to ~/.codex (fail-open — §5.2/§7). */
export function codexSessionsRoot(): string {
  return join(process.env.CODEX_HOME || join(homedir(), ".codex"), "sessions");
}

// Locate a conversation's rollout by filename suffix. Called ONCE per tailer
// (not per poll) — the sessions tree is date-partitioned and unbounded.
function locateRollout(root: string, convId: string): string | null {
  const suffix = `-${convId}.jsonl`;
  let bestPath: string | null = null;
  let bestMtime = -Infinity;
  const walk = (dir: string): void => {
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return; // unreadable dir — skip
    }
    for (const name of names) {
      const full = join(dir, name);
      let st: ReturnType<typeof statSync>;
      try {
        st = statSync(full);
      } catch {
        continue; // raced unlink — ignore
      }
      if (st.isDirectory()) walk(full);
      else if (name.startsWith("rollout-") && name.endsWith(suffix) && st.mtimeMs > bestMtime) {
        bestPath = full;
        bestMtime = st.mtimeMs;
      }
    }
  };
  walk(root);
  return bestPath;
}

function buildResponseCall(convId: string, ans: RolloutAnswer, now: () => number): OtelCall {
  const ts = ans.tsMs ?? now();
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
  private readonly firstSeen = new Map<number, number>(); // answer index → first-seen ms
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
    if (!this.filePath) {
      // Locate once found, then poll that path directly. Until then, retry the
      // locate each poll (bounded — the tailer retires if the file never shows).
      this.filePath = locateRollout(this.opts.sessionsRoot ?? codexSessionsRoot(), this.opts.convId);
      if (!this.filePath) {
        this.checkRetire();
        return;
      }
    }
    let text: string;
    try {
      text = readFileSync(this.filePath, "utf8");
    } catch {
      this.checkRetire(); // file gone/unreadable — still age toward retirement
      return;
    }
    const answers = answersFromText(text);
    const now = this.now();
    if (answers.length > this.firstSeen.size) this.lastChange = now;

    // Emit each answer once when first seen, and re-emit it within the retry
    // window so a raced answer (its turn row not yet written) lands once the
    // row appears. attach is idempotent — a re-emit for an already-answered
    // turn simply drops in the daemon (design §5.1/§6.1a).
    const window = this.opts.retryWindowMs ?? RETRY_WINDOW_MS;
    const due: OtelCall[] = [];
    answers.forEach((ans, i) => {
      let seen = this.firstSeen.get(i);
      if (seen === undefined) {
        seen = now;
        this.firstSeen.set(i, seen);
      }
      if (now - seen <= window) due.push(buildResponseCall(this.opts.convId, ans, this.now));
    });
    if (due.length) this.opts.emit(due);
    this.checkRetire(now);
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

  constructor(private readonly opts: WatcherOptions) {}

  onActivity(convId: string): void {
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
    for (const tailer of this.tailers.values()) tailer.stop();
    this.tailers.clear();
  }
}
