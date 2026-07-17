// Viewer session projection (non-core): the "see a whole session" view. Two
// faces: listSessions (the browse tab) and buildSessionTurns (one session
// rendered as a chronological conversation, like the agent's own UI).
//
// The delta problem: wire-mode requests each carry the FULL growing message
// history (turn N resends turns 1..N-1), so replaying every call verbatim
// would repeat every message dozens of times. Each wire turn therefore shows
// only the messages ADDED since the previous wire call in the session. Mode B
// (otel) rows are already per-turn — their messages are always all new.
import type { Store } from "../core/store/store";
import { buildDetail, leakSpansFor, type DetailLeak } from "./detail";
import type { Message } from "../core/call";

export interface SessionRow {
  sessionId: string;
  agent?: string;
  provider?: string;
  model?: string; // most recent non-null model in the session
  firstTs: number;
  lastTs: number;
  calls: number;
  leaks: number; // leak events pinned to this session
  source: string; // 'wire' | 'otel' | 'mixed'
  title?: string; // earliest meaningful call summary — reads like a conversation title
}

// The browse tab: one row per session, newest activity first. Display query,
// non-core (rides Store.queryAll like the feed).
export function listSessions(store: Store, limit: number): SessionRow[] {
  return store
    .queryAll<Record<string, unknown>>(
      `SELECT e.session_id,
              MAX(e.agent) AS agent, MAX(e.provider) AS provider,
              (SELECT model FROM exchanges m WHERE m.session_id = e.session_id
                 AND m.model IS NOT NULL ORDER BY m.ts_request DESC LIMIT 1) AS model,
              MIN(e.ts_request) AS first_ts, MAX(e.ts_request) AS last_ts,
              COUNT(*) AS calls,
              COUNT(DISTINCT e.source) AS n_sources, MAX(e.source) AS one_source,
              (SELECT COUNT(*) FROM leak_events le WHERE le.session_id = e.session_id) AS leaks,
              -- The session's opening summary as a title. Skip buildSummary's
              -- placeholder sentinels so a tool-only / empty opening turn doesn't
              -- title the session; take the next real prompt instead. Summaries
              -- are already secret-scrubbed at capture, so no leak enters a title.
              (SELECT t.summary FROM exchanges t
                 WHERE t.session_id = e.session_id
                   AND t.summary IS NOT NULL AND t.summary != ''
                   AND t.summary NOT IN ('(no message content)', 'unparsed call (raw view available)')
                 ORDER BY t.ts_request ASC, t.id ASC LIMIT 1) AS title
       FROM exchanges e GROUP BY e.session_id
       ORDER BY last_ts DESC LIMIT ?`,
      [limit],
    )
    .map((r) => ({
      sessionId: r.session_id as string,
      agent: (r.agent as string) ?? undefined,
      provider: (r.provider as string) ?? undefined,
      model: (r.model as string) ?? undefined,
      firstTs: r.first_ts as number,
      lastTs: r.last_ts as number,
      calls: r.calls as number,
      leaks: (r.leaks as number) ?? 0,
      source: (r.n_sources as number) > 1 ? "mixed" : ((r.one_source as string) ?? "wire"),
      title: (r.title as string) ?? undefined,
    }));
}

export interface SessionHeadline { title?: string; agent?: string }

// Title + agent for a SET of sessions in one query — the leaks CLI groups its
// log by session and needs a headline per group (one query, not N). Same
// sentinel-skipping title pick as listSessions. Sessions with a leak event but
// no surviving exchanges (retention aged the calls out, 7d, before the event,
// 90d) simply don't appear in the map — the caller falls back to a placeholder.
export function sessionHeadlines(store: Store, sessionIds: string[]): Map<string, SessionHeadline> {
  const out = new Map<string, SessionHeadline>();
  if (sessionIds.length === 0) return out;
  const placeholders = sessionIds.map(() => "?").join(",");
  const rows = store.queryAll<Record<string, unknown>>(
    `SELECT e.session_id AS sid,
       (SELECT t.summary FROM exchanges t
          WHERE t.session_id = e.session_id
            AND t.summary IS NOT NULL AND t.summary != ''
            AND t.summary NOT IN ('(no message content)', 'unparsed call (raw view available)')
          ORDER BY t.ts_request ASC, t.id ASC LIMIT 1) AS title,
       (SELECT a.agent FROM exchanges a
          WHERE a.session_id = e.session_id AND a.agent IS NOT NULL
          ORDER BY a.ts_request ASC LIMIT 1) AS agent
     FROM exchanges e
     WHERE e.session_id IN (${placeholders})
     GROUP BY e.session_id`,
    sessionIds,
  );
  for (const r of rows) {
    out.set(r.sid as string, {
      title: (r.title as string) ?? undefined,
      agent: (r.agent as string) ?? undefined,
    });
  }
  return out;
}

export interface SessionTurn {
  id: string; // call id — the transcript links each turn back to its call
  tsRequest: number;
  model?: string;
  source: string;
  status?: number;
  messages: Message[]; // only what this turn ADDED (see delta note above)
  responseText: string | null;
  leaks: DetailLeak[];
}

export interface SessionView {
  sessionId: string;
  system: string | null; // shown once, from the first call that carries one
  turns: SessionTurn[];
  truncated: boolean; // true when the session has more calls than the cap
}

// One session as a conversation. Reuses buildDetail per call so the transcript
// shows the same parsed messages/response/leak highlights as the detail view.
export function buildSessionTurns(store: Store, sessionId: string, cap = 200): SessionView {
  const ids = store.queryAll<{ id: string }>(
    `SELECT id FROM exchanges WHERE session_id = ? ORDER BY ts_request ASC, id ASC LIMIT ?`,
    [sessionId, cap + 1],
  );
  const truncated = ids.length > cap;
  const turns: SessionTurn[] = [];
  let system: string | null = null;
  let prevWire: Message[] = [];
  for (const { id } of ids.slice(0, cap)) {
    const call = store.getCall(id);
    if (!call) continue;
    const d = buildDetail(call, leakSpansFor(store, id));
    system ??= d.system;
    let messages = d.messages;
    if (d.source === "otel" && messages.length === 0 && d.requestRaw) {
      // Legacy Mode B rows (captured before display_messages existed) still
      // have their scan text — show it as one block rather than an empty turn.
      // Labeled by what the content IS (the request: prompt + tool inputs);
      // provenance ("self-reported") is the session/turn chip's job, not this.
      messages = [{ role: "request", content: d.requestRaw }];
    }
    if (d.source === "wire") {
      // Show only the tail this call added on top of the previous wire call's
      // history. Guard against a shrunk/reshaped history (compaction, branch,
      // retry): if the recorded prefix doesn't actually match, fall back to
      // the newest message rather than mis-attributing old ones as new.
      if (messages.length > prevWire.length && sameHistoryPrefix(messages, prevWire)) {
        messages = messages.slice(prevWire.length);
      } else if (messages.length > 0) {
        messages = messages.slice(-1);
      }
      // Only advance the baseline on a turn that actually parsed. A truncated /
      // unparseable wire body yields 0 messages; clobbering prevWire with [] would
      // make the NEXT turn re-show its whole history as new (the repetition this
      // delta exists to kill). Keep the last good history as the diff base.
      if (d.messages.length > 0) prevWire = d.messages;
    }
    turns.push({
      id: d.id,
      tsRequest: d.tsRequest,
      model: d.model,
      source: d.source,
      status: d.status,
      messages,
      responseText: d.responseText,
      leaks: d.leaks,
    });
  }
  return { sessionId, system, turns, truncated };
}

// Cheap prefix check: same roles + same content lengths. Full string compares
// over a 200-call session would be O(history²) bytes; role+length catches the
// real mismatch cases (compaction rewrote history, branch, different session
// glued by the resolver) without that cost.
function sameHistoryPrefix(cur: Message[], prev: Message[]): boolean {
  for (let i = 0; i < prev.length; i++) {
    const a = cur[i];
    const b = prev[i];
    if (!a || a.role !== b!.role) return false;
    const al = typeof a.content === "string" ? a.content.length : JSON.stringify(a.content)?.length;
    const bl = typeof b!.content === "string" ? b!.content.length : JSON.stringify(b!.content)?.length;
    if (al !== bl) return false;
  }
  return true;
}
