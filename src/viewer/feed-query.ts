// Viewer feed projection (non-core): the dashboard's Layer-0 row shape. Kept
// out of the core Store so display queries don't count against the R9
// security-path budget — reads a read-only handle via Store.queryAll.
import { escapeLike, type Store } from "../core/store/store";
import { detailLeaks, leakSpansFor, type DetailLeak } from "./detail";

export interface LeakEvent {
  id: string;
  fingerprint: string;
  sessionId: string;
  detector: string;
  secretType: string;
  severity: string;
  confidenceTier: string;
  destination: string;
  occurrences: number;
  firstTs: number;
  lastTs: number;
  firstCall: string | null;
}

// The leak log (CLI `leaks` + viewer /api/leaks). Display query, non-core.
export function listLeakEvents(store: Store): LeakEvent[] {
  return store
    .queryAll<Record<string, unknown>>(
      `SELECT id, fingerprint, session_id, detector, secret_type, severity,
              confidence_tier, destination, occurrences, first_ts, last_ts, first_exchange
       FROM leak_events ORDER BY first_ts`,
    )
    .map((r) => ({
      id: r.id as string,
      fingerprint: r.fingerprint as string,
      sessionId: r.session_id as string,
      detector: r.detector as string,
      secretType: r.secret_type as string,
      severity: r.severity as string,
      confidenceTier: r.confidence_tier as string,
      destination: r.destination as string,
      occurrences: r.occurrences as number,
      firstTs: r.first_ts as number,
      lastTs: r.last_ts as number,
      firstCall: (r.first_exchange as string) ?? null,
    }));
}

export interface FeedRow {
  id: string;
  sessionId: string;
  agent?: string;
  provider?: string;
  model?: string;
  tsRequest: number;
  status?: number;
  summary?: string;
  scanState: string;
  captureState: string;
  sessionTier: string;
  source: string;
  hasLeak: boolean;
}

export function listCalls(store: Store, limit: number): FeedRow[] {
  // Mode B tool rows (codex tool_result, claude hook output) fold under their
  // turn in the transcript, and the feed reads one line per turn the same way
  // a wire session does — so leak-FREE tool rows are hidden here. A row that
  // leaked ALWAYS shows: hiding a leak-bearing call from the feed would be
  // Beagle hiding a leak. The rows themselves are untouched — still captured,
  // scanned, in the transcript (folded or standalone) and reachable by id.
  return store
    .queryAll<Record<string, unknown>>(
      `SELECT e.id, e.session_id, e.agent, e.provider, e.model, e.ts_request,
              e.status, e.summary,
              e.scan_state, e.capture_state, e.session_tier, e.source,
              EXISTS(SELECT 1 FROM leak_occurrences lo WHERE lo.exchange_id = e.id) AS has_leak
       FROM exchanges e
       WHERE (e.endpoint IS NULL
              OR (e.endpoint NOT LIKE 'otel:tool_output:%' AND e.endpoint NOT LIKE 'otel:codex:tool_result:%'))
          OR EXISTS(SELECT 1 FROM leak_occurrences lo WHERE lo.exchange_id = e.id)
       ORDER BY e.ts_request DESC LIMIT ?`,
      [limit],
    )
    .map((r) => ({
      id: r.id as string,
      sessionId: r.session_id as string,
      agent: (r.agent as string) ?? undefined,
      provider: (r.provider as string) ?? undefined,
      model: (r.model as string) ?? undefined,
      tsRequest: r.ts_request as number,
      status: (r.status as number) ?? undefined,
      summary: (r.summary as string) ?? undefined,
      scanState: r.scan_state as string,
      captureState: r.capture_state as string,
      sessionTier: r.session_tier as string,
      source: r.source as string,
      hasLeak: Boolean(r.has_leak),
    }));
}

// ---- literal search over what was SENT --------------------------------------
// The dashboard's search view: each hit ships with real context snippets, so
// the result panel can show WHERE the term appeared without a second fetch —
// and without depending on the feed's 500-row window at all.

const SNIPPET_PRE = 60; // context chars kept before a match
const SNIPPET_POST = 100; // and after (answers lead the question that follows)
const MAX_SNIPPETS = 3;

export interface SearchSnippet {
  pre: string; // context before the match ("…"-prefixed when clipped)
  match: string; // the matched text as it appears in the content (original case)
  post: string; // context after ("…"-suffixed when clipped)
}

export interface SearchCall {
  callId: string;
  sessionId: string;
  tsRequest: number;
  agent?: string;
  model?: string;
  source: string;
  summary?: string;
  hasLeak: boolean;
  matchCount: number;
  snippets: SearchSnippet[];
  /** Detected secret values on this call (empty when clean), so snippets can
   *  red-mark them — R7 follows the content onto the search surface. */
  leaks: DetailLeak[];
}

// ASCII-only lowercase, length-preserving — the same case model as SQLite's
// LIKE, so offsets found on the folded copy slice the ORIGINAL text exactly
// (full Unicode folding can change length: "İ".toLowerCase() is two chars).
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

// Snippets are display projections: collapse whitespace runs so a match deep
// inside pretty-printed JSON still reads as one line in the results list.
const collapse = (s: string): string => s.replace(/\s+/g, " ");

function snip(
  content: string,
  term: string,
  leakValues: string[],
): { matchCount: number; snippets: SearchSnippet[] } {
  const hay = asciiLower(content);
  const needle = asciiLower(term);
  const snippets: SearchSnippet[] = [];
  let matchCount = 0;
  let windowEnd = -1;
  for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + needle.length)) {
    matchCount++;
    // A match inside the previous snippet's window is already on screen —
    // don't mint a near-duplicate snippet for it (the count still tells all).
    if (snippets.length >= MAX_SNIPPETS || i < windowEnd) continue;
    let start = Math.max(0, i - SNIPPET_PRE);
    let end = Math.min(content.length, i + needle.length + SNIPPET_POST);
    // Never bisect a detected secret at a window edge: a half-shown value
    // can't be red-marked (the client highlights by whole-value match), so a
    // straddled one widens the window instead. One pass per value — the
    // residual (a value straddling another value's extension) is vanishing,
    // and the row's leak chip + the expanded detail still carry it.
    for (const v of leakValues) {
      for (let j = content.indexOf(v); j !== -1 && j < end; j = content.indexOf(v, j + 1)) {
        if (j < start && j + v.length > start) start = j;
        if (j < end && j + v.length > end) end = j + v.length;
      }
    }
    windowEnd = end;
    snippets.push({
      pre: (start > 0 ? "…" : "") + collapse(content.slice(start, i)),
      match: collapse(content.slice(i, i + needle.length)),
      post: collapse(content.slice(i + needle.length, end)) + (end < content.length ? "…" : ""),
    });
  }
  return { matchCount, snippets };
}

// Literal, case-insensitive (ASCII, like LIKE) search over the outbound index.
// Newest first; one row over the cap is fetched purely to set `truncated`.
export function searchCalls(
  store: Store,
  term: string,
  limit = 200,
): { hits: SearchCall[]; truncated: boolean } {
  if (term === "") return { hits: [], truncated: false }; // '%%' matches every row
  const rows = store.queryAll<Record<string, unknown>>(
    `SELECT e.id, e.session_id, e.agent, e.model, e.ts_request, e.summary, e.source,
            f.content,
            EXISTS(SELECT 1 FROM leak_occurrences lo WHERE lo.exchange_id = e.id) AS has_leak
     FROM exchanges_fts f JOIN exchanges e ON e.id = f.exchange_id
     WHERE f.content LIKE ? ESCAPE '\\'
     ORDER BY e.ts_request DESC, e.id DESC LIMIT ?`,
    ["%" + escapeLike(term) + "%", limit + 1],
  );
  const truncated = rows.length > limit;
  const hits = rows.slice(0, limit).map((r) => {
    const id = r.id as string;
    // Leak values ride only on flagged rows (rare), where they cost one call
    // fetch each — the price of never rendering a detected secret unmarked.
    const call = r.has_leak ? store.getCall(id) : null;
    const leaks = call ? detailLeaks(call, leakSpansFor(store, id)) : [];
    const { matchCount, snippets } = snip(
      String(r.content ?? ""),
      term,
      leaks.map((l) => l.value),
    );
    return {
      callId: id,
      sessionId: r.session_id as string,
      tsRequest: r.ts_request as number,
      agent: (r.agent as string) ?? undefined,
      model: (r.model as string) ?? undefined,
      source: r.source as string,
      summary: (r.summary as string) ?? undefined,
      hasLeak: Boolean(r.has_leak),
      matchCount,
      snippets,
      leaks,
    };
  });
  return { hits, truncated };
}

// Whole-store totals for the header stat cards. The feed above is a 500-row
// window; these count everything, so the headline numbers don't pin at the
// window size or jitter when the feed refetches. Display query, non-core.
export interface FeedStats {
  calls: number;
  sessions: number;
  agents: number;
}

export function feedStats(store: Store): FeedStats {
  const r = store.queryAll<Record<string, unknown>>(
    `SELECT COUNT(*) AS calls,
            COUNT(DISTINCT session_id) AS sessions,
            COUNT(DISTINCT agent) AS agents
     FROM exchanges`,
  )[0];
  return {
    calls: (r?.calls as number) ?? 0,
    sessions: (r?.sessions as number) ?? 0,
    agents: (r?.agents as number) ?? 0,
  };
}
