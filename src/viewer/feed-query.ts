// Viewer feed projection (non-core): the dashboard's Layer-0 row shape. Kept
// out of the core Store so display queries don't count against the R9
// security-path budget — reads a read-only handle via Store.queryAll.
import { escapeLike, type Store } from "../core/store/store";
import { leakValuesFor, type DetailLeak } from "./detail";

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
  // Every captured row stays in the feed. In particular, subscription tool
  // rows must not be optimistically prepended by SSE and then disappear on the
  // next refetch; the session projection uses those rows as Pi-like call
  // boundaries, and the feed is the stable raw-capture ledger beneath it.
  return store
    .queryAll<Record<string, unknown>>(
      `SELECT e.id, e.session_id, e.agent, e.provider, e.model, e.ts_request,
              e.status, e.summary,
              e.scan_state, e.capture_state, e.session_tier, e.source,
              EXISTS(SELECT 1 FROM leak_occurrences lo WHERE lo.exchange_id = e.id) AS has_leak
       FROM exchanges e
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
// Mirrors asciiLower in static/render-json.module.js: the client re-finds the
// term with ITS copy for the marks and fold-opens, so the two must fold
// identically — change both together, or a hit opens with its match hidden.
// (No shared import on purpose: the render module pulls in preact/htm, which
// has no place in the server's feed-projection graph.)
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
    // and the row's leak chip + the expanded detail still carry it. Two more
    // accepted residuals of the same shape, both still flagged by chip+detail:
    // a value holding a whitespace RUN (display collapse alters it), and a
    // value whose byte form differs between this PARSED search text and the
    // raw body the spans were cut from (an escaped-form secret) — value
    // equality can't bridge either.
    for (const v of leakValues) {
      // The loop guard re-reads `end` each pass, so an occurrence straddling
      // an already-extended end still widens it further; inside the body
      // j < end always holds, so only the far side needs testing.
      for (let j = content.indexOf(v); j !== -1 && j < end; j = content.indexOf(v, j + 1)) {
        if (j < start && j + v.length > start) start = j;
        if (j + v.length > end) end = j + v.length;
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
    // Leak values ride only on flagged rows, via a NARROW fetch (request body
    // + stored transcript) — the price of never rendering a detected secret
    // unmarked, without dragging every flagged row's response/sse payloads
    // through memory (the "searched for the leaked key itself" case flags
    // every hit at once).
    const leaks = r.has_leak ? leakValuesFor(store, id) : [];
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
