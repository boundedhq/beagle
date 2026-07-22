// Viewer feed projection (non-core): the dashboard's Layer-0 row shape. Kept
// out of the core Store so display queries don't count against the R9
// security-path budget — reads a read-only handle via Store.queryAll.
import type { Store } from "../core/store/store";

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
