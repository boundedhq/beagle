// Viewer feed projection (non-core): the dashboard's Layer-0 row shape. Kept
// out of the core Store so display queries don't count against the R9
// security-path budget — reads a read-only handle via Store.queryAll.
import type { Store } from "../core/store/store";

export interface FeedRow {
  id: string;
  sessionId: string;
  agent?: string;
  provider?: string;
  model?: string;
  tsRequest: number;
  status?: number;
  tokensIn?: number;
  tokensOut?: number;
  bytesReq?: number;
  summary?: string;
  scanState: string;
  captureState: string;
  sessionTier: string;
  source: string;
  hasLeak: boolean;
}

export function listExchanges(store: Store, limit: number): FeedRow[] {
  return store
    .queryAll<Record<string, unknown>>(
      `SELECT e.id, e.session_id, e.agent, e.provider, e.model, e.ts_request,
              e.status, e.tokens_in, e.tokens_out, e.bytes_req, e.summary,
              e.scan_state, e.capture_state, e.session_tier, e.source,
              EXISTS(SELECT 1 FROM leak_occurrences lo WHERE lo.exchange_id = e.id) AS has_leak
       FROM exchanges e ORDER BY e.ts_request DESC LIMIT ?`,
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
      tokensIn: (r.tokens_in as number) ?? undefined,
      tokensOut: (r.tokens_out as number) ?? undefined,
      bytesReq: (r.bytes_req as number) ?? undefined,
      summary: (r.summary as string) ?? undefined,
      scanState: r.scan_state as string,
      captureState: r.capture_state as string,
      sessionTier: r.session_tier as string,
      source: r.source as string,
      hasLeak: Boolean(r.has_leak),
    }));
}
