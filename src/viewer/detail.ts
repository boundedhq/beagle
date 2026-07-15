// Viewer detail assembly (non-core): turns a stored CallRecord + its leak
// spans into the shape the dashboard renders — reassembled response text
// (UI fix 1), structured request messages, and the exact secret strings to
// highlight inline (UI fix 2, R7). Reuses the format parsers.
import type { CallRecord, Store } from "../core/store/store";
import { detectFormat, parseRequest, parseResponse } from "../parsers/parsers";
import type { Message } from "../core/call";

export interface LeakSpan {
  start: number;
  end: number;
  secretType: string;
  tier: string;
}

// Secret spans for one call (R7 inline highlight). Non-core display query.
export function leakSpansFor(store: Store, callId: string): LeakSpan[] {
  return store
    .queryAll<Record<string, unknown>>(
      `SELECT lo.span_start AS s, lo.span_end AS e, le.secret_type AS t, le.confidence_tier AS tier
       FROM leak_occurrences lo JOIN leak_events le ON le.id = lo.event_id
       WHERE lo.exchange_id = ? AND lo.span_start IS NOT NULL AND lo.span_end IS NOT NULL`,
      [callId],
    )
    .map((r) => ({
      start: r.s as number,
      end: r.e as number,
      secretType: r.t as string,
      tier: r.tier as string,
    }));
}

export interface DetailLeak {
  value: string; // the exact string to highlight wherever it appears
  secretType: string;
  tier: string;
}

export interface CallDetail {
  id: string;
  agent?: string;
  provider?: string;
  model?: string;
  endpoint?: string;
  sessionId: string;
  sessionTier: string;
  summary?: string;
  tsRequest: number;
  status?: number;
  tokensIn?: number;
  tokensOut?: number;
  bytesReq?: number;
  bytesResp?: number;
  scanState: string;
  captureState: string;
  source: string;
  system: string | null;
  messages: Message[];
  responseText: string | null; // reassembled (SSE or JSON), null if unparseable
  requestRaw: string;
  responseRaw: string;
  sseRaw: string | null;
  leaks: DetailLeak[];
}

const REDACTED_RE = /\[REDACTED:[^\]]+\]/g;

export function buildDetail(call: CallRecord, spans: LeakSpan[]): CallDetail {
  const dec = new TextDecoder("utf-8", { fatal: false });
  const requestRaw = call.requestBody ? dec.decode(call.requestBody) : "";
  const responseRaw = call.responseBody ? dec.decode(call.responseBody) : "";
  const sseRaw = call.sseRaw ? dec.decode(call.sseRaw) : null;
  const format = detectFormat(call.endpoint ?? "");

  const parsedReq = call.requestBody ? parseRequest(format, call.requestBody) : null;
  // Reassemble from the decoded body; fall back to the raw SSE for streamed
  // responses whose decoded body is the event stream.
  const parsedResp =
    call.responseBody ? parseResponse(format, call.responseBody)
    : call.sseRaw ? parseResponse(format, call.sseRaw)
    : null;

  return {
    id: call.id,
    agent: call.agent,
    provider: call.provider,
    model: call.model,
    endpoint: call.endpoint,
    sessionId: call.sessionId,
    sessionTier: call.sessionTier,
    summary: call.summary,
    tsRequest: call.tsRequest,
    status: call.status,
    tokensIn: call.tokensIn,
    tokensOut: call.tokensOut,
    bytesReq: call.bytesReq,
    bytesResp: call.bytesResp,
    scanState: call.scanState,
    captureState: call.captureState,
    source: call.source,
    system: parsedReq?.system ?? null,
    messages: parsedReq?.messages ?? [],
    responseText: parsedResp?.text ?? null,
    requestRaw,
    responseRaw,
    sseRaw,
    leaks: extractLeaks(requestRaw, spans, call.redacted ?? false),
  };
}

function extractLeaks(requestText: string, spans: LeakSpan[], redacted: boolean): DetailLeak[] {
  // A redacted body no longer holds the secret at the recorded offsets — the
  // placeholders ARE the markers, so highlight those instead. Driven by the
  // stored redaction flag, not a string sniff (which could false-match a body
  // that legitimately contains the literal "[REDACTED:").
  if (redacted) {
    const seen = new Set<string>();
    const out: DetailLeak[] = [];
    for (const m of requestText.matchAll(REDACTED_RE)) {
      if (seen.has(m[0])) continue;
      seen.add(m[0]);
      const type = m[0].split(":")[1] ?? "secret";
      out.push({ value: m[0], secretType: type, tier: "structured" });
    }
    return out;
  }
  // Normal body: slice each span to recover the secret value; de-dup by value.
  const byValue = new Map<string, DetailLeak>();
  for (const s of spans) {
    if (s.start < 0 || s.end > requestText.length || s.end <= s.start) continue;
    const value = requestText.slice(s.start, s.end);
    if (!value || byValue.has(value)) continue;
    byValue.set(value, { value, secretType: s.secretType, tier: s.tier });
  }
  return [...byValue.values()];
}
