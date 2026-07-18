// Viewer detail assembly (non-core): turns a stored CallRecord + its leak
// spans into the shape the dashboard renders — reassembled response text
// (UI fix 1), structured request messages, and the exact secret strings to
// highlight inline (UI fix 2, R7). Reuses the format parsers.
import type { CallRecord, Store } from "../core/store/store";
import {
  detectFormat, extractActions, parseRequest, parseResponse, sanitizeTool,
  type DisplayMessage, type ToolAction,
} from "../parsers/parsers";

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

// Whether/what this call leaked, from the leak EVENTS — the authoritative
// answer, independent of highlight spans (a v1-era occurrence has NULL spans;
// its call still leaked and must never read as clean). Non-core display query.
export function leakTypesFor(store: Store, callId: string): Array<{ secretType: string; tier: string }> {
  return store
    .queryAll<Record<string, unknown>>(
      `SELECT DISTINCT le.secret_type AS t, le.confidence_tier AS tier
       FROM leak_occurrences lo JOIN leak_events le ON le.id = lo.event_id
       WHERE lo.exchange_id = ?`,
      [callId],
    )
    .map((r) => ({ secretType: r.t as string, tier: r.tier as string }));
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
  messages: DisplayMessage[];
  responseText: string | null; // reassembled (SSE or JSON), null if unparseable
  /** Tool calls the model made in THIS response — "what was sent back" beyond
   *  text. Display-only: response bytes are not request-scanned (R7 note). */
  responseCalls: ToolAction[];
  /** Index into messages where this request's NEW content starts (server-side
   *  diff vs the previous wire call), or null when no truthful claim exists
   *  (first call, purged/unparseable predecessors, rewritten history, Mode B). */
  newFrom: number | null;
  /** Leaks detected on the NEXT request — where a secret inside this
   *  response's tool calls actually gets scanned. Display highlighting only. */
  responseLeaks: DetailLeak[];
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
    // Mode B bodies are scan text, not provider JSON — their structure rides
    // the persisted display_messages instead, and the stored response body IS
    // the response text (the mapper wrote it that way).
    messages: parsedReq?.messages ?? call.displayMessages ?? [],
    responseText:
      parsedResp?.text ?? (call.source === "otel" && responseRaw ? responseRaw : null),
    // Mode B bodies are plain text — extractActions parses nothing there and
    // returns [], so the section simply doesn't render for self-reports.
    // The tool name becomes a card HEADER label — sanitize at this boundary
    // (same rule every other header path applies); hostile names render as
    // the generic "tool", their args still fully visible in the body.
    responseCalls: (call.responseBody
      ? extractActions(format, call.responseBody)
      : call.sseRaw
        ? extractActions(format, call.sseRaw)
        : []
    ).map((a) => ({ ...a, tool: sanitizeTool(a.tool) ?? "tool" })),
    newFrom: null, // filled by the /api/call route (needs the previous call)
    responseLeaks: [], // filled by the route (needs the next call)
    requestRaw,
    responseRaw,
    sseRaw,
    leaks: extractLeaks(requestRaw, spans, call.redacted ?? false),
  };
}

// Just the parsed request messages — same result as buildDetail(call).messages,
// but without decoding/parsing the RESPONSE. The calls-detail delta walk-back
// diffs against previous calls and needs only this; a full buildDetail per
// walked-back call would re-parse each (100KB+) response for nothing.
export function detailMessages(call: CallRecord): DisplayMessage[] {
  const format = detectFormat(call.endpoint ?? "");
  return (
    (call.requestBody ? parseRequest(format, call.requestBody)?.messages : undefined) ??
    call.displayMessages ??
    []
  );
}

// Just the request-side leaks — same result as buildDetail(call, spans).leaks,
// without any response work. Used to surface the NEXT call's leaks on a detail
// (R7 backward highlight) without building its whole CallDetail.
export function detailLeaks(call: CallRecord, spans: LeakSpan[]): DetailLeak[] {
  const requestRaw = call.requestBody ? new TextDecoder("utf-8", { fatal: false }).decode(call.requestBody) : "";
  return extractLeaks(requestRaw, spans, call.redacted ?? false);
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
