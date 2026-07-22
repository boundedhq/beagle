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
  const stored = storedProjection(call);
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
    system: stored?.system ?? parsedReq?.system ?? null,
    // Mode B bodies are scan text, not provider JSON — their structure rides
    // the persisted display_messages instead, and the stored response body IS
    // the response text (the mapper wrote it that way). A stored projection
    // WINS over the re-parse: see storedProjection for why re-deriving would be
    // wrong wherever one exists.
    messages: stored?.messages ?? parsedReq?.messages ?? [],
    // Stored reply first, for the same reason `messages` prefers its stored
    // copy: the re-parse below REASSEMBLES a streamed answer, rebuilding a key
    // the provider split across frames that no single frame of the body holds.
    responseText:
      stored?.responseText ??
      parsedResp?.text ??
      (call.source === "otel" && responseRaw ? responseRaw : null),
    // Stored calls first, for the third time and the same reason: extractActions
    // JSON-PARSES the body, decoding escapes the scanner matched against, so a
    // key written `AKIA…` in those bytes matches no rule there — nothing is
    // spliced — and both `detail` and the re-serialized `args` rebuild it whole.
    // args especially: it is the card's body, so an unmasked one would win over
    // a masked detail beside it.
    // Mode B bodies are plain text — extractActions parses nothing there and
    // returns [], so the section simply doesn't render for self-reports.
    // The tool name becomes a card HEADER label — sanitize at this boundary
    // (same rule every other header path applies); hostile names render as
    // the generic "tool", their args still visible in the body.
    responseCalls: (
      stored?.responseCalls ??
      (call.responseBody
        ? extractActions(format, call.responseBody)
        : call.sseRaw
          ? extractActions(format, call.sseRaw)
          : [])
    ).map((a) => ({ ...a, tool: sanitizeTool(a.tool) ?? "tool" })),
    newFrom: null, // filled by the /api/call route (needs the previous call)
    responseLeaks: [], // filled by the route (needs the next call)
    requestRaw,
    responseRaw,
    sseRaw,
    leaks: extractLeaks(requestRaw, spans, call.redacted ?? false, storedText(call.displayMessages)),
  };
}

// The transcript a row PERSISTED, split back into its system prompt and its
// messages. It exists in exactly two cases, and in both, re-deriving from the
// stored body instead would be wrong:
//   - a Mode B row, whose body is scan text with no provider JSON to parse;
//   - a wire row whose derived scan masked text the body redaction could not
//     (a secret the display manufactures by joining content blocks is not in
//     the body to mask), so re-parsing rebuilds the very string that was
//     removed. See Daemon.captureCall.
// The wire writer always puts the system prompt at index 0 — empty string when
// the request had none — so lifting it back is unambiguous even for a body
// whose own messages carry a "system" role. Mode B rows never write one, and
// their roles are user/tool, so they fall through with system undefined.
// A wire row's REPLY rides the same array as a trailing kind:"response" entry —
// the writer's own marker, never a value the parsers produce — because the
// re-derive is wrong for it too: parseResponse REASSEMBLES a streamed answer,
// so a key the provider split across two text_delta frames is in no single
// frame of the stored body and re-parsing rebuilds it whole.
function storedProjection(
  call: CallRecord,
): {
  system?: string;
  messages: DisplayMessage[];
  responseText?: string;
  responseCalls?: ToolAction[];
} | null {
  let stored = call.displayMessages as DisplayMessage[] | undefined | null;
  if (!stored?.length) return null;
  // The reply's tool calls trail everything, in order (see Daemon.captureCall).
  // Taken as a block so a row that stored none is distinguishable from one whose
  // reply made none — both yield undefined and fall through to the re-parse.
  let responseCalls: ToolAction[] | undefined;
  const firstCall = stored.findIndex((m) => m.kind === "response-call");
  if (firstCall !== -1) {
    responseCalls = stored.slice(firstCall).map((m) => ({
      tool: m.tool ?? "tool",
      detail: m.detail || undefined,
      args: m.content || undefined,
      callId: m.callId,
    }));
    stored = stored.slice(0, firstCall);
    if (!stored.length) return { messages: [], responseCalls };
  }
  let responseText: string | undefined;
  if (stored[stored.length - 1]!.kind === "response") {
    responseText = stored[stored.length - 1]!.content;
    stored = stored.slice(0, -1);
    if (!stored.length) return { messages: [], responseText, responseCalls };
  }
  if (stored[0]!.role !== "system") return { messages: stored, responseText, responseCalls };
  return {
    system: stored[0]!.content || undefined,
    messages: stored.slice(1),
    responseText,
    responseCalls,
  };
}

// Every string a row stores as its own transcript, for placeholder discovery
// (extractLeaks). Empty for the rows that keep none.
//
// `detail` counts as much as `content`: it is redacted from its own offsets and
// so carries its own placeholder, whose hash is over the form found THERE — a
// detail decodes one escaping level further than the content beside it, so the
// two forms of one secret hash differently and finding only the content's would
// leave the detail's rendering unhighlighted (the case the redacted branch of
// extractLeaks exists for).
// Structural param (content + detail are all it reads): CallRecord's stored
// projection types `kind` looser than the parsers' DisplayMessage union, and
// both shapes must flow through here.
function storedText(messages: Array<{ content: string; detail?: string }> | undefined | null): string {
  return (messages ?? []).flatMap((m) => [m.content, m.detail ?? ""]).join("\n");
}

// Just the parsed request messages — same result as buildDetail(call).messages,
// but without decoding/parsing the RESPONSE. The calls-detail delta walk-back
// diffs against previous calls and needs only this; a full buildDetail per
// walked-back call would re-parse each (100KB+) response for nothing.
export function detailMessages(call: CallRecord): DisplayMessage[] {
  const format = detectFormat(call.endpoint ?? "");
  return (
    storedProjection(call)?.messages ??
    (call.requestBody ? parseRequest(format, call.requestBody)?.messages : undefined) ??
    []
  );
}

// Just the request-side leaks — same result as buildDetail(call, spans).leaks,
// without any response work. Used to surface the NEXT call's leaks on a detail
// (R7 backward highlight) without building its whole CallDetail.
export function detailLeaks(call: CallRecord, spans: LeakSpan[]): DetailLeak[] {
  const requestRaw = call.requestBody ? new TextDecoder("utf-8", { fatal: false }).decode(call.requestBody) : "";
  return extractLeaks(requestRaw, spans, call.redacted ?? false, storedText(call.displayMessages));
}

// The same leaks from a NARROW row fetch: request body + stored transcript +
// redaction flag — the three surfaces extractLeaks reads — WITHOUT getCall's
// response/sse payloads, which the search view was loading and discarding for
// every leak-bearing hit. Resilient per row: a corrupt display_messages JSON
// degrades to placeholder discovery over the body alone instead of throwing
// (one bad row must not take down the whole /api/search response).
export function leakValuesFor(store: Store, callId: string): DetailLeak[] {
  const r = store.queryAll<{ redacted: number | null; request_body: Uint8Array | null; display_messages: string | null }>(
    `SELECT e.redacted, p.request_body, p.display_messages
     FROM exchanges e LEFT JOIN payloads p ON p.exchange_id = e.id
     WHERE e.id = ?`,
    [callId],
  )[0];
  if (!r) return [];
  const requestRaw = r.request_body ? new TextDecoder("utf-8", { fatal: false }).decode(r.request_body) : "";
  let messages: DisplayMessage[] | null = null;
  if (r.display_messages) {
    try { messages = JSON.parse(r.display_messages) as DisplayMessage[]; } catch { /* body-only discovery */ }
  }
  return extractLeaks(requestRaw, leakSpansFor(store, callId), !!r.redacted, storedText(messages));
}

function extractLeaks(
  requestText: string,
  spans: LeakSpan[],
  redacted: boolean,
  transcript = "",
): DetailLeak[] {
  // A redacted body no longer holds the secret at the recorded offsets — the
  // placeholders ARE the markers, so highlight those instead. Driven by the
  // stored redaction flag, not a string sniff (which could false-match a body
  // that legitimately contains the literal "[REDACTED:").
  // The stored transcript is searched alongside the body, and ONLY here: a
  // derived-only redaction leaves its placeholder in the transcript and nothing
  // in the body, so without it the one surface that was masked would render
  // unhighlighted. The span branch below must never see it — those offsets
  // index the body alone.
  if (redacted) {
    const seen = new Set<string>();
    const out: DetailLeak[] = [];
    for (const m of `${requestText}\n${transcript}`.matchAll(REDACTED_RE)) {
      if (seen.has(m[0])) continue;
      seen.add(m[0]);
      // The emitted shape is "[REDACTED:type:shorthash]" (redact.ts) — the
      // type is the run between the opener and the NEXT colon-or-bracket, so
      // a hash-less legacy "[REDACTED:type]" parses clean too (split(":")[1]
      // alone kept its closing bracket and mislabeled the chip).
      const type = m[0].slice("[REDACTED:".length, -1).split(":")[0] || "secret";
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
