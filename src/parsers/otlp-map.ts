// OTLP → canonical Call mapping (design §6.2, Mode B). Claude Code's OTel
// export → canonical Call, marked source='otel' → the agent-reported badge
// (R7): this is the agent's self-report, not wire bytes.
//
// Real schema (verified against Claude Code 2.1.193 in the Phase-0 spike —
// docs/mode-b-spike.md; scope "com.anthropic.claude_code.events"). This is NOT
// the OpenTelemetry GenAI semconv — there is no `gen_ai.prompt`/`gen_ai.
// completion`. Instead one user turn is SPLIT across several event log records
// that share (session.id, prompt.id):
//   event.name=user_prompt        → prompt (verbatim), prompt.id, session.id
//   event.name=tool_result        → tool_input (verbatim), tool_name — but NO
//                                    result content, only *_size_bytes
//   event.name=api_request        → model, input_tokens, output_tokens
//   event.name=assistant_response → response (verbatim), model
// We reassemble those into one Call per turn. request.bodyBytes carries the
// OUTBOUND leak surface the daemon actually scans: the user prompt plus every
// tool INPUT (bash commands, file paths, write payloads). Tool RESULT content
// is not exported by the client, so a secret present only in a tool's output
// is invisible to Mode B — the honest cost of the agent-reported badge, stated
// in `status`/docs.
import type { Call } from "../core/call";
import { ulid } from "../core/store/ulid";

interface OtlpContext {
  agent: string;
  provider: string;
}

interface AttrValue {
  stringValue?: string;
  intValue?: string | number;
  doubleValue?: number;
  boolValue?: boolean;
}

export interface OtelCall extends Call {
  convId?: string;
  runToken?: string;
}

function attrMap(attrs: Array<{ key: string; value: AttrValue }> | undefined): Map<string, AttrValue> {
  const m = new Map<string, AttrValue>();
  // Array-safe: a record whose `attributes` is an object (malformed) must not
  // throw — it would take the whole batch's scanning down with it.
  for (const a of Array.isArray(attrs) ? attrs : []) m.set(a.key, a.value);
  return m;
}

function str(v: AttrValue | undefined): string | undefined {
  return v?.stringValue;
}

// OTLP/JSON may encode int64 as a STRING or a number; also accept doubleValue.
function int(v: AttrValue | undefined): number | undefined {
  if (v === undefined) return undefined;
  const raw = v.intValue ?? v.doubleValue;
  if (raw === undefined) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

function addInt(a: number | undefined, b: number | undefined): number | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return a + b;
}

function nano(v: string | number | undefined): number | undefined {
  if (v === undefined || v === null) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

// A user prompt may be a plain string OR a JSON-encoded message array (long /
// resumed conversations serialize the whole list). Flatten either into
// readable text for the display messages[]; the scanner reads the raw string
// separately so nothing is lost.
function flattenPromptText(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      const items = Array.isArray(parsed) ? parsed : [parsed];
      const parts = items.map((m: Record<string, unknown>) => {
        const c = m?.content;
        if (typeof c === "string") return c;
        if (Array.isArray(c)) return c.map((b: Record<string, unknown>) => (typeof b?.text === "string" ? b.text : "")).join("");
        return typeof m === "string" ? m : "";
      });
      return parts.join("\n");
    } catch {
      /* not JSON after all */
    }
  }
  return raw;
}

interface Turn {
  order: number; // first-seen index, for stable output ordering
  sessionId?: string;
  tsNano?: number;
  prompt?: string;
  toolInputs: string[];
  response?: string;
  model?: string;
  tokensIn?: number;
  tokensOut?: number;
}

interface OtlpRecord {
  attributes?: Array<{ key: string; value: AttrValue }>;
  timeUnixNano?: string | number;
  startTimeUnixNano?: string | number;
}

// Only these event types carry content we keep; everything else Claude Code
// emits (hook_*, mcp_server_connection, plugin_loaded, tool_decision,
// api_refusal, …) is operational noise with no leak surface.
const CONTENT_EVENTS = new Set(["user_prompt", "tool_result", "assistant_response", "api_request"]);

// Every level is array-guarded: a non-array container (object instead of []) is
// treated as empty rather than throwing and discarding the whole payload.
const arr = <T>(x: unknown): T[] => (Array.isArray(x) ? (x as T[]) : []);

function collectRecords(payload: unknown): OtlpRecord[] {
  const out: OtlpRecord[] = [];
  const p = payload as { resourceLogs?: unknown; resourceSpans?: unknown };
  for (const rl of arr<Record<string, unknown>>(p?.resourceLogs)) {
    for (const sl of arr<Record<string, unknown>>(rl?.scopeLogs)) {
      for (const rec of arr<OtlpRecord>(sl?.logRecords)) out.push(rec);
    }
  }
  // Spans kept as a forward-compat fallback: if a future client emits GenAI
  // spans instead of events, they flow through the same accumulator.
  for (const rs of arr<Record<string, unknown>>(p?.resourceSpans)) {
    for (const ss of arr<Record<string, unknown>>(rs?.scopeSpans)) {
      for (const span of arr<OtlpRecord>(ss?.spans)) out.push(span);
    }
  }
  return out;
}

function buildTurnCall(t: Turn, ctx: OtlpContext): OtelCall {
  const ts = t.tsNano !== undefined ? Math.floor(t.tsNano / 1e6) : Date.now();
  // The scanned body is the outbound leak surface: the prompt + every tool
  // input, raw, so a secret in any of them is caught. The response is inbound
  // (not a leak vector) and rides response.text for display only.
  const scanText = [t.prompt ?? "", ...t.toolInputs].filter(Boolean).join("\n");
  const promptDisplay = t.prompt ? flattenPromptText(t.prompt) : "";
  return {
    id: ulid(ts),
    runId: "otel",
    source: "otel",
    agent: ctx.agent,
    provider: ctx.provider,
    model: t.model,
    endpoint: "otel:claude_code.turn",
    request: {
      bodyBytes: new TextEncoder().encode(scanText),
      messages: promptDisplay ? [{ role: "user", content: promptDisplay }] : [],
    },
    response: {
      text: t.response ?? "",
      bodyBytes: new TextEncoder().encode(t.response ?? ""),
    },
    meta: { tsRequest: ts, tsResponse: ts, tokensIn: t.tokensIn, tokensOut: t.tokensOut },
    convId: t.sessionId,
  };
}

// Reassemble Claude Code's split event stream into one Call per user turn.
// Malformed input degrades to [] (R3). Correlation is per DELIVERED PAYLOAD:
// a turn whose events span multiple OTLP POST batches yields a partial Call
// per batch (prompt-only, then response-only) — the scanner + fingerprint
// dedup make that harmless (all content is scanned, no double alert).
export function mapOtlpLogsToCalls(payload: unknown, ctx: OtlpContext): OtelCall[] {
  try {
    const turns = new Map<string, Turn>();
    let idx = 0;
    for (const rec of collectRecords(payload)) {
      const i = idx++;
      // Per-record isolation: one malformed record is SKIPPED, never allowed to
      // discard the scanning of valid secret-bearing records in the same batch.
      try {
        const a = attrMap(rec.attributes);
        const name = str(a.get("event.name"));
        if (!name || !CONTENT_EVENTS.has(name)) continue;
        const sessionId = str(a.get("session.id"));
        const promptId = str(a.get("prompt.id"));
        // Group by turn. A content record with no prompt.id still gets its own
        // turn so nothing scannable is silently dropped.
        const key = promptId ? `${sessionId ?? ""}::${promptId}` : `${sessionId ?? ""}::orphan-${i}`;
        let turn = turns.get(key);
        if (!turn) {
          turn = { order: i, sessionId, toolInputs: [] };
          turns.set(key, turn);
        }
        const ns = nano(rec.timeUnixNano ?? rec.startTimeUnixNano);
        if (ns !== undefined && (turn.tsNano === undefined || ns < turn.tsNano)) turn.tsNano = ns;
        if (name === "user_prompt") {
          turn.prompt = str(a.get("prompt")) ?? turn.prompt;
        } else if (name === "tool_result") {
          const ti = str(a.get("tool_input"));
          if (ti) turn.toolInputs.push(ti);
        } else if (name === "assistant_response") {
          turn.response = str(a.get("response")) ?? turn.response;
          // The model on assistant_response is authoritative — it's the model
          // that actually produced the reply. It wins over any earlier
          // api_request model (a refused server-fallback attempt would set a
          // different, wrong model first).
          const m = str(a.get("model"));
          if (m) turn.model = m;
        } else if (name === "api_request") {
          turn.model ??= str(a.get("model")); // fallback only if no response model yet
          turn.tokensIn = addInt(turn.tokensIn, int(a.get("input_tokens")));
          turn.tokensOut = addInt(turn.tokensOut, int(a.get("output_tokens")));
        }
      } catch {
        /* skip a single malformed record; the rest of the batch still maps */
      }
    }
    return [...turns.values()]
      .filter((t) => t.prompt || t.response || t.toolInputs.length > 0)
      .sort((x, y) => x.order - y.order)
      .map((t) => buildTurnCall(t, ctx));
  } catch {
    return [];
  }
}

// ---- tool-output capture via a PostToolUse hook (Mode B gap fix) ----
//
// Claude Code's OTel export omits tool RESULT content — only the size — so a
// secret that appears ONLY in a tool's output (e.g. the body of a file the
// agent reads) escapes Mode B. Its PostToolUse hook, however, receives that
// output. `beagle run claude --telemetry` registers a Beagle-owned hook (via
// the vendor `--settings` flag — additive, verified not to clobber the user's
// own hooks) that forwards each tool result to the loopback receiver. This
// maps that hook payload into a scannable Call.

interface HookPayload {
  session_id?: string;
  tool_name?: string;
  tool_input?: unknown;
  tool_response?: unknown;
}

const asText = (v: unknown): string =>
  v === undefined || v === null ? "" : typeof v === "string" ? v : JSON.stringify(v);

/** Map a Claude Code PostToolUse hook payload into a Call whose scanned body
 *  is the tool's input AND output. Its own row (a tool call is a distinct unit
 *  of captured data), chained to the turn's session via session_id. Returns
 *  null when there's nothing to scan or the payload is malformed. */
export function mapHookToCall(payload: unknown, ctx: OtlpContext): OtelCall | null {
  try {
    if (typeof payload !== "object" || payload === null) return null;
    const p = payload as HookPayload;
    const toolName = typeof p.tool_name === "string" ? p.tool_name : "tool";
    const toolInput = asText(p.tool_input);
    const toolResponse = asText(p.tool_response);
    if (!toolInput && !toolResponse) return null; // nothing to scan
    const ts = Date.now();
    // The scanned surface: tool name + input + output, raw, so a secret in the
    // command OR its result is caught.
    const scanText = `${toolName}\n${toolInput}\n${toolResponse}`;
    return {
      id: ulid(ts),
      runId: "otel",
      source: "otel",
      agent: ctx.agent,
      provider: ctx.provider,
      endpoint: `otel:tool_output:${toolName}`,
      request: {
        bodyBytes: new TextEncoder().encode(scanText),
        messages: [{ role: "tool", content: `${toolName}: ${toolResponse.slice(0, 4000)}` }],
      },
      response: { text: "", bodyBytes: new Uint8Array() },
      meta: { tsRequest: ts, tsResponse: ts },
      convId: typeof p.session_id === "string" ? p.session_id : undefined,
    };
  } catch {
    return null;
  }
}

/** The additional settings passed to Claude Code via `--settings` to register
 *  the tool-output hook. No matcher → fires for every tool. */
export function buildHookSettings(command: string): Record<string, unknown> {
  return { hooks: { PostToolUse: [{ hooks: [{ type: "command", command }] }] } };
}

// Vendor-shipped knobs only (R2 bright line): env vars, never patching. All
// verified honored against Claude Code 2.1.193 in the Phase-0 spike; the
// content flags surface user prompts and tool INPUTS (not tool results — the
// hook above closes that gap).
export function buildOtelEnv(endpoint: string, runToken: string): Record<string, string> {
  return {
    CLAUDE_CODE_ENABLE_TELEMETRY: "1",
    OTEL_LOGS_EXPORTER: "otlp",
    OTEL_EXPORTER_OTLP_PROTOCOL: "http/json",
    OTEL_EXPORTER_OTLP_ENDPOINT: endpoint,
    OTEL_LOG_USER_PROMPTS: "1",
    OTEL_LOG_TOOL_DETAILS: "1",
    OTEL_LOG_TOOL_CONTENT: "1",
    // Batch delay down so the alert lag (Mode B is batched, not wire-instant)
    // is ~1s, not the default tens of seconds.
    OTEL_BLRP_SCHEDULE_DELAY: "1000",
    OTEL_EXPORTER_OTLP_HEADERS: `x-beagle-run=${runToken}`,
  };
}
