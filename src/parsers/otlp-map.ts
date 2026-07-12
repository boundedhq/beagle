// OTLP GenAI mapping (design §6.2, Mode B). Claude Code's OTel export (with
// content flags on) → canonical Call. Marked source='otel' → the
// agent-reported badge (R7): this is the agent's self-report, not wire bytes.
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
  for (const a of attrs ?? []) m.set(a.key, a.value);
  return m;
}

function str(v: AttrValue | undefined): string | undefined {
  return v?.stringValue;
}

// OTLP/JSON encodes int64 as a STRING; also accept doubleValue as a fallback.
function int(v: AttrValue | undefined): number | undefined {
  if (v === undefined) return undefined;
  const raw = v.intValue ?? v.doubleValue;
  if (raw === undefined) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

/** First present of several attribute keys — accommodates GenAI semconv drift
 *  (input_tokens vs prompt_tokens) without guessing which Claude Code emits. */
function firstInt(a: Map<string, AttrValue>, keys: string[]): number | undefined {
  for (const k of keys) {
    const n = int(a.get(k));
    if (n !== undefined) return n;
  }
  return undefined;
}

// gen_ai.prompt may be a plain string OR a JSON-encoded message array (the
// content flags can serialize the whole message list). Flatten either into
// scannable text so a secret in any message is detected.
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

interface OtelRecord {
  attributes?: Array<{ key: string; value: AttrValue }>;
  timeUnixNano?: string | number;
  startTimeUnixNano?: string | number;
}

function recordToCall(rec: OtelRecord, ctx: OtlpContext): OtelCall | null {
  const a = attrMap(rec.attributes);
  // Only inference records carry prompt/completion content.
  if (!a.has("gen_ai.prompt") && !a.has("gen_ai.completion")) return null;
  const promptRaw = str(a.get("gen_ai.prompt")) ?? "";
  // The scanner reads bodyBytes: it must see the RAW serialized prompt so a
  // secret buried in a nested block (e.g. a tool_result's content) is still
  // caught — flattening is lossy and is used only for the readable messages[].
  const promptDisplay = promptRaw ? flattenPromptText(promptRaw) : "";
  const completion = str(a.get("gen_ai.completion")) ?? "";
  const tsSource = rec.timeUnixNano ?? rec.startTimeUnixNano;
  const tsNano = tsSource !== undefined ? Number(tsSource) : Date.now() * 1e6;
  const ts = Number.isFinite(tsNano) ? Math.floor(tsNano / 1e6) : Date.now();
  return {
    id: ulid(ts),
    runId: str(a.get("beagle.run_token")) ?? "otel",
    source: "otel",
    agent: ctx.agent,
    provider: str(a.get("gen_ai.system")) ?? ctx.provider,
    model: str(a.get("gen_ai.response.model")) ?? str(a.get("gen_ai.request.model")),
    endpoint: "otel:gen_ai.client.inference",
    request: {
      bodyBytes: new TextEncoder().encode(promptRaw),
      messages: promptDisplay ? [{ role: "user", content: promptDisplay }] : [],
    },
    response: {
      text: completion,
      bodyBytes: new TextEncoder().encode(completion),
    },
    meta: {
      tsRequest: ts,
      tsResponse: ts,
      tokensIn: firstInt(a, ["gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens"]),
      tokensOut: firstInt(a, ["gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens"]),
    },
    convId: str(a.get("session.id")),
    runToken: str(a.get("beagle.run_token")),
  };
}

// Accepts OTLP logs (resourceLogs/scopeLogs/logRecords) AND spans
// (resourceSpans/scopeSpans/spans) — Claude Code's GenAI export may use either
// depending on version. Malformed input degrades to [] (R3).
export function mapOtlpLogsToCalls(payload: unknown, ctx: OtlpContext): OtelCall[] {
  const out: OtelCall[] = [];
  try {
    const p = payload as {
      resourceLogs?: Array<Record<string, any>>;
      resourceSpans?: Array<Record<string, any>>;
    };
    for (const rl of p?.resourceLogs ?? []) {
      for (const sl of rl.scopeLogs ?? []) {
        for (const rec of sl.logRecords ?? []) {
          const call = recordToCall(rec, ctx);
          if (call) out.push(call);
        }
      }
    }
    for (const rs of p?.resourceSpans ?? []) {
      for (const ss of rs.scopeSpans ?? []) {
        for (const span of ss.spans ?? []) {
          const call = recordToCall(span, ctx);
          if (call) out.push(call);
        }
      }
    }
  } catch {
    return [];
  }
  return out;
}

// Vendor-shipped knobs only (R2 bright line): env vars, never patching.
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
    // is seconds, not the default tens of seconds.
    OTEL_BLRP_SCHEDULE_DELAY: "1000",
    OTEL_EXPORTER_OTLP_HEADERS: `x-beagle-run=${runToken}`,
  };
}
