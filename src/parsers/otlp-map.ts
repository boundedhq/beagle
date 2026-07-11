// OTLP GenAI mapping (design §6.2, Mode B). Claude Code's OTel export (with
// content flags on) → canonical Exchange. Marked source='otel' → the
// agent-reported badge (R7): this is the agent's self-report, not wire bytes.
import type { Exchange } from "../core/exchange";
import { ulid } from "../core/store/ulid";

interface OtlpContext {
  agent: string;
  provider: string;
}

interface AttrValue {
  stringValue?: string;
  intValue?: string | number;
  boolValue?: boolean;
}

export interface OtelExchange extends Exchange {
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

function int(v: AttrValue | undefined): number | undefined {
  if (v?.intValue === undefined) return undefined;
  const n = Number(v.intValue);
  return Number.isFinite(n) ? n : undefined;
}

export function mapOtlpLogsToExchanges(payload: unknown, ctx: OtlpContext): OtelExchange[] {
  const out: OtelExchange[] = [];
  try {
    const p = payload as { resourceLogs?: Array<Record<string, any>> };
    if (!p?.resourceLogs) return [];
    for (const rl of p.resourceLogs) {
      for (const sl of rl.scopeLogs ?? []) {
        for (const rec of sl.logRecords ?? []) {
          const a = attrMap(rec.attributes);
          // Only inference records carry prompt/completion content.
          if (!a.has("gen_ai.prompt") && !a.has("gen_ai.completion")) continue;
          const prompt = str(a.get("gen_ai.prompt")) ?? "";
          const completion = str(a.get("gen_ai.completion")) ?? "";
          const tsNano = rec.timeUnixNano ? Number(rec.timeUnixNano) : Date.now() * 1e6;
          const ts = Math.floor(tsNano / 1e6);
          out.push({
            id: ulid(ts),
            runId: str(a.get("beagle.run_token")) ?? "otel",
            source: "otel",
            agent: ctx.agent,
            provider: str(a.get("gen_ai.system")) ?? ctx.provider,
            model: str(a.get("gen_ai.response.model")) ?? str(a.get("gen_ai.request.model")),
            endpoint: "otel:gen_ai.client.inference",
            request: {
              // The scanner reads bodyBytes; give it the reported prompt text.
              bodyBytes: new TextEncoder().encode(prompt),
              messages: prompt ? [{ role: "user", content: prompt }] : [],
            },
            response: {
              text: completion,
              bodyBytes: new TextEncoder().encode(completion),
            },
            meta: {
              tsRequest: ts,
              tsResponse: ts,
              tokensIn: int(a.get("gen_ai.usage.input_tokens")),
              tokensOut: int(a.get("gen_ai.usage.output_tokens")),
            },
            convId: str(a.get("session.id")),
            runToken: str(a.get("beagle.run_token")),
          });
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
