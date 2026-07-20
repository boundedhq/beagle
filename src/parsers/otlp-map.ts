// OTLP → canonical Call mapping (design §6.2, Mode B): agent OTel exports →
// canonical Call, marked source='otel' → the agent-reported badge (R7). This
// is the agent's self-report, not wire bytes. Two vendor schemas share this
// module and the loopback receiver — Claude Code's (below) and Codex's
// (`codex.*`, further down); the payload's event names discriminate.
import { sanitizeTool, type DisplayMessage } from "./parsers";
//
// Claude Code's real schema (verified live against 2.1.193; scope
// "com.anthropic.claude_code.events"). This is NOT the OpenTelemetry GenAI
// semconv — there is no `gen_ai.prompt`/`gen_ai.completion`. Instead one user
// turn is SPLIT across several event log records
// that share (session.id, prompt.id):
//   event.name=user_prompt        → prompt (verbatim), prompt.id, session.id
//   event.name=tool_result        → tool_input (verbatim), tool_name — but NO
//                                    result content, only *_size_bytes
//   event.name=api_request        → model, input_tokens, output_tokens
//   event.name=assistant_response → response (verbatim), model
// We reassemble those into one Call per turn. request.bodyBytes carries the
// OUTBOUND leak surface the daemon actually scans: the user prompt plus every
// tool INPUT (bash commands, file paths, write payloads). Claude Code's export
// omits tool RESULT content, so for it a secret present only in a tool's
// output needs the PostToolUse hook below; Codex's export carries tool output
// inline (see the codex section).
import { readFileSync } from "node:fs";
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
  // OTLP uses 0 as the "unknown time" sentinel — never a real timestamp.
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

// The record's event time. Codex sets timeUnixNano to literal "0" on every
// record (verified live, codex 0.144.x) and puts the real time in
// observedTimeUnixNano — taking the 0 at face value dated every codex row
// 1970-01-01 and zeroed its ulid. Prefer the event time, then the collector's
// observed time, then a span's start time.
function recordNano(rec: OtlpRecord): number | undefined {
  return nano(rec.timeUnixNano) ?? nano(rec.observedTimeUnixNano) ?? nano(rec.startTimeUnixNano);
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
  tools: Array<{ name?: string; input: string }>;
  response?: string;
  model?: string;
  tokensIn?: number;
  tokensOut?: number;
}

interface OtlpRecord {
  attributes?: Array<{ key: string; value: AttrValue }>;
  timeUnixNano?: string | number;
  observedTimeUnixNano?: string | number;
  startTimeUnixNano?: string | number;
}

// Only these event types carry content we keep; everything else Claude Code
// emits (hook_*, mcp_server_connection, plugin_loaded, tool_decision,
// api_refusal, …) is operational noise with no leak surface.
const CONTENT_EVENTS = new Set(["user_prompt", "tool_result", "assistant_response", "api_request"]);

// Claude Code fires internal side-calls that REUSE the user turn's session.id +
// prompt.id but carry a non-user query_source — session-title generation today
// (a haiku call whose response is `{"title": …}`), likely more later. Left in,
// they fold into the turn: their tokens sum in, their model can win, and under
// last-write-wins their response CLOBBERS the real reply (verified live — a
// `generate_session_title` response overwriting the answer is exactly why some
// captured turns showed a title JSON or went blank). Skip them by source. A
// denylist, not an allowlist: an unrecognized source is kept as real content,
// so we never silently drop a genuine reply.
const INTERNAL_QUERY_SOURCES = new Set(["generate_session_title"]);

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
  const scanText = [t.prompt ?? "", ...t.tools.map((c) => c.input)].filter(Boolean).join("\n");
  const promptDisplay = t.prompt ? flattenPromptText(t.prompt) : "";
  // Surface tool calls as readable messages (role "tool"), not only in the
  // scanned body — otherwise a tool-call-only turn reads "(no message content)"
  // in the feed and its input never reaches the search index (searchText is
  // built from messages). Name-prefixed for display; the leak-surface scanText
  // stays inputs-only.
  const messages: DisplayMessage[] = [];
  if (promptDisplay) messages.push({ role: "user", content: promptDisplay });
  for (const c of t.tools) {
    messages.push({
      role: "tool", content: c.name ? `${c.name}: ${c.input}` : c.input,
      tool: sanitizeTool(c.name), kind: "call",
    });
  }
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
      messages,
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
    const records = collectRecords(payload);
    // Codex speaks its own `codex.*` event schema and carries tool OUTPUT
    // inline; route it to the Codex mapper. Claude Code splits a turn across
    // several records, reassembled below. The loopback receiver is shared, so
    // the payload's schema — not any per-receiver setting — is the discriminator.
    if (isCodexPayload(records)) return mapCodexRecords(records);
    const turns = new Map<string, Turn>();
    let idx = 0;
    for (const rec of records) {
      const i = idx++;
      // Per-record isolation: one malformed record is SKIPPED, never allowed to
      // discard the scanning of valid secret-bearing records in the same batch.
      try {
        const a = attrMap(rec.attributes);
        const name = str(a.get("event.name"));
        if (!name || !CONTENT_EVENTS.has(name)) continue;
        // Drop internal side-calls before they touch the turn (response, model,
        // and token counts all mis-attribute otherwise).
        if (INTERNAL_QUERY_SOURCES.has(str(a.get("query_source")) ?? "")) continue;
        const sessionId = str(a.get("session.id"));
        const promptId = str(a.get("prompt.id"));
        // Group by turn. A content record with no prompt.id still gets its own
        // turn so nothing scannable is silently dropped.
        const key = promptId ? `${sessionId ?? ""}::${promptId}` : `${sessionId ?? ""}::orphan-${i}`;
        let turn = turns.get(key);
        if (!turn) {
          turn = { order: i, sessionId, tools: [] };
          turns.set(key, turn);
        }
        const ns = recordNano(rec);
        if (ns !== undefined && (turn.tsNano === undefined || ns < turn.tsNano)) turn.tsNano = ns;
        if (name === "user_prompt") {
          turn.prompt = str(a.get("prompt")) ?? turn.prompt;
        } else if (name === "tool_result") {
          const ti = str(a.get("tool_input"));
          if (ti) turn.tools.push({ name: str(a.get("tool_name")), input: ti });
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
      .filter((t) => t.prompt || t.response || t.tools.length > 0)
      .sort((x, y) => x.order - y.order)
      .map((t) => buildTurnCall(t, ctx));
  } catch {
    return [];
  }
}

// ---- Codex subscription capture (Codex Mode B) ----
//
// Codex on a "Sign in with ChatGPT" login can't be wire-redirected — its
// built-in `openai` provider is locked and OPENAI_BASE_URL doesn't reach
// inference. But Codex ships its own OpenTelemetry exporter, and (verified live
// against Codex 0.144.x, scope "codex_otel.log_only") its `codex.*` log events
// carry the whole OUTBOUND leak surface in ONE stream — no PostToolUse hook
// needed (unlike Claude Code, whose export omits tool results):
//   event.name=codex.user_prompt → prompt (verbatim), conversation.id, model
//   event.name=codex.tool_result → tool_name, arguments (the command run),
//                                   output (the tool's RESULT content, e.g. the
//                                   bytes of a secret file the agent `cat`s)
// codex.sse_event (kind=response.completed) carries token counts, read for
// meta only. Everything else Codex emits (codex.api_request, codex.turn_ttft,
// websocket_*, startup_phase, …) is operational, no content.
// Each content event becomes its OWN Call — a prompt and a tool call are
// distinct captured units — mirroring the Claude Code hook mapper's per-tool
// rows. Codex's export also carries PII (user.email, user.account_id); we read
// ONLY content, conversation/call ids, and token counts — never those
// attributes.
const CODEX_CONTENT = new Set(["codex.user_prompt", "codex.tool_result"]);

function isCodexPayload(records: OtlpRecord[]): boolean {
  for (const rec of records) {
    const n = str(attrMap(rec.attributes).get("event.name"));
    if (n && n.startsWith("codex.")) return true;
  }
  return false;
}

function buildCodexCall(o: {
  ts: number;
  convId?: string;
  model?: string;
  endpoint: string;
  scanText: string;
  display: DisplayMessage;
}): OtelCall {
  return {
    id: ulid(o.ts),
    runId: "otel",
    source: "otel",
    // The shared loopback receiver defaults its context to claude-code/anthropic;
    // a codex.* payload is unambiguously Codex, so it self-labels here so those
    // defaults can't bleed onto Codex rows.
    agent: "codex",
    provider: "openai",
    model: o.model,
    endpoint: o.endpoint,
    request: {
      bodyBytes: new TextEncoder().encode(o.scanText),
      messages: [o.display],
    },
    response: { text: "", bodyBytes: new Uint8Array() },
    meta: { tsRequest: o.ts, tsResponse: o.ts },
    convId: o.convId,
  };
}

interface CodexToolGroup {
  order: number;
  ts: number;
  convId?: string;
  model?: string;
  tool: string;
  parts: string[]; // arguments + outputs across the call's records, in order
  lastOutput: string;
}

function mapCodexRecords(records: OtlpRecord[]): OtelCall[] {
  const out: Array<{ order: number; call: OtelCall }> = [];
  // Tool results are grouped by call_id: codex can stream one exec's output
  // across several tool_result records (chunks), and a secret split across a
  // chunk boundary must land in ONE scan surface to match the detector regex.
  const tools = new Map<string, CodexToolGroup>();
  // Token counts ride codex.sse_event (kind=response.completed), not the
  // content events; collected per conversation, attached to its prompt Call
  // WHEN they share a delivered payload. Codex often flushes them in a later
  // batch — then the counts are simply absent ("?" in the UI), the honest
  // rendering for a self-report.
  const tokens = new Map<string, { tokensIn: number; tokensOut: number }>();
  const promptByConv = new Map<string, OtelCall>();
  let idx = 0;
  for (const rec of records) {
    const i = idx++;
    // Per-record isolation: one malformed record is skipped, never allowed to
    // discard the scanning of valid secret-bearing records in the same batch.
    try {
      const a = attrMap(rec.attributes);
      const name = str(a.get("event.name"));
      const convId = str(a.get("conversation.id"));
      if (name === "codex.sse_event") {
        const tin = int(a.get("input_token_count"));
        const tout = int(a.get("output_token_count"));
        if (convId && (tin !== undefined || tout !== undefined)) {
          const t = tokens.get(convId) ?? { tokensIn: 0, tokensOut: 0 };
          t.tokensIn += tin ?? 0;
          t.tokensOut += tout ?? 0;
          tokens.set(convId, t);
        }
        continue;
      }
      if (!name || !CODEX_CONTENT.has(name)) continue;
      const model = str(a.get("model"));
      const ns = recordNano(rec);
      const ts = ns !== undefined ? Math.floor(ns / 1e6) : Date.now();
      if (name === "codex.user_prompt") {
        const prompt = str(a.get("prompt"));
        if (!prompt) continue;
        const call = buildCodexCall({
          ts,
          convId,
          model,
          endpoint: "otel:codex:user_prompt",
          scanText: prompt,
          display: { role: "user", content: flattenPromptText(prompt) },
        });
        out.push({ order: i, call });
        if (convId) promptByConv.set(convId, call);
      } else {
        // codex.tool_result — scan BOTH the command and its output: a secret can
        // hide in the arguments (curl -H "Authorization: Bearer …") or in the
        // result (the bytes of a secret file the agent reads back).
        const tool = str(a.get("tool_name")) ?? "tool";
        const args = str(a.get("arguments")) ?? "";
        const output = str(a.get("output")) ?? "";
        if (!args && !output) continue;
        const callId = str(a.get("call_id"));
        const key = callId ? `${convId ?? ""}::${callId}` : `orphan-${i}`;
        let g = tools.get(key);
        if (!g) {
          g = { order: i, ts, convId, model, tool, parts: [], lastOutput: "" };
          tools.set(key, g);
        }
        // Chunks of one call repeat the same arguments — dedupe; outputs concat.
        if (args && !g.parts.includes(args)) g.parts.push(args);
        if (output) {
          g.parts.push(output);
          g.lastOutput = output;
        }
      }
    } catch {
      /* skip a single malformed record; the rest of the batch still maps */
    }
  }
  for (const g of tools.values()) {
    out.push({
      order: g.order,
      call: buildCodexCall({
        ts: g.ts,
        convId: g.convId,
        model: g.model,
        endpoint: `otel:codex:tool_result:${g.tool}`,
        scanText: `${g.tool}\n${g.parts.join("\n")}`,
        display: {
          role: "tool", content: `${g.tool}: ${g.lastOutput.slice(0, 4000)}`,
          tool: sanitizeTool(g.tool), kind: "result",
        },
      }),
    });
  }
  for (const [convId, t] of tokens) {
    const p = promptByConv.get(convId);
    if (p) {
      p.meta.tokensIn = t.tokensIn;
      p.meta.tokensOut = t.tokensOut;
    }
  }
  return out.sort((x, y) => x.order - y.order).map((x) => x.call);
}

/** Map a Codex OTLP logs payload into scannable Calls. Malformed input degrades
 *  to []. Exported for direct testing; the receiver reaches it through
 *  `mapOtlpLogsToCalls`, which auto-detects the codex.* schema. */
export function mapCodexOtlpToCalls(payload: unknown): OtelCall[] {
  try {
    return mapCodexRecords(collectRecords(payload));
  } catch {
    return [];
  }
}

/** The codex `-c` config overrides that point its OpenTelemetry exporter at
 *  Beagle's loopback receiver. Prepended to the user's codex argv (`-c` is a
 *  global flag, honored before the subcommand). `log_user_prompt` turns on
 *  prompt content; the exporter posts application/json to /v1/logs. Vendor
 *  knobs only (R2) — no patching, no config-file writes. The per-run TOKEN is
 *  NOT here: it rides the OTEL_EXPORTER_OTLP_HEADERS env var (buildCodexOtelEnv)
 *  so it never lands on the process command line, where `ps`/audit logs would
 *  leak it to other local users — the same invariant the Claude path holds.
 *  `base` is a Beagle-generated loopback URL, nothing to escape. */
export function buildCodexOtelArgs(base: string): string[] {
  const exporter = `otel.exporter={ "otlp-http" = { endpoint = "${base}/v1/logs", protocol = "json" } }`;
  return ["-c", "otel.log_user_prompt=true", "-c", exporter];
}

/** The env carrying the receiver's auth token as the OTLP header it gates on.
 *  Env, never argv — see above. Two codex-specific subtleties, both verified
 *  live against codex 0.144.x (bundled opentelemetry-otlp 0.31):
 *  - The crate resolves headers as OTEL_EXPORTER_OTLP_LOGS_HEADERS
 *    .or_else(OTEL_EXPORTER_OTLP_HEADERS) — REPLACE, not merge. Setting only
 *    the generic var means a user's own signal-specific export shadows the
 *    token (silent zero capture) — so Beagle sets the signal-specific var,
 *    which always wins, and leaves the user's generic var untouched for
 *    codex's child processes.
 *  - `undefined` entries mean "remove from the child env": codex is compiled
 *    without the gzip feature, so an inherited OTEL_EXPORTER_OTLP_*COMPRESSION
 *    =gzip kills its exporter at startup — again silent zero capture. */
export function buildCodexOtelEnv(runToken: string): Record<string, string | undefined> {
  return {
    OTEL_EXPORTER_OTLP_LOGS_HEADERS: `x-beagle-run=${runToken}`,
    OTEL_EXPORTER_OTLP_COMPRESSION: undefined,
    OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: undefined,
  };
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
        messages: [{
          role: "tool", content: `${toolName}: ${toolResponse.slice(0, 4000)}`,
          tool: sanitizeTool(toolName), kind: "result",
        }] as DisplayMessage[],
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

/** Merge Beagle's tool-output hook into a USER-supplied `--settings` value
 *  (a file path or an inline JSON string — Claude Code accepts both). The
 *  user's settings pass through verbatim; Beagle's hook is APPENDED to their
 *  PostToolUse list. Unreadable/invalid input degrades to just the hook —
 *  capture must not fail open because a user file was malformed. */
export function mergeHookIntoSettings(userValue: string, command: string): Record<string, unknown> {
  let user: Record<string, unknown> = {};
  try {
    const raw = userValue.trim().startsWith("{") ? userValue : readFileSync(userValue, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) user = parsed as Record<string, unknown>;
  } catch {
    /* fall through: hook-only settings */
  }
  const hooks =
    user.hooks && typeof user.hooks === "object" && !Array.isArray(user.hooks)
      ? (user.hooks as Record<string, unknown>)
      : {};
  const ptu = Array.isArray(hooks.PostToolUse) ? hooks.PostToolUse : [];
  return {
    ...user,
    hooks: { ...hooks, PostToolUse: [...ptu, { hooks: [{ type: "command", command }] }] },
  };
}

// Vendor-shipped knobs only (R2 bright line): env vars, never patching. All
// verified honored against Claude Code 2.1.193 (content flags in the Phase-0
// spike; the signal-specific OTLP vars verified live with a hostile generic
// var alongside). The content flags surface user prompts and tool INPUTS (not
// tool results — the hook above closes that gap).
//
// SIGNAL-SPECIFIC OTLP vars, same rationale as buildCodexOtelEnv: per the OTel
// spec they beat the generic vars, so a user/org shell exporting
// OTEL_EXPORTER_OTLP_LOGS_ENDPOINT to a company collector can't silently
// divert the export away from Beagle — and Beagle in turn leaves the GENERIC
// vars untouched, so the org's own metrics/traces pipelines keep working while
// the agent is watched. Note the spec's shape difference: the signal-specific
// endpoint is the FULL URL (…/v1/logs), not a base. `undefined` entries mean
// "remove from the child env" (Claude's exporter would try gzip the loopback
// receiver doesn't speak).
export function buildOtelEnv(endpoint: string, runToken: string): Record<string, string | undefined> {
  return {
    CLAUDE_CODE_ENABLE_TELEMETRY: "1",
    OTEL_LOGS_EXPORTER: "otlp",
    OTEL_EXPORTER_OTLP_LOGS_PROTOCOL: "http/json",
    OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: `${endpoint}/v1/logs`,
    OTEL_EXPORTER_OTLP_LOGS_HEADERS: `x-beagle-run=${runToken}`,
    OTEL_LOG_USER_PROMPTS: "1",
    OTEL_LOG_TOOL_DETAILS: "1",
    OTEL_LOG_TOOL_CONTENT: "1",
    // Batch delay down so the alert lag (Mode B is batched, not wire-instant)
    // is ~1s, not the default tens of seconds.
    OTEL_BLRP_SCHEDULE_DELAY: "1000",
    OTEL_EXPORTER_OTLP_COMPRESSION: undefined,
    OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: undefined,
  };
}
