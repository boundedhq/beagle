// Format parsers (non-core, R3): they drive the readable view, tier-2 session
// keying, and the derived text that is scanned and redacted. Malformed input
// degrades to null; raw-body capture and scanning still continue.
import type { Message } from "../core/call";

export type Format = "anthropic-messages" | "openai-chat" | "openai-responses" | "unknown";

/** A Message enriched for DISPLAY (non-core, viewer-only semantics). content
 *  stays byte-for-byte what it always was — these fields only label it, so
 *  history diffing, search text, and summaries are untouched. */
export interface DisplayMessage extends Message {
  tool?: string; // sanitized tool name, or undefined when unknown/hostile
  // "response"/"response-call": the wire transcript's stored reply and the tool
  // calls it made — writer-only markers, never produced by the parsers.
  kind?: "call" | "result" | "response" | "response-call";
  callId?: string;
  detail?: string; // the originating call's short detail, shown in result headers
  /** Viewer-only: the exchange row a reconstructed subscription card came
   *  from, so the transcript can still reach that row's own detail/raw view.
   *  Stamped at read time; never written into display_messages. */
  sourceId?: string;
}

/** How much of a tool RESULT's text the stored transcript keeps — a `cat` of a
 *  large file must not be persisted twice at full length (the scanned body
 *  already holds all of it). Applied by the daemon AFTER redaction, never by
 *  the mappers that build these messages: clamping first left the raw PREFIX of
 *  a secret straddling the cap in display_messages, since the scrub that
 *  followed matched the whole value and found nothing. */
export const DISPLAY_RESULT_CAP = 4000;

// A tool name is display-critical (it becomes a card header): accept only
// names that look like identifiers; anything else renders unlabeled.
export function sanitizeTool(name: unknown): string | undefined {
  return typeof name === "string" && /^[A-Za-z_][\w.-]{0,40}$/.test(name) ? name : undefined;
}

export interface ParsedRequest {
  model?: string;
  system?: string;
  messages: DisplayMessage[];
  convId?: string;
  prevResponseId?: string;
  /** Explicitly stateless one-shot (store:false, no conversation identity) —
   *  e.g. opencode's title-generation turn. Must never fuzzy-link. */
  oneShot?: boolean;
}

export interface ParsedResponse {
  model?: string;
  text?: string;
  tokensIn?: number;
  tokensOut?: number;
  responseId?: string;
}

export function detectFormat(endpoint: string): Format {
  const path = endpoint.split("?")[0] ?? endpoint;
  if (path.endsWith("/messages")) return "anthropic-messages";
  if (path.endsWith("/chat/completions")) return "openai-chat";
  if (path.endsWith("/responses")) return "openai-responses";
  return "unknown";
}

export function parseRequest(format: Format, bytes: Uint8Array): ParsedRequest | null {
  try {
    const body = JSON.parse(new TextDecoder().decode(bytes));
    if (format === "anthropic-messages") {
      return {
        model: body.model,
        system: flattenContent(body.system),
        messages: (body.messages ?? []).map(toMessage),
        convId: body.metadata?.conversation_id,
      };
    }
    if (format === "openai-chat") {
      const messages: Message[] = (body.messages ?? []).map(toMessage);
      return {
        model: body.model,
        system: messages.find((m) => m.role === "system" || m.role === "developer")?.content,
        messages,
      };
    }
    if (format === "openai-responses") {
      const input = body.input;
      // Two passes: outputs reference their call by call_id only, so first
      // collect every call's name (+ short detail), then map — a result card
      // can then say WHICH tool produced it and what it was asked to do, even
      // though the output item itself names neither.
      const nameByCallId = new Map<string, ToolAction>();
      if (Array.isArray(input)) {
        for (const item of input) {
          const t = sanitizeTool(item?.name);
          if (item?.type === "function_call" && typeof item.call_id === "string" && t) {
            nameByCallId.set(item.call_id, toolAction(t, safeJson(item.arguments)));
          }
        }
      }
      const messages: DisplayMessage[] =
        typeof input === "string"
          ? [{ role: "user", content: input }]
          : (input ?? [])
              .map((i: Record<string, unknown>) => responsesItem(i, nameByCallId))
              .filter((m: DisplayMessage | null): m is DisplayMessage => m !== null);
      // prompt_cache_key is a per-CONVERSATION affinity key by design (cache
      // routing works by shared prompt prefix), and clients use it that way —
      // opencode sends "ses_<its session id>" on every conversational call.
      // That is a deterministic session identity, far stronger than history
      // heuristics. Precedence: a request that chains with previous_response_id
      // (server-issued ground truth) keeps that as its identity — the CLIENT-
      // chosen cache key only steps in when there is no chain, so a client
      // that keyed its cache per-user rather than per-conversation could never
      // shadow correct chaining and merge its conversations.
      const cacheKey =
        typeof body.prompt_cache_key === "string" && body.prompt_cache_key !== ""
          ? body.prompt_cache_key
          : undefined;
      return {
        model: body.model,
        system: flattenContent(body.instructions),
        messages,
        convId: body.previous_response_id ? undefined : cacheKey,
        prevResponseId: body.previous_response_id,
        // store:false with no conversation identity at all is an explicitly
        // stateless one-shot — opencode's title-generation turn. Its system
        // prompt and opening message are IDENTICAL across conversations, so it
        // must never fuzzy-link into another session.
        oneShot: body.store === false && !cacheKey && !body.previous_response_id,
      };
    }
    return null;
  } catch {
    return null;
  }
}

export function parseResponse(format: Format, bytes: Uint8Array): ParsedResponse | null {
  try {
    const text = new TextDecoder().decode(bytes);
    // JSON first: a JSON body can legitimately contain "data:" (data-URIs);
    // a real SSE stream never parses as JSON.
    let body: Record<string, any>;
    try {
      body = JSON.parse(text);
    } catch {
      return parseSse(format, text);
    }
    if (format === "anthropic-messages") {
      return {
        model: body.model,
        text: flattenContent(body.content),
        tokensIn: body.usage?.input_tokens,
        tokensOut: body.usage?.output_tokens,
      };
    }
    if (format === "openai-chat") {
      return {
        model: body.model,
        text: body.choices?.[0]?.message?.content ?? undefined,
        tokensIn: body.usage?.prompt_tokens,
        tokensOut: body.usage?.completion_tokens,
      };
    }
    if (format === "openai-responses") {
      const texts: string[] = [];
      for (const item of body.output ?? []) {
        if (item.type === "message") {
          for (const c of item.content ?? []) {
            if (typeof c.text === "string") texts.push(c.text);
          }
        }
      }
      return {
        model: body.model,
        responseId: body.id,
        text: texts.join("") || undefined,
        tokensIn: body.usage?.input_tokens,
        tokensOut: body.usage?.output_tokens,
      };
    }
    return null;
  } catch {
    return null;
  }
}

function parseSse(format: Format, raw: string): ParsedResponse | null {
  const out: ParsedResponse = {};
  const parts: string[] = [];
  for (const line of raw.split("\n")) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (payload === "" || payload === "[DONE]") continue;
    let ev: Record<string, any>;
    try {
      ev = JSON.parse(payload);
    } catch {
      continue;
    }
    if (format === "anthropic-messages") {
      if (ev.type === "message_start") {
        out.model = ev.message?.model ?? out.model;
        out.tokensIn = ev.message?.usage?.input_tokens ?? out.tokensIn;
      } else if (ev.type === "content_block_delta" && ev.delta?.type === "text_delta") {
        parts.push(ev.delta.text ?? "");
      } else if (ev.type === "message_delta") {
        out.tokensOut = ev.usage?.output_tokens ?? out.tokensOut;
      }
    } else if (format === "openai-chat") {
      out.model = ev.model ?? out.model;
      const delta = ev.choices?.[0]?.delta?.content;
      if (typeof delta === "string") parts.push(delta);
      if (ev.usage) {
        out.tokensIn = ev.usage.prompt_tokens ?? out.tokensIn;
        out.tokensOut = ev.usage.completion_tokens ?? out.tokensOut;
      }
    } else if (format === "openai-responses") {
      out.model = ev.model ?? out.model;
      if (ev.type === "response.output_text.delta" && typeof ev.delta === "string") {
        parts.push(ev.delta);
      }
      if (ev.type === "response.completed") {
        out.responseId = ev.response?.id ?? out.responseId;
        out.tokensIn = ev.response?.usage?.input_tokens ?? out.tokensIn;
        out.tokensOut = ev.response?.usage?.output_tokens ?? out.tokensOut;
      }
    }
  }
  if (parts.length > 0) out.text = parts.join("");
  return out.text || out.model || out.responseId ? out : null;
}

export interface ToolAction {
  tool: string;
  detail?: string; // e.g. the shell command or a file path (bounded by its reader)
  callId?: string; // pairs a call with its result in the NEXT request
  args?: string; // full raw arguments (JSON text) for the display card body
  /** Viewer-only: the self-report row that supplied this reconstructed call.
   *  Lets a Pi-shaped subscription transcript keep the raw capture reachable. */
  sourceId?: string;
}

// Extract the tool calls the assistant made in its response, for a plain-English
// "what the turn did" summary. Best-effort; streamed tool inputs may be partial.
export function extractActions(format: Format, bytes: Uint8Array): ToolAction[] {
  try {
    const text = new TextDecoder().decode(bytes);
    let body: Record<string, any>;
    try {
      body = JSON.parse(text);
    } catch {
      return extractActionsSse(format, text);
    }
    const out: ToolAction[] = [];
    if (format === "anthropic-messages") {
      for (const b of body.content ?? []) {
        if (b?.type === "tool_use") {
          out.push(toolAction(b.name, b.input, b.id, JSON.stringify(b.input ?? {})));
        }
      }
    } else if (format === "openai-chat") {
      for (const tc of body.choices?.[0]?.message?.tool_calls ?? []) {
        out.push(toolAction(tc.function?.name, safeJson(tc.function?.arguments), tc.id, tc.function?.arguments));
      }
    } else if (format === "openai-responses") {
      for (const item of body.output ?? []) {
        if (item?.type === "function_call") {
          out.push(toolAction(item.name, safeJson(item.arguments), item.call_id, item.arguments));
        }
      }
    }
    return out;
  } catch {
    return [];
  }
}

function extractActionsSse(format: Format, raw: string): ToolAction[] {
  const out: ToolAction[] = [];
  for (const line of raw.split("\n")) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]") continue;
    let ev: Record<string, any>;
    try { ev = JSON.parse(payload); } catch { continue; }
    if (format === "anthropic-messages" && ev.type === "content_block_start" && ev.content_block?.type === "tool_use") {
      out.push(toolAction(ev.content_block.name, ev.content_block.input, ev.content_block.id));
    } else if (format === "openai-chat") {
      for (const tc of ev.choices?.[0]?.delta?.tool_calls ?? []) {
        if (tc.function?.name) out.push(toolAction(tc.function.name, undefined, tc.id));
      }
    } else if (format === "openai-responses") {
      // Tool calls ride output_item events; `.done` carries the COMPLETE
      // arguments (`.added` is an empty shell — using it would double-count).
      if (ev.type === "response.output_item.done" && ev.item?.type === "function_call") {
        out.push(toolAction(ev.item.name, safeJson(ev.item.arguments), ev.item.call_id, ev.item.arguments));
      }
    }
  }
  return out;
}

function safeJson(s: unknown): Record<string, unknown> | undefined {
  if (typeof s !== "string") return undefined;
  try { return JSON.parse(s); } catch { return undefined; }
}

function toolAction(name: unknown, input: unknown, callId?: unknown, args?: unknown): ToolAction {
  const tool = String(name ?? "tool");
  const inp = (input ?? {}) as Record<string, unknown>;
  // Pull a short, useful detail for the common coding-agent tools.
  const detail =
    (typeof inp.command === "string" && inp.command) ||
    (typeof inp.file_path === "string" && inp.file_path) ||
    (typeof inp.path === "string" && inp.path) ||
    (typeof inp.pattern === "string" && inp.pattern) ||
    (typeof inp.url === "string" && inp.url) ||
    (typeof inp.query === "string" && inp.query) ||
    (typeof inp.name === "string" && inp.name) || // e.g. skill {"name":"…"}
    undefined;
  const out: ToolAction = { tool };
  // Full, NOT clamped here. Every reader bounds it for display (summarizeActions
  // takes 40 chars), and the daemon scrubs detected secrets out of it on the way
  // to the summary — a parse-time clamp ran BEFORE that scrub, so a secret cut
  // by it no longer matched and its prefix rode the feed line into the store.
  if (detail) out.detail = String(detail);
  if (typeof callId === "string") out.callId = callId;
  if (typeof args === "string") out.args = args;
  return out;
}

function toMessage(m: Record<string, unknown>): DisplayMessage {
  const out: DisplayMessage = {
    role: String(m.role ?? "unknown"),
    content: flattenContent(m.content) ?? "",
  };
  // Tool RESULTS hide inside role-messages on two formats: openai-chat sends
  // them as role:"tool" turns, anthropic embeds tool_result blocks in USER
  // messages. Label them so the sent-suffix never captions tool output as the
  // human's ask (role/content stay untouched — display label only).
  if (out.role === "tool") out.kind = "result";
  else if (
    out.role === "user" &&
    Array.isArray(m.content) &&
    (m.content as Array<Record<string, unknown>>).some((b) => b?.type === "tool_result")
  ) {
    out.kind = "result";
    const results = (m.content as Array<Record<string, unknown>>)
      .filter((b) => b?.type === "tool_result");
    // One DisplayMessage can carry several Anthropic results. Only attach an
    // origin when it is unambiguous; claiming the first call would label the
    // combined output with the wrong tool/path for every result after it.
    if (results.length === 1 && typeof results[0]?.tool_use_id === "string") {
      out.callId = results[0].tool_use_id;
    }
  }
  return out;
}

// Responses-API `input` items are not all role-messages: tool calls, tool
// outputs, and encrypted reasoning ride the same array as TYPED items with no
// role — which used to render as a wall of "unknown" cards. Label them what
// they are: content keeps the existing conventions BYTE-FOR-BYTE (history
// diffing and search depend on it); the display fields carry the labels.
function responsesItem(
  item: Record<string, unknown>,
  nameByCallId: Map<string, ToolAction>,
): DisplayMessage | null {
  const callId = typeof item.call_id === "string" ? item.call_id : undefined;
  if (item.type === "function_call") {
    return {
      role: "tool", content: `${String(item.name ?? "tool")}: ${asText(item.arguments)}`,
      tool: sanitizeTool(item.name), kind: "call", callId,
    };
  }
  if (item.type === "function_call_output") {
    const origin = callId ? nameByCallId.get(callId) : undefined;
    return {
      role: "tool", content: flattenContent(item.output) ?? asText(item.output),
      tool: origin?.tool, kind: "result", callId, detail: origin?.detail,
    };
  }
  // Encrypted model-internal state — unreadable by design. The raw view
  // carries the exact bytes; the readable projection skips the ciphertext.
  if (item.type === "reasoning") return null;
  // Built-in typed calls (web_search_call, computer_call, …) and their
  // outputs: same generic labeling so they don't read as "unknown" cards.
  if (typeof item.type === "string" && item.type.endsWith("_call_output")) {
    return {
      role: "tool", content: flattenContent(item.output) ?? asText(item.output ?? item),
      tool: sanitizeTool(item.type.slice(0, -"_call_output".length)), kind: "result",
      callId: callId ?? (typeof item.id === "string" ? item.id : undefined),
    };
  }
  if (typeof item.type === "string" && item.type.endsWith("_call")) {
    return {
      role: "tool", content: asText(item.arguments ?? item.action ?? item.input ?? item),
      tool: sanitizeTool(item.type.slice(0, -"_call".length)), kind: "call",
      callId: callId ?? (typeof item.id === "string" ? item.id : undefined),
    };
  }
  return toMessage(item);
}

// Tool arguments/output are strings in the API, but Beagle observes untrusted
// third-party clients — a non-string must serialize to real text, never
// "[object Object]", or a secret inside it drops out of `beagle search`
// (the "was this ever sent?" answer must stay definitive). Leak DETECTION is
// unaffected either way — the scanner reads the raw bytes.
function asText(v: unknown): string {
  return typeof v === "string" ? v : v == null ? "" : JSON.stringify(v);
}

function flattenContent(content: unknown): string | undefined {
  if (content == null) return undefined;
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((block: Record<string, unknown>) => {
        if (typeof block === "string") return block;
        if (typeof block.text === "string") return block.text;
        if (block.type === "tool_result") return flattenContent(block.content) ?? "";
        if (typeof block.content === "string") return block.content;
        return "";
      })
      .join("");
  }
  return undefined;
}
