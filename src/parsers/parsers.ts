// Format parsers (non-core, R3): they drive the readable view and tier-2
// session keying, never the security path. Malformed input degrades to null
// — capture and detection don't depend on these.
import type { Message } from "../core/call";

export type Format = "anthropic-messages" | "openai-chat" | "openai-responses" | "unknown";

export interface ParsedRequest {
  model?: string;
  system?: string;
  messages: Message[];
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
      const messages: Message[] =
        typeof input === "string"
          ? [{ role: "user", content: input }]
          : (input ?? []).map(responsesItem).filter((m: Message | null): m is Message => m !== null);
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
  detail?: string; // e.g. the shell command or a file path
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
        if (b?.type === "tool_use") out.push(toolAction(b.name, b.input));
      }
    } else if (format === "openai-chat") {
      for (const tc of body.choices?.[0]?.message?.tool_calls ?? []) {
        out.push(toolAction(tc.function?.name, safeJson(tc.function?.arguments)));
      }
    } else if (format === "openai-responses") {
      for (const item of body.output ?? []) {
        if (item?.type === "function_call") out.push(toolAction(item.name, safeJson(item.arguments)));
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
      out.push(toolAction(ev.content_block.name, ev.content_block.input));
    } else if (format === "openai-chat") {
      for (const tc of ev.choices?.[0]?.delta?.tool_calls ?? []) {
        if (tc.function?.name) out.push(toolAction(tc.function.name, undefined));
      }
    }
  }
  return out;
}

function safeJson(s: unknown): Record<string, unknown> | undefined {
  if (typeof s !== "string") return undefined;
  try { return JSON.parse(s); } catch { return undefined; }
}

function toolAction(name: unknown, input: unknown): ToolAction {
  const tool = String(name ?? "tool");
  const inp = (input ?? {}) as Record<string, unknown>;
  // Pull a short, useful detail for the common coding-agent tools.
  const detail =
    (typeof inp.command === "string" && inp.command) ||
    (typeof inp.file_path === "string" && inp.file_path) ||
    (typeof inp.path === "string" && inp.path) ||
    (typeof inp.pattern === "string" && inp.pattern) ||
    undefined;
  return detail ? { tool, detail: String(detail) } : { tool };
}

function toMessage(m: Record<string, unknown>): Message {
  return {
    role: String(m.role ?? "unknown"),
    content: flattenContent(m.content) ?? "",
  };
}

// Responses-API `input` items are not all role-messages: tool calls, tool
// outputs, and encrypted reasoning ride the same array as TYPED items with no
// role — which used to render as a wall of "unknown" cards. Label them what
// they are, in the "Name: payload" convention the viewer's tool cards parse.
function responsesItem(item: Record<string, unknown>): Message | null {
  if (item.type === "function_call") {
    return { role: "tool", content: `${String(item.name ?? "tool")}: ${String(item.arguments ?? "")}` };
  }
  if (item.type === "function_call_output") {
    return { role: "tool", content: flattenContent(item.output) ?? String(item.output ?? "") };
  }
  // Encrypted model-internal state — unreadable by design. The raw view
  // carries the exact bytes; the readable projection skips the ciphertext.
  if (item.type === "reasoning") return null;
  return toMessage(item);
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
