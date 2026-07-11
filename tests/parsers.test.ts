import { describe, expect, test } from "bun:test";
import { detectFormat, parseRequest, parseResponse } from "../src/parsers/parsers";

const enc = (s: string) => new TextEncoder().encode(s);

describe("detectFormat", () => {
  test("by endpoint path", () => {
    expect(detectFormat("/v1/messages")).toBe("anthropic-messages");
    expect(detectFormat("/v1/chat/completions")).toBe("openai-chat");
    expect(detectFormat("/v1/responses")).toBe("openai-responses");
    expect(detectFormat("/v1beta/models/gemini:generateContent")).toBe("unknown");
  });
});

describe("Anthropic Messages", () => {
  test("request: system, messages, model extracted; content blocks flattened", () => {
    const body = JSON.stringify({
      model: "claude-sonnet-5",
      system: "You are a helpful assistant.",
      messages: [
        { role: "user", content: "read main.ts" },
        { role: "assistant", content: [{ type: "text", text: "reading" }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "file contents" }] },
      ],
      tools: [{ name: "bash" }],
    });
    const p = parseRequest("anthropic-messages", enc(body))!;
    expect(p.model).toBe("claude-sonnet-5");
    expect(p.system).toBe("You are a helpful assistant.");
    expect(p.messages.length).toBe(3);
    expect(p.messages[1]?.content).toBe("reading");
    expect(p.messages[2]?.content).toContain("file contents");
  });

  test("streamed SSE response: text reassembled, usage extracted", () => {
    const sse = [
      'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-sonnet-5","usage":{"input_tokens":100}}}\n',
      'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}\n',
      'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":" world"}}\n',
      'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}\n',
    ].join("\n");
    const r = parseResponse("anthropic-messages", enc(sse))!;
    expect(r.text).toBe("Hello world");
    expect(r.tokensIn).toBe(100);
    expect(r.tokensOut).toBe(12);
    expect(r.model).toBe("claude-sonnet-5");
  });

  test("non-streamed JSON response", () => {
    const body = JSON.stringify({
      model: "claude-sonnet-5",
      content: [{ type: "text", text: "plain answer" }],
      usage: { input_tokens: 10, output_tokens: 5 },
    });
    const r = parseResponse("anthropic-messages", enc(body))!;
    expect(r.text).toBe("plain answer");
    expect(r.tokensOut).toBe(5);
  });
});

describe("OpenAI Chat Completions", () => {
  test("request messages", () => {
    const body = JSON.stringify({
      model: "gpt-5",
      messages: [
        { role: "system", content: "be brief" },
        { role: "user", content: "hi" },
      ],
    });
    const p = parseRequest("openai-chat", enc(body))!;
    expect(p.model).toBe("gpt-5");
    expect(p.system).toBe("be brief");
    expect(p.messages.length).toBe(2);
  });

  test("streamed SSE response reassembles delta content", () => {
    const sse = [
      'data: {"choices":[{"delta":{"content":"Hel"}}],"model":"gpt-5"}',
      'data: {"choices":[{"delta":{"content":"lo"}}]}',
      'data: {"usage":{"prompt_tokens":9,"completion_tokens":3},"choices":[]}',
      "data: [DONE]",
    ].join("\n\n");
    const r = parseResponse("openai-chat", enc(sse))!;
    expect(r.text).toBe("Hello");
    expect(r.tokensIn).toBe(9);
    expect(r.tokensOut).toBe(3);
  });
});

describe("OpenAI Responses", () => {
  test("request: input items and previous_response_id", () => {
    const body = JSON.stringify({
      model: "gpt-5",
      previous_response_id: "resp_123",
      input: [{ role: "user", content: [{ type: "input_text", text: "continue" }] }],
    });
    const p = parseRequest("openai-responses", enc(body))!;
    expect(p.prevResponseId).toBe("resp_123");
    expect(p.messages[0]?.content).toBe("continue");
  });

  test("response: id and output text", () => {
    const body = JSON.stringify({
      id: "resp_456",
      output: [{ type: "message", content: [{ type: "output_text", text: "done" }] }],
      usage: { input_tokens: 20, output_tokens: 4 },
    });
    const r = parseResponse("openai-responses", enc(body))!;
    expect(r.responseId).toBe("resp_456");
    expect(r.text).toBe("done");
  });
});

describe("JSON containing 'data:' substrings is not misrouted to the SSE parser", () => {
  test("data-URI in response content parses as JSON", () => {
    const body = JSON.stringify({
      model: "claude-sonnet-5",
      content: [{ type: "text", text: "here: data:image/png;base64,iVBORw0KGgo=" }],
      usage: { input_tokens: 1, output_tokens: 2 },
    });
    const r = parseResponse("anthropic-messages", enc(body))!;
    expect(r.text).toContain("data:image/png");
    expect(r.tokensOut).toBe(2);
  });
});

describe("malformed input degrades to null, never throws (R3)", () => {
  test("garbage bytes", () => {
    expect(parseRequest("anthropic-messages", enc("not json{{{"))).toBeNull();
    expect(parseResponse("openai-chat", enc("\x00\x01binary"))).toBeNull();
  });
});
