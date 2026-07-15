import { describe, expect, test } from "bun:test";
import { buildDetail, type LeakSpan } from "../src/viewer/detail";
import type { CallRecord } from "../src/core/store/store";

const enc = (s: string) => new TextEncoder().encode(s);

function call(overrides: Partial<CallRecord> = {}): CallRecord {
  return {
    id: "01EX", sessionId: "s1", runId: "r1", source: "wire",
    agent: "claude-code", provider: "anthropic", model: "claude-sonnet-5",
    endpoint: "/v1/messages", tsRequest: Date.now(), tsResponse: Date.now(),
    status: 200, tokensIn: 10, tokensOut: 5, bytesReq: 1, bytesResp: 1,
    summary: "x", scanState: "ok", captureState: "ok", sessionTier: "prefix",
    requestBody: enc('{"system":"be brief","messages":[{"role":"user","content":"hi"}]}'),
    requestHeaders: [], responseBody: null, responseHeaders: [], sseRaw: null,
    searchText: "",
    ...overrides,
  };
}

describe("buildDetail — response reassembly (UI fix 1)", () => {
  test("reassembles a streamed Anthropic SSE response into readable text", () => {
    const sse =
      'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-sonnet-5"}}\n\n' +
      'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"I read "}}\n\n' +
      'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"main.ts."}}\n\n';
    const d = buildDetail(call({ responseBody: enc(sse), sseRaw: enc(sse) }), []);
    expect(d.responseText).toBe("I read main.ts.");
  });

  test("non-streamed JSON response reassembles too", () => {
    const body = JSON.stringify({ content: [{ type: "text", text: "plain answer" }] });
    const d = buildDetail(call({ responseBody: enc(body) }), []);
    expect(d.responseText).toBe("plain answer");
  });

  test("passes byte sizes and token counts through for the detail meta line", () => {
    const d = buildDetail(call({ bytesReq: 15872, bytesResp: 2048, tokensIn: 1240, tokensOut: 96 }), []);
    expect(d.bytesReq).toBe(15872);
    expect(d.bytesResp).toBe(2048);
    expect(d.tokensIn).toBe(1240);
    expect(d.tokensOut).toBe(96);
  });

  test("structures request system + messages", () => {
    const d = buildDetail(call(), []);
    expect(d.system).toBe("be brief");
    expect(d.messages).toEqual([{ role: "user", content: "hi" }]);
  });

  test("unparseable response falls back to raw, never throws", () => {
    const d = buildDetail(call({ responseBody: enc("\x00\x01 not json or sse") }), []);
    expect(d.responseText).toBeNull();
    expect(d.responseRaw).toContain("not json");
  });
});

describe("buildDetail — leak values to highlight (UI fix 2)", () => {
  test("slices the secret value from the request body using its span", () => {
    const req = 'key AKIAZQ3DRSTUVWXY2345 here';
    const start = req.indexOf("AKIA");
    const spans: LeakSpan[] = [{ start, end: start + 20, secretType: "aws-access-key-id", tier: "structured" }];
    const d = buildDetail(call({ requestBody: enc(req) }), spans);
    expect(d.leaks).toEqual([{ value: "AKIAZQ3DRSTUVWXY2345", secretType: "aws-access-key-id", tier: "structured" }]);
  });

  test("de-duplicates identical secret values across spans", () => {
    const req = "AKIAZQ3DRSTUVWXY2345 ... AKIAZQ3DRSTUVWXY2345";
    const spans: LeakSpan[] = [
      { start: 0, end: 20, secretType: "aws-access-key-id", tier: "structured" },
      { start: 25, end: 45, secretType: "aws-access-key-id", tier: "structured" },
    ];
    const d = buildDetail(call({ requestBody: enc(req) }), spans);
    expect(d.leaks.length).toBe(1);
  });

  test("redacted body: highlights the [REDACTED:...] placeholders instead of slicing", () => {
    const req = 'key [REDACTED:aws-access-key-id:a1b2c3] here';
    // spans point at the ORIGINAL (pre-redaction) offsets — must be ignored.
    // The stored redacted flag (not a string sniff) drives placeholder mode.
    const spans: LeakSpan[] = [{ start: 4, end: 24, secretType: "aws-access-key-id", tier: "structured" }];
    const d = buildDetail(call({ requestBody: enc(req), redacted: true }), spans);
    expect(d.leaks.map((l) => l.value)).toEqual(["[REDACTED:aws-access-key-id:a1b2c3]"]);
  });

  test("unredacted body that happens to contain [REDACTED: text is sliced, not placeholder-matched", () => {
    // Without the stored flag we must not treat a literal "[REDACTED:" in a
    // normal body as a redaction marker — slice the real span instead.
    const req = 'talking about [REDACTED: foo] and AKIAZQ3DRSTUVWXY2345';
    const start = req.indexOf("AKIA");
    const spans: LeakSpan[] = [{ start, end: start + 20, secretType: "aws-access-key-id", tier: "structured" }];
    const d = buildDetail(call({ requestBody: enc(req) }), spans);
    expect(d.leaks.map((l) => l.value)).toEqual(["AKIAZQ3DRSTUVWXY2345"]);
  });

  test("no spans, no leaks", () => {
    expect(buildDetail(call(), []).leaks).toEqual([]);
  });

  test("out-of-bounds span is ignored, never crashes", () => {
    const spans: LeakSpan[] = [{ start: 9999, end: 10005, secretType: "x", tier: "structured" }];
    expect(buildDetail(call(), spans).leaks).toEqual([]);
  });

  test("spans stay aligned when multi-byte characters precede the secret", () => {
    // Scanner offsets are UTF-16 string indices into the decoded body; the
    // detail slice must use the same basis. Emoji (surrogate pairs) + CJK
    // before the secret would expose any byte-vs-char mismatch.
    const prefix = "🐕🐕 日本語テキスト — ";
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const body = `${prefix}${secret} end`;
    // compute the span exactly as the scanner does: indexOf on the decoded string
    const start = body.indexOf(secret);
    const spans: LeakSpan[] = [{ start, end: start + secret.length, secretType: "aws-access-key-id", tier: "structured" }];
    const d = buildDetail(call({ requestBody: enc(body) }), spans);
    expect(d.leaks.map((l) => l.value)).toEqual([secret]);
  });
});
