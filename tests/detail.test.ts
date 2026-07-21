import { describe, expect, test } from "bun:test";
import { buildDetail, detailLeaks, detailMessages, type LeakSpan } from "../src/viewer/detail";
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

  test("a STITCHED Mode B turn renders its question and its answer together", () => {
    // The shape attachOtelResponse leaves behind: the question rides
    // display_messages (written with the prompt batch), the answer rides
    // response_body (written by the later stitch). Both must reach the UI —
    // the whole point of stitching is a turn that reads as one exchange, and
    // a row whose answer never rendered is what this feature set out to fix.
    const d = buildDetail(
      call({
        source: "otel", endpoint: "otel:claude_code.turn", requestBody: enc("how does memory work?"),
        displayMessages: [{ role: "user", content: "how does memory work?" }],
        responseBody: enc("It works like this — the full answer"),
        model: "claude-opus-4-8",
      }),
      [],
    );
    expect(d.messages).toEqual([{ role: "user", content: "how does memory work?" }]);
    expect(d.responseText).toBe("It works like this — the full answer");
    expect(d.model).toBe("claude-opus-4-8");
  });

  test("passes capture provenance through so the detail can explain wire vs agent-reported", () => {
    expect(buildDetail(call({ source: "wire" }), []).source).toBe("wire");
    expect(buildDetail(call({ source: "otel" }), []).source).toBe("otel");
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

  test("Mode B call: structure comes from persisted display messages, response from raw text", () => {
    // otel bodies are scan text, not provider JSON — before display_messages
    // the structured view was empty and the row fell back to raw bytes.
    const d = buildDetail(
      call({
        source: "otel", endpoint: "otel:claude_code.turn",
        requestBody: enc("run the tests"),
        responseBody: enc("Running them now."),
        displayMessages: [{ role: "user", content: "run the tests" }],
      }),
      [],
    );
    expect(d.messages).toEqual([{ role: "user", content: "run the tests" }]);
    expect(d.responseText).toBe("Running them now.");
  });

  test("wire call with no stored transcript parses its body — the usual case", () => {
    const d = buildDetail(call(), []);
    expect(d.messages).toEqual([{ role: "user", content: "hi" }]);
    expect(d.system).toBe("be brief");
  });

  test("a wire call's STORED transcript wins over re-parsing its body", () => {
    // This used to go the other way, on the reasoning that a wire body parses
    // on its own so a stored copy could only be stale. Derived redaction broke
    // that: a secret the display MANUFACTURES by joining content blocks is not
    // in the body, so the body redaction cannot remove it and re-parsing at
    // read time rebuilds it whole. A wire row now persists a transcript only
    // when that happened, which makes the stored copy the authoritative one.
    // Layout is [system, ...messages], system always at index 0.
    const d = buildDetail(
      call({
        displayMessages: [
          { role: "system", content: "be brief" },
          { role: "user", content: "here is the key [REDACTED:aws-access-key-id:abc123] use it" },
        ],
      }),
      [],
    );
    expect(d.messages).toEqual([
      { role: "user", content: "here is the key [REDACTED:aws-access-key-id:abc123] use it" },
    ]);
    expect(d.system).toBe("be brief");
    // Same authority for the delta walk-back, which reads messages on its own.
    expect(detailMessages(call({ displayMessages: [{ role: "system", content: "" }, { role: "user", content: "masked" }] })))
      .toEqual([{ role: "user", content: "masked" }]);
  });

  test("a redacted row's placeholder is highlighted even when only the transcript holds it", () => {
    // The derived-only case: the body never contained the assembled secret, so
    // there is no placeholder in it and no span to slice. Without searching the
    // stored transcript, R7's highlight would find nothing on the one surface
    // that was actually masked.
    const d = buildDetail(
      call({
        redacted: true,
        displayMessages: [
          { role: "system", content: "" },
          { role: "user", content: "key [REDACTED:aws-access-key-id:abc123] sent" },
        ],
      }),
      [],
    );
    expect(d.leaks).toEqual([
      { value: "[REDACTED:aws-access-key-id:abc123]", secretType: "aws-access-key-id", tier: "structured" },
    ]);
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

// The lightweight walk-back/next-call helpers must stay byte-identical to the
// full buildDetail — they exist only to skip response re-parsing, never to
// change the result.
describe("detailMessages / detailLeaks agree with buildDetail", () => {
  const secret = "AKIAZQ3DRSTUVWXY2345";
  const reqBody = enc(`{"messages":[{"role":"user","content":"key ${secret}"},{"role":"assistant","content":"ok"}]}`);
  const spanStart = new TextDecoder().decode(reqBody).indexOf(secret);
  const spans: LeakSpan[] = [{ start: spanStart, end: spanStart + secret.length, secretType: "aws-access-key-id", tier: "structured" }];

  test("detailMessages === buildDetail(...).messages (no response needed)", () => {
    const c = call({ requestBody: reqBody, responseBody: enc('{"content":[{"type":"text","text":"ok"}]}') });
    expect(detailMessages(c)).toEqual(buildDetail(c, []).messages);
  });

  test("detailMessages falls back to displayMessages for Mode B, like buildDetail", () => {
    const c = call({ source: "otel", requestBody: enc("scan text"), displayMessages: [{ role: "user", content: "hi" }] });
    expect(detailMessages(c)).toEqual(buildDetail(c, []).messages);
  });

  test("detailLeaks === buildDetail(..., spans).leaks", () => {
    const c = call({ requestBody: reqBody });
    expect(detailLeaks(c, spans)).toEqual(buildDetail(c, spans).leaks);
  });
});
