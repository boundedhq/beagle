import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mapOtlpLogsToCalls, buildOtelEnv } from "../src/parsers/otlp-map";
import { OtlpReceiver } from "../src/core/otlp/receiver";

// A minimal OTLP/HTTP logs payload shaped like Claude Code's GenAI export.
function otlpLogsBody(token: string, opts: { sessionId?: string; prompt?: string; response?: string } = {}) {
  return {
    resourceLogs: [
      {
        resource: {
          attributes: [{ key: "service.name", value: { stringValue: "claude-code" } }],
        },
        scopeLogs: [
          {
            logRecords: [
              {
                timeUnixNano: "1720000000000000000",
                body: { stringValue: "gen_ai.client.inference" },
                attributes: [
                  { key: "gen_ai.system", value: { stringValue: "anthropic" } },
                  { key: "gen_ai.request.model", value: { stringValue: "claude-sonnet-5" } },
                  { key: "gen_ai.response.model", value: { stringValue: "claude-sonnet-5" } },
                  { key: "session.id", value: { stringValue: opts.sessionId ?? "otel-sess-1" } },
                  { key: "gen_ai.prompt", value: { stringValue: opts.prompt ?? "read the config file" } },
                  { key: "gen_ai.completion", value: { stringValue: opts.response ?? "done" } },
                  { key: "gen_ai.usage.input_tokens", value: { intValue: "120" } },
                  { key: "gen_ai.usage.output_tokens", value: { intValue: "8" } },
                  { key: "beagle.run_token", value: { stringValue: token } },
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}

describe("OTLP → Call mapping (Mode B)", () => {
  test("maps GenAI log attributes to a canonical Call with source=otel", () => {
    const calls = mapOtlpLogsToCalls(otlpLogsBody("tok"), { agent: "claude-code", provider: "anthropic" });
    expect(calls.length).toBe(1);
    const ex = calls[0]!;
    expect(ex.source).toBe("otel");
    expect(ex.provider).toBe("anthropic");
    expect(ex.model).toBe("claude-sonnet-5");
    expect(ex.meta.tokensIn).toBe(120);
    expect(ex.meta.tokensOut).toBe(8);
    // prompt content is scannable in bodyBytes
    expect(new TextDecoder().decode(ex.request.bodyBytes)).toContain("read the config file");
    expect(ex.response.text).toContain("done");
  });

  test("carries the session id for tier-1 resolution", () => {
    const ex = mapOtlpLogsToCalls(otlpLogsBody("tok", { sessionId: "conv-xyz" }), { agent: "claude-code", provider: "anthropic" })[0]!;
    expect(ex.convId).toBe("conv-xyz");
  });

  test("a secret in the reported prompt is present in bodyBytes for scanning", () => {
    const ex = mapOtlpLogsToCalls(
      otlpLogsBody("tok", { prompt: "here: AKIAZQ3DRSTUVWXY2345" }),
      { agent: "claude-code", provider: "anthropic" },
    )[0]!;
    expect(new TextDecoder().decode(ex.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("malformed payload yields no calls, never throws", () => {
    expect(mapOtlpLogsToCalls({ garbage: true }, { agent: "x", provider: "y" })).toEqual([]);
    expect(mapOtlpLogsToCalls(null, { agent: "x", provider: "y" })).toEqual([]);
  });
});

describe("OTel shape robustness (real-world variants — Gap 3 hardening)", () => {
  function attrs(map: Record<string, unknown>) {
    return Object.entries(map).map(([key, value]) => {
      if (typeof value === "number") return { key, value: { intValue: value } };
      return { key, value: { stringValue: String(value) } };
    });
  }

  test("int64 attributes serialized as JSON strings are parsed (OTLP/JSON encodes int64 as string)", () => {
    const body = {
      resourceLogs: [{ scopeLogs: [{ logRecords: [{
        timeUnixNano: "1720000000000000000",
        attributes: [
          { key: "gen_ai.system", value: { stringValue: "anthropic" } },
          { key: "gen_ai.prompt", value: { stringValue: "hi" } },
          { key: "gen_ai.completion", value: { stringValue: "ok" } },
          { key: "gen_ai.usage.input_tokens", value: { intValue: "1200" } }, // string!
          { key: "gen_ai.usage.output_tokens", value: { intValue: "34" } },
        ],
      }] }] }],
    };
    const ex = mapOtlpLogsToCalls(body, { agent: "claude-code", provider: "anthropic" })[0]!;
    expect(ex.meta.tokensIn).toBe(1200);
    expect(ex.meta.tokensOut).toBe(34);
  });

  test("alternate token attribute names (prompt_tokens/completion_tokens) are accepted", () => {
    const body = {
      resourceLogs: [{ scopeLogs: [{ logRecords: [{
        timeUnixNano: "1720000000000000000",
        attributes: attrs({
          "gen_ai.prompt": "hi",
          "gen_ai.completion": "ok",
          "gen_ai.usage.prompt_tokens": 90,
          "gen_ai.usage.completion_tokens": 7,
        }),
      }] }] }],
    };
    const ex = mapOtlpLogsToCalls(body, { agent: "claude-code", provider: "anthropic" })[0]!;
    expect(ex.meta.tokensIn).toBe(90);
    expect(ex.meta.tokensOut).toBe(7);
  });

  test("GenAI carried as spans (resourceSpans) is mapped too", () => {
    const body = {
      resourceSpans: [{ scopeSpans: [{ spans: [{
        startTimeUnixNano: "1720000000000000000",
        attributes: attrs({
          "gen_ai.system": "anthropic",
          "gen_ai.request.model": "claude-sonnet-5",
          "gen_ai.prompt": "please read AKIAZQ3DRSTUVWXY2345",
          "gen_ai.completion": "done",
          "session.id": "span-sess-1",
          "beagle.run_token": "tok",
        }),
      }] }] }],
    };
    const calls = mapOtlpLogsToCalls(body, { agent: "claude-code", provider: "anthropic" });
    expect(calls.length).toBe(1);
    expect(calls[0]!.source).toBe("otel");
    expect(calls[0]!.model).toBe("claude-sonnet-5");
    expect(calls[0]!.convId).toBe("span-sess-1");
    // the secret in the reported prompt is scannable
    expect(new TextDecoder().decode(calls[0]!.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("a JSON-array gen_ai.prompt (message list) is flattened into scannable text", () => {
    const promptJson = JSON.stringify([
      { role: "system", content: "You are Claude Code." },
      { role: "user", content: "key AKIAZQ3DRSTUVWXY2345" },
    ]);
    const body = {
      resourceLogs: [{ scopeLogs: [{ logRecords: [{
        timeUnixNano: "1720000000000000000",
        attributes: [
          { key: "gen_ai.prompt", value: { stringValue: promptJson } },
          { key: "gen_ai.completion", value: { stringValue: "ok" } },
        ],
      }] }] }],
    };
    const ex = mapOtlpLogsToCalls(body, { agent: "claude-code", provider: "anthropic" })[0]!;
    expect(new TextDecoder().decode(ex.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
    expect(new TextDecoder().decode(ex.request.bodyBytes)).toContain("You are Claude Code.");
  });

  test("a secret in a nested tool_result block is in bodyBytes for scanning (raw, not lossy-flattened)", () => {
    // The flatten for display only extracts .text; a tool_result's content
    // would be dropped by it. bodyBytes must be the RAW prompt so detection
    // still sees the secret.
    const promptJson = JSON.stringify([
      { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "AKIAZQ3DRSTUVWXY2345" }] },
    ]);
    const body = {
      resourceLogs: [{ scopeLogs: [{ logRecords: [{
        timeUnixNano: "1720000000000000000",
        attributes: [
          { key: "gen_ai.prompt", value: { stringValue: promptJson } },
          { key: "gen_ai.completion", value: { stringValue: "ok" } },
        ],
      }] }] }],
    };
    const ex = mapOtlpLogsToCalls(body, { agent: "claude-code", provider: "anthropic" })[0]!;
    expect(new TextDecoder().decode(ex.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("mixed resourceLogs + resourceSpans in one payload both map", () => {
    const body = {
      resourceLogs: [{ scopeLogs: [{ logRecords: [{
        timeUnixNano: "1720000000000000000",
        attributes: attrs({ "gen_ai.prompt": "from-log", "gen_ai.completion": "a" }),
      }] }] }],
      resourceSpans: [{ scopeSpans: [{ spans: [{
        startTimeUnixNano: "1720000000000000000",
        attributes: attrs({ "gen_ai.prompt": "from-span", "gen_ai.completion": "b" }),
      }] }] }],
    };
    const calls = mapOtlpLogsToCalls(body, { agent: "claude-code", provider: "anthropic" });
    expect(calls.length).toBe(2);
    const prompts = calls.map((e) => new TextDecoder().decode(e.request.bodyBytes)).sort();
    expect(prompts).toEqual(["from-log", "from-span"]);
  });
});

describe("buildOtelEnv (vendor knobs only, R2)", () => {
  test("sets the documented Claude Code telemetry knobs, json protocol, token header", () => {
    const env = buildOtelEnv("http://127.0.0.1:4318", "run-token-abc");
    expect(env.CLAUDE_CODE_ENABLE_TELEMETRY).toBe("1");
    expect(env.OTEL_LOGS_EXPORTER).toBe("otlp");
    expect(env.OTEL_EXPORTER_OTLP_PROTOCOL).toBe("http/json");
    expect(env.OTEL_EXPORTER_OTLP_ENDPOINT).toBe("http://127.0.0.1:4318");
    expect(env.OTEL_LOG_USER_PROMPTS).toBe("1");
    expect(env.OTEL_EXPORTER_OTLP_HEADERS).toContain("run-token-abc");
  });
});

describe("OtlpReceiver HTTP endpoint", () => {
  let receiver: OtlpReceiver;
  let got: unknown[];
  let port: number;

  beforeEach(async () => {
    got = [];
    receiver = new OtlpReceiver({
      token: "secret-run-token",
      onCalls: (exs) => got.push(...exs),
    });
    port = await receiver.listen(0);
  });

  afterEach(() => receiver.close());

  test("accepts json logs with the run token and yields an call", async () => {
    const r = await fetch(`http://127.0.0.1:${port}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": "secret-run-token" },
      body: JSON.stringify(otlpLogsBody("secret-run-token")),
    });
    expect(r.status).toBe(200);
    expect(got.length).toBe(1);
  });

  test("rejects a missing or wrong run token", async () => {
    const r = await fetch(`http://127.0.0.1:${port}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(otlpLogsBody("x")),
    });
    expect(r.status).toBe(401);
    expect(got.length).toBe(0);
  });

  test("rejects protobuf (json-only receiver)", async () => {
    const r = await fetch(`http://127.0.0.1:${port}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/x-protobuf", "x-beagle-run": "secret-run-token" },
      body: new Uint8Array([0x0a, 0x00]),
    });
    expect(r.status).toBe(415);
  });

  test("binds loopback only", () => {
    expect(receiver.boundAddress).toBe("127.0.0.1");
  });

  test("multi-byte UTF-8 content survives chunked bodies intact", async () => {
    // A prompt with characters whose UTF-8 encoding is likely to straddle a
    // chunk boundary; a naive per-chunk string coercion would corrupt it.
    const prompt = "日本語のプロンプト — café — 🐕".repeat(2000);
    const r = await fetch(`http://127.0.0.1:${port}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": "secret-run-token" },
      body: JSON.stringify(otlpLogsBody("secret-run-token", { prompt })),
    });
    expect(r.status).toBe(200);
    expect(got.length).toBe(1);
    const ex = got[0] as { request: { bodyBytes: Uint8Array } };
    expect(new TextDecoder().decode(ex.request.bodyBytes)).toBe(prompt);
  });
});
