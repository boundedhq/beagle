import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mapOtlpLogsToExchanges, buildOtelEnv } from "../src/parsers/otlp-map";
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

describe("OTLP → Exchange mapping (Mode B)", () => {
  test("maps GenAI log attributes to a canonical Exchange with source=otel", () => {
    const exchanges = mapOtlpLogsToExchanges(otlpLogsBody("tok"), { agent: "claude-code", provider: "anthropic" });
    expect(exchanges.length).toBe(1);
    const ex = exchanges[0]!;
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
    const ex = mapOtlpLogsToExchanges(otlpLogsBody("tok", { sessionId: "conv-xyz" }), { agent: "claude-code", provider: "anthropic" })[0]!;
    expect(ex.convId).toBe("conv-xyz");
  });

  test("a secret in the reported prompt is present in bodyBytes for scanning", () => {
    const ex = mapOtlpLogsToExchanges(
      otlpLogsBody("tok", { prompt: "here: AKIAZQ3DRSTUVWXY2345" }),
      { agent: "claude-code", provider: "anthropic" },
    )[0]!;
    expect(new TextDecoder().decode(ex.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("malformed payload yields no exchanges, never throws", () => {
    expect(mapOtlpLogsToExchanges({ garbage: true }, { agent: "x", provider: "y" })).toEqual([]);
    expect(mapOtlpLogsToExchanges(null, { agent: "x", provider: "y" })).toEqual([]);
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
      onExchanges: (exs) => got.push(...exs),
    });
    port = await receiver.listen(0);
  });

  afterEach(() => receiver.close());

  test("accepts json logs with the run token and yields an exchange", async () => {
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
});
