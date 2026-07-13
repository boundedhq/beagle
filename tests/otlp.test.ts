import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { mapOtlpLogsToCalls, buildOtelEnv } from "../src/parsers/otlp-map";
import { OtlpReceiver } from "../src/core/otlp/receiver";

// Build a Claude Code OTel log record (the REAL schema — event.name events,
// verified against Claude Code 2.1.193 in the Phase-0 spike). `tsNano` lets a
// test order records within a turn.
function event(name: string, attrs: Record<string, string | number>, tsNano = "1720000000000000000") {
  return {
    timeUnixNano: tsNano,
    body: { stringValue: `claude_code.${name}` },
    attributes: [
      { key: "event.name", value: { stringValue: name } },
      ...Object.entries(attrs).map(([key, value]) =>
        typeof value === "number"
          ? { key, value: { intValue: value } }
          : { key, value: { stringValue: value } },
      ),
    ],
  };
}

function logs(records: unknown[]) {
  return {
    resourceLogs: [
      {
        resource: { attributes: [{ key: "service.name", value: { stringValue: "claude-code" } }] },
        scopeLogs: [{ scope: { name: "com.anthropic.claude_code.events" }, logRecords: records }],
      },
    ],
  };
}

// A full one-turn export as Claude Code really emits it: several records
// sharing (session.id, prompt.id).
function turnRecords(opts: { session?: string; prompt?: string; response?: string; toolInput?: string } = {}) {
  const s = opts.session ?? "sess-1";
  const p = "prompt-1";
  const recs: unknown[] = [
    event("user_prompt", { "session.id": s, "prompt.id": p, prompt: opts.prompt ?? "read the config" }, "1720000000000000000"),
  ];
  if (opts.toolInput) {
    recs.push(event("tool_result", { "session.id": s, "prompt.id": p, tool_name: "Bash", tool_input: opts.toolInput, tool_result_size_bytes: 42 }, "1720000000100000000"));
  }
  recs.push(event("api_request", { "session.id": s, "prompt.id": p, model: "claude-sonnet-5", input_tokens: 120, output_tokens: 8 }, "1720000000200000000"));
  recs.push(event("assistant_response", { "session.id": s, "prompt.id": p, model: "claude-sonnet-5", response: opts.response ?? "done" }, "1720000000300000000"));
  return recs;
}

const ctx = { agent: "claude-code", provider: "anthropic" };
const decode = (b: Uint8Array) => new TextDecoder().decode(b);

describe("OTLP → Call mapping — Claude Code's real event schema (Mode B)", () => {
  test("reassembles the split event stream into one Call per turn", () => {
    const calls = mapOtlpLogsToCalls(logs(turnRecords()), ctx);
    expect(calls.length).toBe(1);
    const c = calls[0]!;
    expect(c.source).toBe("otel");
    expect(c.provider).toBe("anthropic");
    expect(c.model).toBe("claude-sonnet-5");
    expect(c.meta.tokensIn).toBe(120);
    expect(c.meta.tokensOut).toBe(8);
    expect(c.convId).toBe("sess-1"); // tier-1 session key
    expect(decode(c.request.bodyBytes)).toContain("read the config"); // prompt scannable
    expect(c.response.text).toContain("done"); // assistant response captured
  });

  test("a secret in the user prompt is present in the scanned body", () => {
    const c = mapOtlpLogsToCalls(logs(turnRecords({ prompt: "deploy with AKIAZQ3DRSTUVWXY2345" })), ctx)[0]!;
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("a secret in a TOOL INPUT (e.g. a bash command) is present in the scanned body", () => {
    // Tool inputs are an outbound leak surface (a command line, a write
    // payload). The spike confirmed tool_input is exported verbatim.
    const c = mapOtlpLogsToCalls(logs(turnRecords({ toolInput: '{"command":"aws s3 ls --key AKIAZQ3DRSTUVWXY2345"}' })), ctx)[0]!;
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("operational events (hooks, mcp, plugin, tool_decision) produce no calls", () => {
    const noise = logs([
      event("hook_execution_start", { "session.id": "s", hook_event: "SessionStart" }),
      event("mcp_server_connection", { "session.id": "s", server_name: "x", status: "connected" }),
      event("plugin_loaded", { "session.id": "s", "plugin.name": "y" }),
      event("tool_decision", { "session.id": "s", "prompt.id": "p", decision: "accept", tool_name: "Read" }),
      event("api_refusal", { "session.id": "s", "prompt.id": "p", model: "m" }),
    ]);
    expect(mapOtlpLogsToCalls(noise, ctx)).toEqual([]);
  });

  test("two distinct prompts (different prompt.id) become two Calls, in order", () => {
    const recs = [
      event("user_prompt", { "session.id": "s", "prompt.id": "p1", prompt: "first" }, "1720000000000000000"),
      event("assistant_response", { "session.id": "s", "prompt.id": "p1", response: "a1" }, "1720000000100000000"),
      event("user_prompt", { "session.id": "s", "prompt.id": "p2", prompt: "second" }, "1720000000200000000"),
      event("assistant_response", { "session.id": "s", "prompt.id": "p2", response: "a2" }, "1720000000300000000"),
    ];
    const calls = mapOtlpLogsToCalls(logs(recs), ctx);
    expect(calls.length).toBe(2);
    expect(decode(calls[0]!.request.bodyBytes)).toBe("first");
    expect(decode(calls[1]!.request.bodyBytes)).toBe("second");
    expect(calls[0]!.response.text).toBe("a1");
    expect(calls[1]!.response.text).toBe("a2");
  });

  test("token counts sum across multiple api_request records in one turn (retries/fallback)", () => {
    const recs = [
      event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "hi" }),
      event("api_request", { "session.id": "s", "prompt.id": "p", model: "m", input_tokens: 4058, output_tokens: 181 }),
      event("api_request", { "session.id": "s", "prompt.id": "p", model: "m", input_tokens: 2, output_tokens: 38 }),
      event("assistant_response", { "session.id": "s", "prompt.id": "p", response: "ok" }),
    ];
    const c = mapOtlpLogsToCalls(logs(recs), ctx)[0]!;
    expect(c.meta.tokensIn).toBe(4060);
    expect(c.meta.tokensOut).toBe(219);
  });

  test("int64 tokens survive whether OTLP encodes them as number or string", () => {
    const asNumber = mapOtlpLogsToCalls(logs([
      event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "hi" }),
      event("api_request", { "session.id": "s", "prompt.id": "p", input_tokens: 1200, output_tokens: 34 }),
    ]), ctx)[0]!;
    expect(asNumber.meta.tokensIn).toBe(1200);
    // string-encoded int64 (OTLP/JSON spec form)
    const asString = mapOtlpLogsToCalls(logs([
      event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "hi" }),
      {
        timeUnixNano: "1720000000000000000",
        attributes: [
          { key: "event.name", value: { stringValue: "api_request" } },
          { key: "session.id", value: { stringValue: "s" } },
          { key: "prompt.id", value: { stringValue: "p" } },
          { key: "input_tokens", value: { intValue: "1200" } },
          { key: "output_tokens", value: { intValue: "34" } },
        ],
      },
    ]), ctx)[0]!;
    expect(asString.meta.tokensIn).toBe(1200);
    expect(asString.meta.tokensOut).toBe(34);
  });

  test("a user_prompt alone (turn split across OTLP batches) still yields a scannable Call", () => {
    // Correlation is per delivered payload; a batch with only the prompt must
    // still produce a Call so its secret is scanned — not held for a completion
    // that may arrive in a later POST.
    const c = mapOtlpLogsToCalls(logs([
      event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "lone AKIAZQ3DRSTUVWXY2345" }),
    ]), ctx)[0]!;
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
    expect(c.response.text).toBe("");
  });

  test("malformed payload yields no calls, never throws", () => {
    expect(mapOtlpLogsToCalls({ garbage: true }, ctx)).toEqual([]);
    expect(mapOtlpLogsToCalls(null, ctx)).toEqual([]);
    expect(mapOtlpLogsToCalls({ resourceLogs: [{ scopeLogs: [{ logRecords: [{}] }] }] }, ctx)).toEqual([]);
  });

  test("ONE malformed record must not suppress scanning of co-batched valid records", () => {
    // Fail-open-for-the-whole-payload would be a silent leak miss: a single bad
    // record (attributes as an object, not an array) must be skipped, NOT drop
    // the real user_prompt carrying a secret that shares the batch.
    const body = {
      resourceLogs: [{ scopeLogs: [{ logRecords: [
        { attributes: {} }, // malformed: attributes is an object, iterating it throws
        event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "secret AKIAZQ3DRSTUVWXY2345" }),
      ] }] }],
    };
    const calls = mapOtlpLogsToCalls(body, ctx);
    expect(calls.length).toBe(1);
    expect(decode(calls[0]!.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("non-array containers (resourceLogs/scopeLogs) degrade to [] without throwing", () => {
    expect(mapOtlpLogsToCalls({ resourceLogs: { bad: 1 } }, ctx)).toEqual([]);
    expect(mapOtlpLogsToCalls({ resourceLogs: [{ scopeLogs: { bad: 1 } }] }, ctx)).toEqual([]);
  });

  test("the turn is credited to the model that produced the response, not a refused fallback", () => {
    // Real server-fallback turn: api_request #1 on model A gets refused, the
    // retry (#2) and the assistant_response are on model B. The Call's model
    // must be B — the model that actually generated the reply.
    const recs = [
      event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "hi" }, "1720000000000000000"),
      event("api_request", { "session.id": "s", "prompt.id": "p", model: "model-A", input_tokens: 10, output_tokens: 1 }, "1720000000100000000"),
      event("api_refusal", { "session.id": "s", "prompt.id": "p", model: "model-A" }, "1720000000150000000"),
      event("api_request", { "session.id": "s", "prompt.id": "p", model: "model-B", input_tokens: 2, output_tokens: 5 }, "1720000000200000000"),
      event("assistant_response", { "session.id": "s", "prompt.id": "p", model: "model-B", response: "ok" }, "1720000000300000000"),
    ];
    const c = mapOtlpLogsToCalls(logs(recs), ctx)[0]!;
    expect(c.model).toBe("model-B");
    expect(c.meta.tokensIn).toBe(12); // tokens still sum across both api_requests
  });

  test("forward-compat: a GenAI-style span still flows through the accumulator", () => {
    // If a future client emits spans, the collector still finds records; a span
    // carrying user_prompt-shaped attrs maps like any other content event.
    const body = {
      resourceSpans: [{ scopeSpans: [{ spans: [
        { startTimeUnixNano: "1720000000000000000", attributes: [
          { key: "event.name", value: { stringValue: "user_prompt" } },
          { key: "session.id", value: { stringValue: "span-s" } },
          { key: "prompt.id", value: { stringValue: "p" } },
          { key: "prompt", value: { stringValue: "from a span AKIAZQ3DRSTUVWXY2345" } },
        ] },
      ] }] }],
    };
    const c = mapOtlpLogsToCalls(body, ctx)[0]!;
    expect(c.convId).toBe("span-s");
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });
});

describe("OTLP mapper — against the REAL Claude Code capture (spike fixture)", () => {
  // tests/fixtures/claude-code-otlp.json is a verbatim capture from a real
  // `claude` session (Claude Code 2.1.193), PII attributes stripped and a
  // test AWS key injected into the prompt. This is the durable proof that the
  // mapper matches production output — not a synthetic approximation.
  const fixture = JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "claude-code-otlp.json"), "utf8"));

  test("reassembles the real export into exactly one turn Call, with exact numbers", () => {
    const calls = mapOtlpLogsToCalls(fixture, ctx);
    expect(calls.length).toBe(1);
    const c = calls[0]!;
    expect(c.source).toBe("otel");
    expect(c.convId).toBe("d82062e5-a22f-4f85-9914-a47cf3073a72"); // real session.id
    // The real turn is a server-fallback: api_request(4058/181, claude-fable-5),
    // an api_refusal, then api_request(2/38, claude-opus-4-8) + assistant_response.
    // Exact values, so wrong-sum / wrong-model / counting-the-refusal all fail.
    expect(c.meta.tokensIn).toBe(4060); // 4058 + 2
    expect(c.meta.tokensOut).toBe(219); // 181 + 38
    expect(c.model).toBe("claude-opus-4-8"); // the model that produced the reply, not the refused one
  });

  test("the injected prompt secret AND the real tool_input are both in the scanned body", () => {
    const c = mapOtlpLogsToCalls(fixture, ctx)[0]!;
    const scanned = decode(c.request.bodyBytes);
    expect(scanned).toContain("AKIAZQ3DRSTUVWXY2345"); // prompt secret → scannable
    expect(scanned).toContain("fake-creds.txt"); // tool_input (Read file_path) → scannable
    expect(c.response.text).toContain("config keys"); // real assistant response captured
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
    // the flags that make tool inputs (a real leak surface) show up at all
    expect(env.OTEL_LOG_TOOL_DETAILS).toBe("1");
    expect(env.OTEL_LOG_TOOL_CONTENT).toBe("1");
    expect(env.OTEL_EXPORTER_OTLP_HEADERS).toContain("run-token-abc");
  });
});

describe("OtlpReceiver HTTP endpoint", () => {
  let receiver: OtlpReceiver;
  let got: unknown[];
  let port: number;

  beforeEach(async () => {
    got = [];
    receiver = new OtlpReceiver({ token: "secret-run-token", onCalls: (exs) => got.push(...exs) });
    port = await receiver.listen(0);
  });

  afterEach(() => receiver.close());

  const post = (body: unknown, headers: Record<string, string>) =>
    fetch(`http://127.0.0.1:${port}/v1/logs`, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) });

  test("accepts json logs with the run token and yields a call", async () => {
    const r = await post(logs(turnRecords()), { "content-type": "application/json", "x-beagle-run": "secret-run-token" });
    expect(r.status).toBe(200);
    expect(got.length).toBe(1);
  });

  test("rejects a missing or wrong run token", async () => {
    const r = await post(logs(turnRecords()), { "content-type": "application/json" });
    expect(r.status).toBe(401);
    expect(got.length).toBe(0);
  });

  test("rejects protobuf (json-only receiver, by construction)", async () => {
    const r = await post("\x0a\x00", { "content-type": "application/x-protobuf", "x-beagle-run": "secret-run-token" });
    expect(r.status).toBe(415);
  });

  test("binds loopback only", () => {
    expect(receiver.boundAddress).toBe("127.0.0.1");
  });

  test("multi-byte UTF-8 content survives chunked bodies intact", async () => {
    const prompt = "日本語のプロンプト — café — 🐕".repeat(2000);
    const r = await post(logs(turnRecords({ prompt })), { "content-type": "application/json", "x-beagle-run": "secret-run-token" });
    expect(r.status).toBe(200);
    expect(got.length).toBe(1);
    const c = got[0] as { request: { bodyBytes: Uint8Array } };
    // prompt is part of the scanned body for the turn
    expect(decode(c.request.bodyBytes)).toContain(prompt);
  });
});
