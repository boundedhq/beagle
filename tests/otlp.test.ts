import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { DisplayMessage } from "../src/parsers/parsers";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  mapOtlpLogsToCalls,
  buildOtelEnv,
  mapHookToCall,
  buildHookSettings,
  mapCodexOtlpToCalls,
  buildCodexOtelArgs,
  buildCodexOtelEnv,
  mergeHookIntoSettings,
} from "../src/parsers/otlp-map";
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

  test("a tool-call-only turn surfaces the tool as a readable message (name-prefixed), not a blank row", () => {
    // No user_prompt / assistant_response — just a tool call. Its input must
    // become a readable message so the feed shows what the turn did instead of
    // "(no message content)", AND so it reaches the search index (built from
    // messages). The name is display-only; the scanned body stays inputs-only.
    // empty prompt/response → the mapper treats them as absent, so it's a
    // tool-call-only turn (like the real `{"tz":…}` calendar call).
    const c = mapOtlpLogsToCalls(logs(turnRecords({ prompt: "", response: "", toolInput: '{"tz":"America/Los_Angeles"}' })), ctx)[0]!;
    expect(c.request.messages).toEqual([
      { role: "tool", content: 'Bash: {"tz":"America/Los_Angeles"}', tool: "Bash", kind: "call" },
    ] as DisplayMessage[]);
    expect(decode(c.request.bodyBytes)).toBe('{"tz":"America/Los_Angeles"}'); // leak surface: input only, no name
  });

  test("a normal turn (prompt + tool) keeps the user message AND appends the tool call, in order", () => {
    // Regression guard: adding tool messages must not drop or reorder the user
    // prompt. The scanned body is prompt + tool input; the response still wins
    // the summary (verified in summary.test.ts), so normal rows are unchanged.
    const c = mapOtlpLogsToCalls(logs(turnRecords({ prompt: "check the tz", toolInput: '{"cmd":"date"}' })), ctx)[0]!;
    expect(c.request.messages).toEqual([
      { role: "user", content: "check the tz" },
      { role: "tool", content: 'Bash: {"cmd":"date"}', tool: "Bash", kind: "call" },
    ] as DisplayMessage[]);
    expect(decode(c.request.bodyBytes)).toBe('check the tz\n{"cmd":"date"}'); // prompt + tool input
  });

  test("an internal title-generation side-call (same prompt.id) never folds into the turn", () => {
    // Claude Code emits a `generate_session_title` api_request + assistant_response
    // that REUSE the user turn's session.id + prompt.id (verified live against a
    // real `-p` capture: haiku title call, response `{"title": …}`, tokens 511/12).
    // It must not touch the turn's response, model, or token counts.
    const recs = [
      event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "the real question" }, "1720000000000000000"),
      event("api_request", { "session.id": "s", "prompt.id": "p", model: "claude-haiku-4-5", input_tokens: 511, output_tokens: 12, query_source: "generate_session_title" }, "1720000000100000000"),
      event("assistant_response", { "session.id": "s", "prompt.id": "p", model: "claude-haiku-4-5", response: '{"title": "A Title"}', query_source: "generate_session_title" }, "1720000000150000000"),
      event("api_request", { "session.id": "s", "prompt.id": "p", model: "claude-opus-4-8", input_tokens: 3024, output_tokens: 13, query_source: "sdk" }, "1720000000200000000"),
      event("assistant_response", { "session.id": "s", "prompt.id": "p", model: "claude-opus-4-8", response: "the real answer", query_source: "sdk" }, "1720000000250000000"),
    ];
    const c = mapOtlpLogsToCalls(logs(recs), ctx)[0]!;
    expect(c.response.text).toBe("the real answer"); // NOT the title JSON
    expect(c.model).toBe("claude-opus-4-8"); // NOT the haiku title model
    expect(c.meta.tokensIn).toBe(3024); // the title call's 511 excluded
    expect(c.meta.tokensOut).toBe(13); // the title call's 12 excluded
  });

  test("the side-call can't clobber the answer even when emitted LAST (the dangerous order)", () => {
    // The bug hid in `-p` only because the real answer happened to come last, so
    // last-write-wins kept it. Batching/interactive ordering can put the title
    // side-call last — this is the case that silently corrupted real turns.
    const recs = [
      event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "real question" }, "1720000000000000000"),
      event("assistant_response", { "session.id": "s", "prompt.id": "p", model: "claude-opus-4-8", response: "the real answer", query_source: "sdk" }, "1720000000100000000"),
      event("assistant_response", { "session.id": "s", "prompt.id": "p", model: "claude-haiku-4-5", response: '{"title": "X"}', query_source: "generate_session_title" }, "1720000000200000000"),
    ];
    const c = mapOtlpLogsToCalls(logs(recs), ctx)[0]!;
    expect(c.response.text).toBe("the real answer");
    expect(c.model).toBe("claude-opus-4-8");
  });

  test("an unrecognized query_source is kept (denylist, never drop a real reply)", () => {
    // Forward-safety: only KNOWN-internal sources are skipped. A future/unknown
    // source must fall through as real content, not vanish.
    const c = mapOtlpLogsToCalls(logs([
      event("user_prompt", { "session.id": "s", "prompt.id": "p", prompt: "hi" }),
      event("assistant_response", { "session.id": "s", "prompt.id": "p", response: "kept anyway", query_source: "some_future_source" }),
    ]), ctx)[0]!;
    expect(c.response.text).toBe("kept anyway");
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

// Build a Codex OTel log record (the REAL schema — codex.* events, scope
// codex_otel.log_only, verified live against Codex 0.144.x). Real codex sets
// timeUnixNano to the literal "0" sentinel and puts the actual time in
// observedTimeUnixNano — the helper mirrors that shape exactly.
function codexEvent(name: string, attrs: Record<string, string | number>, tsNano = "1752300000000000000") {
  return {
    timeUnixNano: "0",
    observedTimeUnixNano: tsNano,
    attributes: [
      { key: "event.name", value: { stringValue: name } },
      ...Object.entries(attrs).map(([key, value]) =>
        typeof value === "number" ? { key, value: { intValue: value } } : { key, value: { stringValue: value } },
      ),
    ],
  };
}
function codexLogs(records: unknown[]) {
  return {
    resourceLogs: [{ scopeLogs: [{ scope: { name: "codex_otel.log_only" }, logRecords: records }] }],
  };
}

describe("Codex OTLP → Call mapping (Codex Mode B, codex.* schema)", () => {
  test("codex.user_prompt → a Call self-labeled codex/openai with the prompt scanned", () => {
    const calls = mapCodexOtlpToCalls(
      codexLogs([
        codexEvent("codex.user_prompt", {
          "conversation.id": "conv-9",
          model: "gpt-5.6",
          prompt: "deploy with AKIAZQ3DRSTUVWXY2345",
        }),
      ]),
    );
    expect(calls.length).toBe(1);
    const c = calls[0]!;
    expect(c.source).toBe("otel");
    expect(c.agent).toBe("codex"); // self-labeled, not the receiver's claude-code default
    expect(c.provider).toBe("openai");
    expect(c.model).toBe("gpt-5.6");
    expect(c.convId).toBe("conv-9");
    expect(c.endpoint).toBe("otel:codex:user_prompt");
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("codex.tool_result → a Call scanning tool name, command, AND output", () => {
    const calls = mapCodexOtlpToCalls(
      codexLogs([
        codexEvent("codex.tool_result", {
          "conversation.id": "conv-9",
          tool_name: "exec_command",
          arguments: '{"cmd":"cat key.txt"}',
          output: "token = AKIAZQ3DRSTUVWXY2345",
        }),
      ]),
    );
    expect(calls.length).toBe(1);
    const c = calls[0]!;
    expect(c.endpoint).toBe("otel:codex:tool_result:exec_command");
    const scanned = decode(c.request.bodyBytes);
    expect(scanned).toContain("cat key.txt"); // the command (a secret could hide here)
    expect(scanned).toContain("AKIAZQ3DRSTUVWXY2345"); // the tool OUTPUT — the key gap Codex closes natively
  });

  test("operational codex.* events (api_request, sse_event) carry no content and map to nothing", () => {
    const calls = mapCodexOtlpToCalls(
      codexLogs([
        codexEvent("codex.api_request", { "conversation.id": "c", success: "true" }),
        codexEvent("codex.sse_event", { "conversation.id": "c", input_token_count: 40 }),
        codexEvent("codex.turn_ttft", { "conversation.id": "c", duration_ms: 12 }),
      ]),
    );
    expect(calls).toEqual([]);
  });

  test("mapOtlpLogsToCalls auto-detects the codex.* schema and routes to the codex mapper", () => {
    // Even with the receiver's default claude-code/anthropic context, a codex
    // payload self-labels codex/openai — one shared receiver, payload-discriminated.
    const calls = mapOtlpLogsToCalls(
      codexLogs([codexEvent("codex.user_prompt", { "conversation.id": "c", prompt: "hi" })]),
      ctx,
    );
    expect(calls.length).toBe(1);
    expect(calls[0]!.agent).toBe("codex");
  });

  test("a genuinely-throwing record is skipped, co-batched valid records still map", () => {
    // `attributes: [null]` makes attrMap execute `null.key` → a real TypeError
    // INSIDE the per-record try/catch (the Array.isArray guard doesn't catch
    // this one — it's a non-empty array). Proves the catch actually isolates a
    // throwing record rather than taking the whole secret-bearing batch down.
    const calls = mapCodexOtlpToCalls(
      codexLogs([
        { attributes: [null] }, // throws mid-map
        codexEvent("codex.user_prompt", { "conversation.id": "c", prompt: "still scanned AKIAZQ3DRSTUVWXY2345" }),
      ]),
    );
    expect(calls.length).toBe(1);
    expect(decode(calls[0]!.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("PII attributes (user.email, user.account_id) are never read into a Call", () => {
    // The record CARRIES PII — this is the real test of the allowlist, not a
    // fixture that had PII pre-stripped. Only content + conversation id survive.
    const calls = mapCodexOtlpToCalls(
      codexLogs([
        codexEvent("codex.user_prompt", {
          "conversation.id": "c",
          "user.email": "victim@example.com",
          "user.account_id": "acct-abc-123",
          prompt: "refactor please",
        }),
      ]),
    );
    expect(calls.length).toBe(1);
    const blob = decode(calls[0]!.request.bodyBytes) + JSON.stringify(calls[0]!.request.messages);
    expect(blob).toContain("refactor please"); // content kept
    expect(blob).not.toContain("victim@example.com"); // PII dropped
    expect(blob).not.toContain("acct-abc-123");
  });

  test("malformed top-level payload degrades to [] (R3, fail-open)", () => {
    expect(mapCodexOtlpToCalls(null)).toEqual([]);
    expect(mapCodexOtlpToCalls({ resourceLogs: "nope" })).toEqual([]);
  });

  test("tool_result chunks sharing a call_id merge into ONE scan surface — a split secret still matches", () => {
    // codex streams long exec output across several tool_result records; a
    // secret cut at a chunk boundary must be reassembled or the detector regex
    // can never see it whole.
    const calls = mapCodexOtlpToCalls(
      codexLogs([
        codexEvent("codex.tool_result", {
          "conversation.id": "c", call_id: "call-7", tool_name: "exec_command",
          arguments: '{"cmd":"cat key.txt"}', output: "half of it: AKIAZQ3DRS",
        }, "1752300000000000000"),
        codexEvent("codex.tool_result", {
          "conversation.id": "c", call_id: "call-7", tool_name: "exec_command",
          arguments: '{"cmd":"cat key.txt"}', output: "TUVWXY2345 and the rest",
        }, "1752300001000000000"),
      ]),
    );
    expect(calls.length).toBe(1); // one Call per call_id, not per chunk
    const scanned = decode(calls[0]!.request.bodyBytes);
    expect(scanned).toContain("AKIAZQ3DRS\nTUVWXY2345"); // chunks adjacent, newline-joined
    expect(scanned.match(/cat key\.txt/g)?.length).toBe(1); // repeated arguments deduped
    // distinct call_ids stay distinct rows
    const two = mapCodexOtlpToCalls(
      codexLogs([
        codexEvent("codex.tool_result", { "conversation.id": "c", call_id: "a", tool_name: "exec", output: "x" }),
        codexEvent("codex.tool_result", { "conversation.id": "c", call_id: "b", tool_name: "exec", output: "y" }),
      ]),
    );
    expect(two.length).toBe(2);
  });

  test("sse_event token counts attach to the conversation's prompt Call", () => {
    const calls = mapCodexOtlpToCalls(
      codexLogs([
        codexEvent("codex.user_prompt", { "conversation.id": "c", prompt: "hi" }),
        codexEvent("codex.sse_event", { "conversation.id": "c", "event.kind": "response.completed", input_token_count: 100, output_token_count: 7 }),
        codexEvent("codex.sse_event", { "conversation.id": "c", "event.kind": "response.completed", input_token_count: 40, output_token_count: 3 }),
      ]),
    );
    expect(calls.length).toBe(1); // sse_events feed meta, never their own rows
    expect(calls[0]!.meta.tokensIn).toBe(140);
    expect(calls[0]!.meta.tokensOut).toBe(10);
  });

  test("timeUnixNano='0' (codex's real sentinel) falls back to observedTimeUnixNano — never 1970", () => {
    // Regression: real codex sets timeUnixNano to literal "0" on EVERY record;
    // taking it at face value dated all codex rows 1970-01-01 with zeroed ulids
    // (caught live). The observed time must win over the 0 sentinel.
    const calls = mapCodexOtlpToCalls(
      codexLogs([codexEvent("codex.user_prompt", { "conversation.id": "c", prompt: "hi" }, "1752300000000000000")]),
    );
    expect(calls.length).toBe(1);
    expect(calls[0]!.meta.tsRequest).toBe(1752300000000); // ms from observedTimeUnixNano
    expect(calls[0]!.id.startsWith("0000")).toBe(false); // ulid seeded with a real time
  });
});

describe("Codex OTLP mapper — against the REAL Codex capture (fixture)", () => {
  // tests/fixtures/codex-otlp.json is a verbatim capture from a real `codex`
  // session (codex 0.144.x), PII attributes (user.email, user.account_id) stripped.
  // Durable proof the codex mapper matches production output.
  const fixture = JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "codex-otlp.json"), "utf8"));

  test("maps the real export into a prompt Call and a tool_result Call", () => {
    const calls = mapCodexOtlpToCalls(fixture);
    expect(calls.length).toBe(2);
    expect(calls.every((c) => c.agent === "codex" && c.provider === "openai")).toBe(true);
    const prompt = calls.find((c) => c.endpoint === "otel:codex:user_prompt")!;
    const tool = calls.find((c) => c.endpoint.startsWith("otel:codex:tool_result"))!;
    expect(prompt).toBeDefined();
    expect(tool).toBeDefined();
    // The real tool output carried the file's contents back to the model — a
    // secret there is scanned. This is the gap Claude Code needs a hook for.
    expect(decode(tool.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
    // Real codex records carry timeUnixNano="0" — the mapped time must come
    // from observedTimeUnixNano, not the sentinel (1970 rows otherwise).
    expect(prompt.meta.tsRequest).toBe(1752300000000);
    expect(tool.meta.tsRequest).toBe(1752300001000);
  });

  test("no PII (email / account id) survives into any mapped Call", () => {
    const blob = mapCodexOtlpToCalls(fixture)
      .map((c) => decode(c.request.bodyBytes) + JSON.stringify(c.request.messages))
      .join("");
    expect(blob).not.toContain("@");
    expect(blob.toLowerCase()).not.toContain("account_id");
  });
});

describe("buildCodexOtelArgs / buildCodexOtelEnv (vendor knobs only, R2)", () => {
  test("points codex's exporter at /v1/logs via -c, with NO token on argv", () => {
    const args = buildCodexOtelArgs("http://127.0.0.1:4318");
    expect(args).toContain("otel.log_user_prompt=true");
    const exporter = args[args.length - 1]!;
    expect(exporter).toContain('endpoint = "http://127.0.0.1:4318/v1/logs"');
    expect(exporter).toContain('protocol = "json"');
    // every knob is a `-c` override, never a config-file write
    expect(args.filter((a) => a === "-c").length).toBe(2);
    // the token must NOT appear anywhere on argv (ps / audit-log exposure)
    expect(args.join(" ")).not.toContain("x-beagle-run");
  });

  test("the token rides the SIGNAL-SPECIFIC header var, not argv, not the generic var", () => {
    const env = buildCodexOtelEnv("run-token-xyz");
    // codex's otlp crate resolves LOGS_HEADERS **or else** the generic var —
    // replace, not merge (verified live). Only the signal-specific var
    // guarantees the token wins over a user's own OTLP env; and leaving the
    // generic var alone preserves it for codex's child processes.
    expect(env.OTEL_EXPORTER_OTLP_LOGS_HEADERS).toBe("x-beagle-run=run-token-xyz");
    expect(env.OTEL_EXPORTER_OTLP_HEADERS).toBeUndefined();
    // and the args builder — the only thing on the command line — never sees it
    expect(buildCodexOtelArgs("http://127.0.0.1:4318").join(" ")).not.toContain("run-token-xyz");
  });

  test("inherited OTLP compression vars are marked for removal (codex lacks gzip support)", () => {
    const env = buildCodexOtelEnv("t");
    // present as keys with undefined values — execAgent deletes those from the
    // child env; codex is compiled without gzip, so an inherited =gzip kills
    // its exporter at startup (silent zero capture).
    expect("OTEL_EXPORTER_OTLP_COMPRESSION" in env).toBe(true);
    expect(env.OTEL_EXPORTER_OTLP_COMPRESSION).toBeUndefined();
    expect("OTEL_EXPORTER_OTLP_LOGS_COMPRESSION" in env).toBe(true);
    expect(env.OTEL_EXPORTER_OTLP_LOGS_COMPRESSION).toBeUndefined();
  });
});

describe("buildOtelEnv (vendor knobs only, R2)", () => {
  test("uses SIGNAL-SPECIFIC OTLP vars so a user's own OTel env can't shadow the export", () => {
    const env = buildOtelEnv("http://127.0.0.1:4318", "run-token-abc");
    expect(env.CLAUDE_CODE_ENABLE_TELEMETRY).toBe("1");
    expect(env.OTEL_LOGS_EXPORTER).toBe("otlp");
    // signal-specific (spec: full URL, wins over user/org generic vars) —
    // verified live against Claude Code 2.1.193 with a hostile generic var set
    expect(env.OTEL_EXPORTER_OTLP_LOGS_PROTOCOL).toBe("http/json");
    expect(env.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT).toBe("http://127.0.0.1:4318/v1/logs");
    expect(env.OTEL_EXPORTER_OTLP_LOGS_HEADERS).toContain("run-token-abc");
    // the GENERIC vars are left alone so an org's own metrics/traces export
    // keeps working while the agent is watched
    expect("OTEL_EXPORTER_OTLP_ENDPOINT" in env).toBe(false);
    expect("OTEL_EXPORTER_OTLP_HEADERS" in env).toBe(false);
    // content flags that make tool inputs (a real leak surface) show up at all
    expect(env.OTEL_LOG_USER_PROMPTS).toBe("1");
    expect(env.OTEL_LOG_TOOL_DETAILS).toBe("1");
    expect(env.OTEL_LOG_TOOL_CONTENT).toBe("1");
    // inherited compression would break the json-only loopback receiver
    expect("OTEL_EXPORTER_OTLP_COMPRESSION" in env).toBe(true);
    expect(env.OTEL_EXPORTER_OTLP_COMPRESSION).toBeUndefined();
    expect(env.OTEL_EXPORTER_OTLP_LOGS_COMPRESSION).toBeUndefined();
  });
});

describe("mergeHookIntoSettings (user --settings coexists with the hook)", () => {
  test("inline JSON: user settings pass through, hook appended to their PostToolUse", () => {
    const user = JSON.stringify({
      theme: "dark",
      hooks: { PostToolUse: [{ hooks: [{ type: "command", command: "user-hook" }] }], Stop: [] },
    });
    const merged = mergeHookIntoSettings(user, "beagle-hook") as {
      theme: string;
      hooks: { PostToolUse: Array<{ hooks: Array<{ command: string }> }>; Stop: unknown[] };
    };
    expect(merged.theme).toBe("dark");
    expect(merged.hooks.Stop).toEqual([]);
    expect(merged.hooks.PostToolUse.length).toBe(2); // user's first, beagle's appended
    expect(merged.hooks.PostToolUse[0]!.hooks[0]!.command).toBe("user-hook");
    expect(merged.hooks.PostToolUse[1]!.hooks[0]!.command).toBe("beagle-hook");
  });

  test("malformed input degrades to hook-only settings (capture never fails open)", () => {
    const merged = mergeHookIntoSettings("/nonexistent/settings.json", "beagle-hook");
    expect(JSON.stringify(merged)).toContain("beagle-hook");
    const merged2 = mergeHookIntoSettings("{not json", "beagle-hook");
    expect(JSON.stringify(merged2)).toContain("beagle-hook");
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

describe("OtlpReceiver — BEAGLE_OTLP_DUMP diagnostic (off by default)", () => {
  let receiver: OtlpReceiver;
  let got: unknown[];
  let port: number;
  let prev: string | undefined;
  let dir: string;

  beforeEach(async () => {
    prev = process.env.BEAGLE_OTLP_DUMP;
    dir = mkdtempSync(join(tmpdir(), "beagle-otlp-dump-"));
    got = [];
    receiver = new OtlpReceiver({ token: "t", onCalls: (exs) => got.push(...exs) });
    port = await receiver.listen(0);
  });
  afterEach(() => {
    receiver.close();
    if (prev === undefined) delete process.env.BEAGLE_OTLP_DUMP;
    else process.env.BEAGLE_OTLP_DUMP = prev;
  });

  const send = (path: string, body: string) =>
    fetch(`http://127.0.0.1:${port}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": "t" },
      body,
    });

  test("unset → nothing is written (the default is silent)", async () => {
    delete process.env.BEAGLE_OTLP_DUMP;
    await send("/v1/logs", JSON.stringify(logs(turnRecords())));
    expect(readdirSync(dir)).toEqual([]);
  });

  test("set → each body is written verbatim, route-tagged and sequenced", async () => {
    process.env.BEAGLE_OTLP_DUMP = dir;
    const body1 = JSON.stringify(logs(turnRecords({ prompt: "first turn" })));
    await send("/v1/logs", body1);
    await send("/v1/hook", JSON.stringify({ session_id: "s", tool_name: "Bash", tool_input: { command: "x" }, tool_response: "y" }));
    expect(readdirSync(dir).sort()).toEqual(["otlp-0001-logs.json", "otlp-0002-hook.json"].sort());
    // verbatim: the dumped bytes equal exactly what was POSTed, so the raw OTLP
    // stream can be inspected byte-for-byte — the whole point of the diagnostic.
    expect(readFileSync(join(dir, "otlp-0001-logs.json"), "utf8")).toBe(body1);
  });

  test("an unwritable dump path never disturbs capture (best-effort, swallowed)", async () => {
    // parent is a regular file → mkdir/write throws; the POST must still 200 and
    // the call must still be delivered. Capture never fails because of a dump.
    const file = join(dir, "not-a-dir");
    writeFileSync(file, "x");
    process.env.BEAGLE_OTLP_DUMP = join(file, "nested");
    const r = await send("/v1/logs", JSON.stringify(logs(turnRecords())));
    expect(r.status).toBe(200);
    expect(got.length).toBe(1);
  });
});

describe("mapHookToCall — PostToolUse hook tool-OUTPUT capture (Mode B gap fix)", () => {
  // Claude Code's OTel export omits tool RESULT content; a PostToolUse hook
  // supplies it. Shape verified live against Claude Code 2.1.193.
  const hook = (over: Record<string, unknown> = {}) => ({
    session_id: "sess-hook-1",
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_input: { command: "cat secrets.env" },
    tool_response: "export AWS_SECRET=AKIAZQ3DRSTUVWXY2345\n",
    tool_use_id: "toolu_1",
    ...over,
  });

  test("a secret in the tool OUTPUT is captured, scannable, source=otel", () => {
    const c = mapHookToCall(hook(), ctx)!;
    expect(c).not.toBeNull();
    expect(c.source).toBe("otel");
    expect(c.convId).toBe("sess-hook-1"); // chains into the same session as the turns
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345"); // the file content
    expect(c.endpoint).toContain("Bash");
  });

  test("tool_input is scanned too (a secret in a command, not just its output)", () => {
    const c = mapHookToCall(hook({ tool_response: "ok", tool_input: { command: "curl -H 'Authorization: AKIAZQ3DRSTUVWXY2345'" } }), ctx)!;
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("an object tool_response is serialized so nested secrets are still scannable", () => {
    const c = mapHookToCall(hook({ tool_response: { stdout: "AKIAZQ3DRSTUVWXY2345", exitCode: 0 } }), ctx)!;
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("no tool content → null (nothing to scan)", () => {
    expect(mapHookToCall({ session_id: "s", tool_name: "X" }, ctx)).toBeNull();
  });

  test("malformed hook payload → null, never throws", () => {
    expect(mapHookToCall(null, ctx)).toBeNull();
    expect(mapHookToCall("not json", ctx)).toBeNull();
    expect(mapHookToCall(12345, ctx)).toBeNull();
  });
});

describe("buildHookSettings — the Beagle-owned PostToolUse hook", () => {
  test("registers a no-matcher PostToolUse command hook (fires for every tool)", () => {
    const s = buildHookSettings("/abs/beagle __hook") as any;
    const entry = s.hooks.PostToolUse[0];
    expect(entry.matcher).toBeUndefined(); // no matcher = all tools (Bash, Read, MCP, …)
    expect(entry.hooks[0]).toEqual({ type: "command", command: "/abs/beagle __hook" });
  });
});

describe("OtlpReceiver — /v1/hook route (tool-output capture)", () => {
  let receiver: OtlpReceiver;
  let got: unknown[];
  let port: number;
  beforeEach(async () => {
    got = [];
    receiver = new OtlpReceiver({ token: "run-tok", onCalls: (exs) => got.push(...exs) });
    port = await receiver.listen(0);
  });
  afterEach(() => receiver.close());

  const hookPayload = { session_id: "s1", tool_name: "Bash", tool_input: { command: "cat .env" }, tool_response: "KEY=AKIAZQ3DRSTUVWXY2345" };

  test("accepts a hook payload with the token and yields a scannable Call", async () => {
    const r = await fetch(`http://127.0.0.1:${port}/v1/hook`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": "run-tok" },
      body: JSON.stringify(hookPayload),
    });
    expect(r.status).toBe(200);
    expect(got.length).toBe(1);
    const c = got[0] as { source: string; request: { bodyBytes: Uint8Array } };
    expect(c.source).toBe("otel");
    expect(decode(c.request.bodyBytes)).toContain("AKIAZQ3DRSTUVWXY2345");
  });

  test("the hook route enforces the same run token", async () => {
    const r = await fetch(`http://127.0.0.1:${port}/v1/hook`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": "wrong" },
      body: JSON.stringify(hookPayload),
    });
    expect(r.status).toBe(401);
    expect(got.length).toBe(0);
  });
});
