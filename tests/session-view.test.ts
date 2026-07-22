import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store, type CallRecord } from "../src/core/store/store";
import { buildSessionTurns, listSessions } from "../src/viewer/session-view";
import { listCalls } from "../src/viewer/feed-query";
import { ulid } from "../src/core/store/ulid";

const enc = (s: string) => new TextEncoder().encode(s);

function call(overrides: Partial<CallRecord> = {}): CallRecord {
  return {
    id: ulid(),
    sessionId: "sess-1",
    runId: "run-1",
    source: "wire",
    agent: "claude-code",
    provider: "anthropic",
    model: "claude-sonnet-5",
    endpoint: "/v1/messages",
    tsRequest: Date.now(),
    tsResponse: Date.now(),
    status: 200,
    scanState: "ok",
    captureState: "ok",
    sessionTier: "conv-id",
    requestBody: enc('{"messages":[{"role":"user","content":"hi"}]}'),
    requestHeaders: [],
    responseBody: enc('{"content":[{"type":"text","text":"hello"}]}'),
    responseHeaders: [],
    sseRaw: null,
    searchText: "",
    ...overrides,
  };
}

// An anthropic-format request body carrying the given messages.
const body = (messages: Array<{ role: string; content: string }>, system?: string) =>
  enc(JSON.stringify(system ? { system, messages } : { messages }));
const resp = (text: string) => enc(JSON.stringify({ content: [{ type: "text", text }] }));

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "beagle-sessview-"));
});

describe("listSessions", () => {
  test("aggregates one row per session, newest activity first", () => {
    const store = Store.open(dir);
    store.insertCall(call({ sessionId: "a", tsRequest: 1000 }));
    store.insertCall(call({ sessionId: "a", tsRequest: 2000 }));
    store.insertCall(call({ sessionId: "b", tsRequest: 5000, agent: "codex", source: "otel" }));
    const rows = listSessions(store, 100);
    expect(rows.map((r) => r.sessionId)).toEqual(["b", "a"]);
    expect(rows[0]).toMatchObject({ calls: 1, agent: "codex", source: "otel" });
    expect(rows[1]).toMatchObject({ calls: 2, firstTs: 1000, lastTs: 2000, source: "wire" });
    store.close();
  });

  test("the response echoed back as the next turn's assistant message is not re-shown", () => {
    // Stateless APIs resend the previous RESPONSE as the next request's
    // assistant message. The delta view must not read as a duplicate.
    const store = Store.open(dir);
    store.insertCall(call({
      tsRequest: 1000,
      requestBody: body([{ role: "user", content: "q1" }]),
      responseBody: resp("answer one"),
    }));
    store.insertCall(call({
      tsRequest: 2000,
      requestBody: body([
        { role: "user", content: "q1" },
        { role: "assistant", content: "answer one" }, // exact echo of turn 1's response
        { role: "user", content: "q2" },
      ]),
      responseBody: resp("answer two"),
    }));
    store.insertCall(call({
      tsRequest: 3000,
      requestBody: body([
        { role: "user", content: "q1" },
        { role: "assistant", content: "answer one" },
        { role: "user", content: "q2" },
        { role: "assistant", content: "answer two REWORDED" }, // NOT an exact echo
        { role: "user", content: "q3" },
      ]),
      responseBody: resp("answer three"),
    }));
    const turns = buildSessionTurns(store, "sess-1").turns;
    expect(turns[1]!.messages.map((m) => m.content)).toEqual(["q2"]); // echo dropped
    // a reworded assistant message is NOT an echo — it must stay visible
    expect(turns[2]!.messages.map((m) => m.content)).toEqual(["answer two REWORDED", "q3"]);
    store.close();
  });

  test("an echo carrying a leak is NOT deduped — the secret stays highlightable (R7)", () => {
    // A secret first appears in turn 1's RESPONSE (not a leak there — responses
    // aren't request-scanned). Turn 2 echoes it back → now a leak. Dropping the
    // echo would show "secret sent" with the value highlighted nowhere.
    const SECRET = "AKIAZQ3DRSTUVWXY2345";
    const echo = `here is the key ${SECRET}`;
    const store = Store.open(dir);
    store.insertCall(call({
      tsRequest: 1000,
      requestBody: body([{ role: "user", content: "q1" }]),
      responseBody: resp(echo),
    }));
    const t2 = body([
      { role: "user", content: "q1" },
      { role: "assistant", content: echo },
      { role: "user", content: "q2" },
    ]);
    const id2 = ulid();
    const span = new TextDecoder().decode(t2).indexOf(SECRET);
    store.insertCall(call({ id: id2, tsRequest: 2000, requestBody: t2, responseBody: resp("ok") }));
    store.upsertLeakEvent({
      fingerprint: "fp", sessionId: "sess-1", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "anthropic", callId: id2, ts: Date.now(),
      spanStart: span, spanEnd: span + SECRET.length,
    });
    const turns = buildSessionTurns(store, "sess-1").turns;
    // turn 2 keeps the echoed assistant message BECAUSE it holds the leak
    expect(turns[1]!.messages.some((m) => m.content.includes(SECRET))).toBe(true);
    expect(turns[1]!.leaks.some((l) => l.value === SECRET)).toBe(true);
    store.close();
  });

  test("utility: only sessions whose EVERY call is a one-shot get the flag", () => {
    const store = Store.open(dir);
    store.insertCall(call({ sessionId: "title-turn", oneShot: true }));
    store.insertCall(call({ sessionId: "convo", oneShot: false }));
    store.insertCall(call({ sessionId: "mixed", oneShot: true }));
    store.insertCall(call({ sessionId: "mixed", oneShot: false, tsRequest: 2000 }));
    const byId = new Map(listSessions(store, 100).map((r) => [r.sessionId, r.utility]));
    expect(byId.get("title-turn")).toBe(true);
    expect(byId.get("convo")).toBe(false);
    expect(byId.get("mixed")).toBe(false); // one real call → a real conversation
    store.close();
  });

  test("the transcript view carries utility itself — badge independent of navigation", () => {
    const store = Store.open(dir);
    store.insertCall(call({ sessionId: "t", oneShot: true }));
    store.insertCall(call({ sessionId: "c", oneShot: false }));
    expect(buildSessionTurns(store, "t").utility).toBe(true);
    expect(buildSessionTurns(store, "c").utility).toBe(false);
    expect(buildSessionTurns(store, "nonexistent").utility).toBe(false);
    store.close();
  });

  test("a session with both wire and otel calls reads 'mixed'", () => {
    const store = Store.open(dir);
    store.insertCall(call({ sessionId: "m", source: "wire" }));
    store.insertCall(call({ sessionId: "m", source: "otel" }));
    expect(listSessions(store, 100)[0]!.source).toBe("mixed");
    store.close();
  });

  test("model is the most recent non-null model, not an arbitrary one", () => {
    const store = Store.open(dir);
    store.insertCall(call({ sessionId: "a", tsRequest: 1, model: "old-model" }));
    store.insertCall(call({ sessionId: "a", tsRequest: 2, model: undefined }));
    store.insertCall(call({ sessionId: "a", tsRequest: 3, model: "new-model" }));
    store.insertCall(call({ sessionId: "a", tsRequest: 4, model: undefined }));
    expect(listSessions(store, 100)[0]!.model).toBe("new-model");
    store.close();
  });

  test("title is the earliest call's summary (reads like a conversation title)", () => {
    const store = Store.open(dir);
    store.insertCall(call({ sessionId: "a", tsRequest: 3, summary: "later turn" }));
    store.insertCall(call({ sessionId: "a", tsRequest: 1, summary: "hey is hyper connected?" }));
    store.insertCall(call({ sessionId: "a", tsRequest: 2, summary: "middle" }));
    expect(listSessions(store, 100)[0]!.title).toBe("hey is hyper connected?");
    store.close();
  });

  test("title skips buildSummary placeholder sentinels, takes the next real prompt", () => {
    const store = Store.open(dir);
    // the opening turn was a tool call with no message content; the title
    // should be the next meaningful summary, not the placeholder.
    store.insertCall(call({ sessionId: "a", tsRequest: 1, summary: "(no message content)" }));
    store.insertCall(call({ sessionId: "a", tsRequest: 2, summary: "unparsed call (raw view available)" }));
    store.insertCall(call({ sessionId: "a", tsRequest: 3, summary: "the real opening ask" }));
    expect(listSessions(store, 100)[0]!.title).toBe("the real opening ask");
    store.close();
  });

  test("a session with only placeholder summaries has no title", () => {
    const store = Store.open(dir);
    store.insertCall(call({ sessionId: "a", tsRequest: 1, summary: "(no message content)" }));
    expect(listSessions(store, 100)[0]!.title).toBeUndefined();
    store.close();
  });

  test("counts the session's leak events", () => {
    const store = Store.open(dir);
    const c = call({ sessionId: "a" });
    store.insertCall(c);
    store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "a", detector: "gitleaks",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "anthropic", ts: Date.now(), callId: c.id,
    });
    expect(listSessions(store, 100)[0]!.leaks).toBe(1);
    store.close();
  });
});

describe("buildSessionTurns — the conversation delta", () => {
  test("wire turns show only the messages ADDED since the previous call", () => {
    const store = Store.open(dir);
    // Turn 1: history [u1]. Turn 2 resends [u1, a1, u2] — the wire reality.
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000,
      requestBody: body([{ role: "user", content: "first question" }], "be brief"),
      responseBody: resp("first answer"),
    }));
    store.insertCall(call({
      id: ulid(2000), tsRequest: 2000,
      requestBody: body([
        { role: "user", content: "first question" },
        { role: "assistant", content: "first answer" },
        { role: "user", content: "second question" },
      ]),
      responseBody: resp("second answer"),
    }));
    const v = buildSessionTurns(store, "sess-1");
    expect(v.system).toBe("be brief");
    expect(v.turns.length).toBe(2);
    expect(v.turns[0]!.messages).toEqual([{ role: "user", content: "first question" }]);
    expect(v.turns[0]!.responseText).toBe("first answer");
    // the repeated history must NOT replay — only the new tail, and the
    // assistant echo of turn 1's response (already read one card up) is
    // deduped too: the turn shows just what the USER added.
    expect(v.turns[1]!.messages).toEqual([
      { role: "user", content: "second question" },
    ]);
    expect(v.turns[1]!.responseText).toBe("second answer");
    store.close();
  });

  test("a truncated wire turn (0 parsed messages) doesn't reset the delta baseline", () => {
    // Regression: an unparseable/truncated wire body yields 0 messages; if it
    // clobbered the running history baseline, the NEXT full turn would re-show
    // its entire history as new — the repetition the delta exists to kill.
    const store = Store.open(dir);
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000,
      requestBody: body([
        { role: "user", content: "q1" },
        { role: "assistant", content: "a1" },
        { role: "user", content: "q2" },
      ]),
    }));
    // a truncated capture: body is not valid provider JSON → 0 parsed messages
    store.insertCall(call({
      id: ulid(2000), tsRequest: 2000, captureState: "truncated",
      requestBody: enc("\x00\x01 not json"),
    }));
    store.insertCall(call({
      id: ulid(3000), tsRequest: 3000,
      requestBody: body([
        { role: "user", content: "q1" },
        { role: "assistant", content: "a1" },
        { role: "user", content: "q2" },
        { role: "assistant", content: "a2" },
        { role: "user", content: "q3" },
      ]),
    }));
    const v = buildSessionTurns(store, "sess-1");
    expect(v.turns.length).toBe(3);
    // turn 3 diffs against turn 1's history (turn 2 didn't parse) → only the tail
    expect(v.turns[2]!.messages).toEqual([
      { role: "assistant", content: "a2" },
      { role: "user", content: "q3" },
    ]);
    store.close();
  });

  test("a rewritten history (compaction) falls back to the newest message, not a bogus tail", () => {
    const store = Store.open(dir);
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000,
      requestBody: body([
        { role: "user", content: "long old question" },
        { role: "assistant", content: "long old answer" },
      ]),
    }));
    // compaction rewrote the history: same length +1, but different content
    store.insertCall(call({
      id: ulid(2000), tsRequest: 2000,
      requestBody: body([
        { role: "user", content: "[summary of the conversation]" },
        { role: "assistant", content: "ok" },
        { role: "user", content: "next question" },
      ]),
    }));
    const v = buildSessionTurns(store, "sess-1");
    // prefix mismatch → show just the newest message rather than mis-slicing
    expect(v.turns[1]!.messages).toEqual([{ role: "user", content: "next question" }]);
    store.close();
  });

  test("Mode B turns show their persisted display messages, no delta math", () => {
    const store = Store.open(dir);
    // A claude-code Mode B session: a prompt turn, then a tool-call turn. The
    // bodies are scan text (NOT provider JSON) — structure rides display_messages.
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000, source: "otel", endpoint: "otel:claude_code.turn",
      requestBody: enc("run the tests"),
      responseBody: enc("Running them now."),
      displayMessages: [{ role: "user", content: "run the tests" }],
    }));
    store.insertCall(call({
      id: ulid(2000), tsRequest: 2000, source: "otel", endpoint: "otel:claude_code.turn",
      requestBody: enc('{"command":"bun test"}'),
      responseBody: null,
      displayMessages: [{ role: "tool", content: 'Bash: {"command":"bun test"}' }],
    }));
    const v = buildSessionTurns(store, "sess-1");
    expect(v.turns.length).toBe(2);
    expect(v.turns[0]!.messages).toEqual([{ role: "user", content: "run the tests" }]);
    // Mode B stores the response text directly as the response body
    expect(v.turns[0]!.responseText).toBe("Running them now.");
    expect(v.turns[1]!.messages).toEqual([{ role: "tool", content: 'Bash: {"command":"bun test"}' }]);
    store.close();
  });

  test("legacy Mode B rows (no display_messages) fall back to the scan text, not an empty turn", () => {
    const store = Store.open(dir);
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000, source: "otel", endpoint: "otel:claude_code.turn",
      requestBody: enc('{"command":"claude mcp list"}'), responseBody: null,
    }));
    const v = buildSessionTurns(store, "sess-1");
    // labeled by what it IS (the request), not its provenance
    expect(v.turns[0]!.messages).toEqual([
      { role: "request", content: '{"command":"claude mcp list"}' },
    ]);
    store.close();
  });

  test("turns come back in chronological order even if inserted out of order", () => {
    const store = Store.open(dir);
    store.insertCall(call({ id: ulid(2000), tsRequest: 2000 }));
    store.insertCall(call({ id: ulid(1000), tsRequest: 1000 }));
    const v = buildSessionTurns(store, "sess-1");
    expect(v.turns.map((t) => t.tsRequest)).toEqual([1000, 2000]);
    store.close();
  });

  test("caps the transcript and says so", () => {
    const store = Store.open(dir);
    for (let i = 0; i < 5; i++) store.insertCall(call({ id: ulid(i + 1), tsRequest: i + 1 }));
    const v = buildSessionTurns(store, "sess-1", 3);
    expect(v.turns.length).toBe(3);
    expect(v.truncated).toBe(true);
    expect(buildSessionTurns(store, "sess-1", 10).truncated).toBe(false);
    store.close();
  });

  test("unknown session yields an empty view, not an error", () => {
    const store = Store.open(dir);
    const v = buildSessionTurns(store, "nope");
    expect(v.turns).toEqual([]);
    expect(v.system).toBeNull();
    store.close();
  });

  test("openai-responses tool flow: calls land on their OWN turn's response; matched echoes drop; results get names (turn clarity)", () => {
    const store = Store.open(dir);
    // Turn 1: user asks; the model responds with a bash function_call.
    const req1 = { input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "run the tests" }] }] };
    const resp1 = { output: [{ type: "function_call", call_id: "c1", name: "bash", arguments: '{"command":"bun test"}' }] };
    // Turn 2: the request echoes the fc and adds the output; model replies with text.
    const req2 = { input: [
      ...req1.input,
      { type: "function_call", call_id: "c1", name: "bash", arguments: '{"command":"bun test"}' },
      { type: "function_call_output", call_id: "c1", output: "452 pass" },
    ] };
    const resp2 = { output: [{ type: "message", content: [{ type: "output_text", text: "All green." }] }] };
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000, endpoint: "/v1/responses",
      requestBody: enc(JSON.stringify(req1)), responseBody: enc(JSON.stringify(resp1)),
    }));
    store.insertCall(call({
      id: ulid(2000), tsRequest: 2000, endpoint: "/v1/responses",
      requestBody: enc(JSON.stringify(req2)), responseBody: enc(JSON.stringify(resp2)),
    }));
    const turns = buildSessionTurns(store, "sess-1").turns;
    // Turn 1's response section carries the model's tool call — no longer
    // invisible until the next request echoes it.
    expect(turns[0]!.responseCalls).toEqual([
      { tool: "bash", detail: "bun test", callId: "c1", args: '{"command":"bun test"}' },
    ]);
    // Turn 2: the fc echo is DROPPED — the call card sits at the end of the
    // previous turn's response, adjacent to this result across the boundary.
    // The result keeps the call's name and detail so the pair stays legible.
    const t2 = turns[1]!.messages;
    expect(t2.map((m) => [m.kind, m.tool, m.detail])).toEqual([
      ["result", "bash", "bun test"],
    ]);
    expect(turns[1]!.responseText).toBe("All green.");
    store.close();
  });

  test("an fc echo carrying a LEAK is never dropped — the request copy is the scanned occurrence (R7)", () => {
    const SECRET = "AKIAZQ3DRSTUVWXY2345";
    const store = Store.open(dir);
    const req1 = { input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }] };
    const resp1 = { output: [{ type: "function_call", call_id: "c1", name: "bash", arguments: `{"command":"x ${SECRET}"}` }] };
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000, endpoint: "/v1/responses",
      requestBody: enc(JSON.stringify(req1)), responseBody: enc(JSON.stringify(resp1)),
    }));
    const req2str = JSON.stringify({ input: [
      ...req1.input,
      { type: "function_call", call_id: "c1", name: "bash", arguments: `{"command":"x ${SECRET}"}` },
      { type: "function_call_output", call_id: "c1", output: "done" },
    ] });
    const id2 = ulid(2000);
    store.insertCall(call({
      id: id2, tsRequest: 2000, endpoint: "/v1/responses",
      requestBody: enc(req2str), responseBody: enc(JSON.stringify({ output: [] })),
    }));
    const at = req2str.indexOf(SECRET);
    store.upsertLeakEvent({
      fingerprint: "fp", sessionId: "sess-1", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "openai", callId: id2, ts: 2000, spanStart: at, spanEnd: at + SECRET.length,
    });
    const turns = buildSessionTurns(store, "sess-1").turns;
    // matched echo, but leak-bearing → stays visible (and highlightable)
    expect(turns[1]!.messages.some((m) => m.kind === "call" && String(m.content).includes(SECRET))).toBe(true);
    store.close();
  });

  test("an fc echo whose previous response did NOT parse is kept (a wrong drop must be impossible)", () => {
    const store = Store.open(dir);
    const req1 = { input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }] };
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000, endpoint: "/v1/responses",
      requestBody: enc(JSON.stringify(req1)),
      responseBody: enc("\x00 not parseable"), // truncated capture
    }));
    const req2 = { input: [
      ...req1.input,
      { type: "function_call", call_id: "cX", name: "bash", arguments: "{}" },
      { type: "function_call_output", call_id: "cX", output: "out" },
    ] };
    store.insertCall(call({
      id: ulid(2000), tsRequest: 2000, endpoint: "/v1/responses",
      requestBody: enc(JSON.stringify(req2)), responseBody: enc(JSON.stringify({ output: [] })),
    }));
    const turns = buildSessionTurns(store, "sess-1").turns;
    expect(turns[0]!.responseCalls).toEqual([]); // nothing parsed
    // no prev responseCalls to match → the echo must stay a visible card
    expect(turns[1]!.messages.some((m) => m.kind === "call")).toBe(true);
    store.close();
  });

  test("a leak on turn N+1 highlights turn N's response section (backward propagation, R7)", () => {
    const SECRET = "AKIAZQ3DRSTUVWXY2345";
    const store = Store.open(dir);
    const req1 = { input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "deploy" }] }] };
    const resp1 = { output: [{ type: "function_call", call_id: "c1", name: "bash", arguments: `{"command":"deploy --key ${SECRET}"}` }] };
    const req2str = JSON.stringify({ input: [
      ...req1.input,
      { type: "function_call", call_id: "c1", name: "bash", arguments: `{"command":"deploy --key ${SECRET}"}` },
      { type: "function_call_output", call_id: "c1", output: "done" },
    ] });
    const id2 = ulid(2000);
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000, endpoint: "/v1/responses",
      requestBody: enc(JSON.stringify(req1)), responseBody: enc(JSON.stringify(resp1)),
    }));
    store.insertCall(call({
      id: id2, tsRequest: 2000, endpoint: "/v1/responses",
      requestBody: enc(req2str), responseBody: enc(JSON.stringify({ output: [] })),
    }));
    const start = req2str.indexOf(SECRET);
    store.upsertLeakEvent({
      fingerprint: "fp", sessionId: "sess-1", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "openai", callId: id2, ts: 2000,
      spanStart: start, spanEnd: start + SECRET.length,
    });
    const turns = buildSessionTurns(store, "sess-1").turns;
    // The secret is scanned on call 2, but DISPLAYED first on turn 1's
    // response card — the propagated leaks make that first render highlight.
    expect(turns[0]!.responseLeaks.some((l) => l.value === SECRET)).toBe(true);
    expect(turns[1]!.leaks.some((l) => l.value === SECRET)).toBe(true);
    store.close();
  });

  test("leak propagation skips an interposed Mode B row — the WIRE response card gets the highlight (R7)", () => {
    const SECRET = "AKIAZQ3DRSTUVWXY2345";
    const store = Store.open(dir);
    const req1 = { input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "deploy" }] }] };
    const resp1 = { output: [{ type: "function_call", call_id: "c1", name: "bash", arguments: `{"command":"x ${SECRET}"}` }] };
    store.insertCall(call({
      id: ulid(1000), tsRequest: 1000, endpoint: "/v1/responses",
      requestBody: enc(JSON.stringify(req1)), responseBody: enc(JSON.stringify(resp1)),
    }));
    // A tool hook fires between response and next request → an otel row lands
    // BETWEEN the two wire calls (the "mixed" session shape).
    store.insertCall(call({
      id: ulid(1500), tsRequest: 1500, source: "otel", endpoint: "otel:tool_output:bash",
      requestBody: enc("hook output"), responseBody: null,
      displayMessages: [{ role: "tool", content: "bash: hook output" }],
    }));
    const req2str = JSON.stringify({ input: [
      ...req1.input,
      { type: "function_call", call_id: "c1", name: "bash", arguments: `{"command":"x ${SECRET}"}` },
      { type: "function_call_output", call_id: "c1", output: "ok" },
    ] });
    const id3 = ulid(2000);
    store.insertCall(call({
      id: id3, tsRequest: 2000, endpoint: "/v1/responses",
      requestBody: enc(req2str), responseBody: enc(JSON.stringify({ output: [] })),
    }));
    const at = req2str.indexOf(SECRET);
    store.upsertLeakEvent({
      fingerprint: "fp", sessionId: "sess-1", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "openai", callId: id3, ts: 2000, spanStart: at, spanEnd: at + SECRET.length,
    });
    const turns = buildSessionTurns(store, "sess-1").turns;
    // wire turn 0 (whose responseCalls card DISPLAYS the secret) gets the
    // propagated leaks — not the interposed otel row.
    expect(turns[0]!.source).toBe("wire");
    expect(turns[0]!.responseLeaks.some((l) => l.value === SECRET)).toBe(true);
    expect(turns[1]!.source).toBe("otel");
    expect(turns[1]!.responseLeaks).toEqual([]);
    store.close();
  });

  test("turn carries the leak values to highlight", () => {
    const store = Store.open(dir);
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const req = `{"messages":[{"role":"user","content":"key ${secret} here"}]}`;
    const c = call({ id: ulid(1000), tsRequest: 1000, requestBody: enc(req) });
    store.insertCall(c);
    const start = req.indexOf(secret);
    store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "sess-1", detector: "gitleaks",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "anthropic", ts: 1000, callId: c.id,
      spanStart: start, spanEnd: start + secret.length,
    });
    const v = buildSessionTurns(store, "sess-1");
    expect(v.turns[0]!.leaks).toEqual([
      { value: secret, secretType: "aws-access-key-id", tier: "structured" },
    ]);
    store.close();
  });
});

// ---- Subscription turn sequencing ----
// Codex/Claude capture lands one row per tool execution beside response rows.
// The projection uses turn_link plus chronology to expose the same boundary
// model as Pi: response tool call → next request tool result.
describe("buildSessionTurns — subscription sequencing", () => {
  const toolCards = (callId: string | undefined, cmd: string, out: string) => [
    { role: "tool", content: cmd, tool: "exec", kind: "call" as const, ...(callId ? { callId } : {}) },
    { role: "tool", content: out, tool: "exec", kind: "result" as const, ...(callId ? { callId } : {}) },
  ];
  const codexPrompt = (overrides: Partial<CallRecord> = {}) =>
    call({
      source: "otel", endpoint: "otel:codex:user_prompt", agent: "codex",
      promptKey: "hashA", displayMessages: [{ role: "user", content: "how does memory work?" }],
      requestBody: enc("how does memory work?"), responseBody: enc("the stitched answer"),
      ...overrides,
    });
  const codexTool = (callId: string, overrides: Partial<CallRecord> = {}) =>
    call({
      source: "otel", endpoint: "otel:codex:tool_result:exec", agent: "codex",
      promptKey: undefined, displayMessages: toolCards(callId, `{"cmd":"ls ${callId}"}`, `out ${callId}`),
      requestBody: enc(`exec\nls ${callId}\nout ${callId}`), responseBody: null, tsResponse: undefined,
      ...overrides,
    });

  test("subscription sessions use pi-like call boundaries and keep every feed row stable", () => {
    const store = Store.open(dir);
    const t0 = Date.now();

    const codexPromptRow = codexPrompt({ id: ulid(t0), tsRequest: t0 });
    const codexTool1 = codexTool("c1", { id: ulid(t0 + 1000), tsRequest: t0 + 1000 });
    const codexTool2 = codexTool("c2", { id: ulid(t0 + 2000), tsRequest: t0 + 2000 });
    for (const c of [codexPromptRow, codexTool1, codexTool2]) store.insertCall(c);
    store.linkTurns("sess-1", [
      { linkKey: "call:c1", promptKey: "hashA", ordinal: 0, seq: 0 },
      { linkKey: "call:c2", promptKey: "hashA", ordinal: 0, seq: 1 },
    ]);

    const codex = buildSessionTurns(store, "sess-1").turns;
    expect(codex).toHaveLength(3);
    expect(codex.map((t) => ({
      request: t.messages.map((m) => m.kind ?? m.role),
      responseCalls: t.responseCalls.map((c) => c.callId),
      response: t.responseText,
    }))).toEqual([
      { request: ["user"], responseCalls: ["c1"], response: null },
      { request: ["result"], responseCalls: ["c2"], response: null },
      { request: ["result"], responseCalls: [], response: "the stitched answer" },
    ]);
    expect(new Set(listCalls(store, 20).map((r) => r.id))).toEqual(
      new Set([codexPromptRow.id, codexTool1.id, codexTool2.id]),
    );
    store.close();
  });

  test("claude keeps each reported response and carries hook results into the next request", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    const first = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude",
      promptKey: "prompt-uuid-chain",
      displayMessages: [
        { role: "user", content: "research this" },
        { role: "tool", content: '{"query":"first"}', tool: "WebSearch", kind: "call" },
      ],
      requestBody: enc("research this\nfirst"), responseBody: enc("I will check."),
      id: ulid(t0), tsRequest: t0,
    });
    const firstHook = call({
      source: "otel", endpoint: "otel:tool_output:WebSearch", agent: "claude",
      displayMessages: [
        { role: "tool", content: '{"query":"first"}', tool: "WebSearch", kind: "call" },
        { role: "tool", content: "first results", tool: "WebSearch", kind: "result" },
      ],
      requestBody: enc("WebSearch\nfirst\nfirst results"), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 500), tsRequest: t0 + 500,
    });
    const second = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude",
      promptKey: "prompt-uuid-chain",
      displayMessages: [
        { role: "tool", content: '{"query":"second"}', tool: "WebSearch", kind: "call" },
      ],
      requestBody: enc("second"), responseBody: enc("Here is the answer."),
      id: ulid(t0 + 1000), tsRequest: t0 + 1000,
    });
    const secondHook = call({
      source: "otel", endpoint: "otel:tool_output:WebSearch", agent: "claude",
      displayMessages: [
        { role: "tool", content: '{"query":"second"}', tool: "WebSearch", kind: "call" },
        { role: "tool", content: "second results", tool: "WebSearch", kind: "result" },
      ],
      requestBody: enc("WebSearch\nsecond\nsecond results"), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 1500), tsRequest: t0 + 1500,
    });
    for (const c of [first, firstHook, second, secondHook]) store.insertCall(c);
    store.linkTurns("sess-1", [
      { linkKey: `row:${firstHook.id}`, promptKey: "prompt-uuid-chain", ordinal: 0, seq: 0 },
      { linkKey: `row:${secondHook.id}`, promptKey: "prompt-uuid-chain", ordinal: 0, seq: 0 },
    ]);

    const claude = buildSessionTurns(store, "sess-1").turns;
    expect(claude).toHaveLength(3);
    expect(claude.map((t) => ({
      request: t.messages.map((m) => [m.kind ?? m.role, m.content]),
      responseCalls: t.responseCalls.map((c) => c.args),
      response: t.responseText,
    }))).toEqual([
      { request: [["user", "research this"]], responseCalls: ['{"query":"first"}'], response: "I will check." },
      { request: [["result", "first results"]], responseCalls: ['{"query":"second"}'], response: "Here is the answer." },
      { request: [["result", "second results"]], responseCalls: [], response: null },
    ]);
    expect(new Set(listCalls(store, 20).map((r) => r.id))).toEqual(
      new Set([first.id, firstHook.id, second.id, secondHook.id]),
    );
    store.close();
  });

  test("claude places a late-stitched final response after the last tool result", () => {
    // Claude's initial user_prompt row can receive the final assistant response
    // in a later OTLP batch. Its request timestamp stays at the start of the
    // turn, so rendering the stitched response on that row pulls the final
    // answer above all intervening tool cycles.
    const store = Store.open(dir);
    const t0 = Date.now();
    const first = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude",
      promptKey: "prompt-late-final",
      displayMessages: [
        { role: "user", content: "research this" },
        { role: "tool", content: "{}", tool: "ToolSearch", kind: "call" },
      ],
      requestBody: enc("research this"), responseBody: enc("final answer"),
      id: ulid(t0), tsRequest: t0, tsResponse: t0 + 2000,
    });
    const firstHook = call({
      source: "otel", endpoint: "otel:tool_output:ToolSearch", agent: "claude",
      displayMessages: [
        { role: "tool", content: "{}", tool: "ToolSearch", kind: "call" },
        { role: "tool", content: "tool list", tool: "ToolSearch", kind: "result" },
      ],
      requestBody: enc("ToolSearch\ntool list"), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 300), tsRequest: t0 + 300,
    });
    const second = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude",
      promptKey: "prompt-late-final",
      displayMessages: [{ role: "tool", content: "{}", tool: "WebSearch", kind: "call" }],
      requestBody: enc("search"), responseBody: enc("searching"),
      id: ulid(t0 + 1000), tsRequest: t0 + 1000, tsResponse: t0 + 1000,
    });
    const secondHook = call({
      source: "otel", endpoint: "otel:tool_output:WebSearch", agent: "claude",
      displayMessages: [
        { role: "tool", content: "{}", tool: "WebSearch", kind: "call" },
        { role: "tool", content: "search results", tool: "WebSearch", kind: "result" },
      ],
      requestBody: enc("WebSearch\nsearch results"), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 1200), tsRequest: t0 + 1200,
    });
    for (const c of [first, firstHook, second, secondHook]) store.insertCall(c);
    store.linkTurns("sess-1", [
      { linkKey: `row:${firstHook.id}`, promptKey: "prompt-late-final", ordinal: 0, seq: 0 },
      { linkKey: `row:${secondHook.id}`, promptKey: "prompt-late-final", ordinal: 0, seq: 0 },
    ]);

    const turns = buildSessionTurns(store, "sess-1").turns;
    expect(turns.map((t) => t.responseText)).toEqual([null, "searching", "final answer"]);
    expect(turns[2]!.messages.map((m) => [m.kind, m.content])).toEqual([
      ["result", "search results"],
    ]);
    store.close();
  });

  test("codex: Pi-like turns follow ROLLOUT order — seq beats inverted report stamps", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    const prompt = codexPrompt({ id: ulid(t0), tsRequest: t0 });
    // Report stamps are COMPLETION times and invert against issue order when
    // calls overlap (a long-running exec issued first finishes last). The
    // rollout's seq is the authority on what the turn ran first, so c2
    // (seq 0) renders first even though its stamp is a full second later.
    const tool1 = codexTool("c1", { id: ulid(t0 + 1000), tsRequest: t0 + 1000 });
    const tool2 = codexTool("c2", { id: ulid(t0 + 2000), tsRequest: t0 + 2000 });
    store.insertCall(prompt);
    store.insertCall(tool1);
    store.insertCall(tool2);
    store.linkTurns("sess-1", [
      { linkKey: "call:c1", promptKey: "hashA", ordinal: 0, seq: 1 },
      { linkKey: "call:c2", promptKey: "hashA", ordinal: 0, seq: 0 },
    ]);
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.map((t) => t.id)).toEqual([prompt.id, tool2.id, tool1.id]);
    expect(view.turns[0]!.responseCalls.map((c) => c.callId)).toEqual(["c2"]);
    expect(view.turns[1]!.messages.map((m) => m.callId)).toEqual(["c2"]);
    expect(view.turns[1]!.responseCalls.map((c) => c.callId)).toEqual(["c1"]);
    expect(view.turns[2]!.messages.map((m) => m.callId)).toEqual(["c1"]);
    expect(view.turns[2]!.responseText).toBe("the stitched answer");
    expect(view.turns[1]!.responseCalls[0]!.sourceId).toBe(tool1.id);
    store.close();
  });

  test("an UNLINKED tool row is sequenced by TIME after the turn that was open", () => {
    // The twin-report case: codex reports each execution twice, and the inner
    // event's id is one the rollout never names — no link can exist. Time is
    // sound within a session (turns are sequential), so the row becomes the
    // result request after the last prompt instead of an unrelated orphan.
    const store = Store.open(dir);
    const t0 = Date.now();
    store.insertCall(codexPrompt({ id: ulid(t0), tsRequest: t0 }));
    store.insertCall(codexTool("c9", { id: ulid(t0 + 1000), tsRequest: t0 + 1000 }));
    // no linkTurns — rollout lagging, absent, or an id it never names
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.length).toBe(2);
    expect(view.turns[0]!.messages.map((m) => m.kind ?? "user")).toEqual(["user"]);
    expect(view.turns[0]!.responseCalls.map((c) => c.callId)).toEqual(["c9"]);
    expect(view.turns[1]!.messages.map((m) => m.kind)).toEqual(["result"]);
    expect(view.turns[1]!.responseText).toBe("the stitched answer");
    store.close();
  });

  test("a tool row BEFORE any turn row stays standalone — never guessed forward", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    store.insertCall(codexTool("c0", { id: ulid(t0 - 5000), tsRequest: t0 - 5000 }));
    store.insertCall(codexPrompt({ id: ulid(t0), tsRequest: t0 }));
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.length).toBe(2);
    expect(view.turns[0]!.messages.map((m) => m.kind)).toEqual(["call", "result"]);
    store.close();
  });

  test("a twin-report inner row interleaves BESIDE its linked harness pair, not after everything", () => {
    // Turn: prompt → exec c1 (linked, seq 0) with its inner twin one ms later
    // (internal id, unlinked) → exec c2 (linked, seq 1) two seconds on. The
    // twin must land right after c1's pair and before c2's — ts-primary
    // ordering is what makes that happen; seq-primary parked every adopted
    // row at the tail.
    const store = Store.open(dir);
    const t0 = Date.now();
    const prompt = codexPrompt({ id: ulid(t0), tsRequest: t0 });
    const harness1 = codexTool("c1", { id: ulid(t0 + 1000), tsRequest: t0 + 1000 });
    const inner1 = codexTool("exec-uuid-1", {
      id: ulid(t0 + 1001), tsRequest: t0 + 1001,
      endpoint: "otel:codex:tool_result:exec_command",
    });
    const harness2 = codexTool("c2", { id: ulid(t0 + 3000), tsRequest: t0 + 3000 });
    for (const c of [prompt, harness1, inner1, harness2]) store.insertCall(c);
    store.linkTurns("sess-1", [
      { linkKey: "call:c1", promptKey: "hashA", ordinal: 0, seq: 0 },
      { linkKey: "call:c2", promptKey: "hashA", ordinal: 0, seq: 1 },
    ]);
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.map((t) => t.id)).toEqual([prompt.id, harness1.id, inner1.id, harness2.id]);
    expect(view.turns.map((t) => ({
      request: t.messages.map((m) => m.callId ?? "user"),
      response: t.responseCalls.map((c) => c.callId),
    }))).toEqual([
      { request: ["user"], response: ["c1"] },
      { request: ["c1"], response: ["exec-uuid-1"] },
      { request: ["exec-uuid-1"], response: ["c2"] },
      { request: ["c2"], response: [] },
    ]);
    // A second turn bounds adoption: an inner row after prompt2 goes THERE.
    const prompt2 = codexPrompt({ id: ulid(t0 + 10_000), tsRequest: t0 + 10_000, promptKey: "hashB" });
    const inner2 = codexTool("exec-uuid-2", {
      id: ulid(t0 + 11_000), tsRequest: t0 + 11_000,
      endpoint: "otel:codex:tool_result:exec_command",
    });
    store.insertCall(prompt2);
    store.insertCall(inner2);
    const view2 = buildSessionTurns(store, "sess-1");
    expect(view2.turns.length).toBe(6);
    expect(view2.turns[4]!.id).toBe(prompt2.id);
    expect(view2.turns[4]!.responseCalls.map((c) => c.callId)).toEqual(["exec-uuid-2"]);
    expect(view2.turns[5]!.messages.map((m) => m.kind)).toEqual(["result"]);
    store.close();
  });

  test("repeated identical prompts: the ordinal routes each turn's tools to ITS row", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    const first = codexPrompt({ id: ulid(t0), tsRequest: t0 });
    const second = codexPrompt({ id: ulid(t0 + 5000), tsRequest: t0 + 5000 }); // same promptKey "hashA"
    const tool = codexTool("c2", { id: ulid(t0 + 6000), tsRequest: t0 + 6000 });
    store.insertCall(first);
    store.insertCall(second);
    store.insertCall(tool);
    store.linkTurns("sess-1", [{ linkKey: "call:c2", promptKey: "hashA", ordinal: 1, seq: 0 }]);
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.length).toBe(3);
    expect(view.turns[0]!.messages.length).toBe(1); // turn 1 untouched
    expect(view.turns[1]!.id).toBe(second.id);
    expect(view.turns[1]!.messages.map((m) => m.kind ?? "user")).toEqual(["user"]);
    expect(view.turns[1]!.responseCalls.map((c) => c.callId)).toEqual(["c2"]);
    expect(view.turns[2]!.messages.map((m) => m.kind)).toEqual(["result"]);
    store.close();
  });

  test("claude: hook results become the next same-prompt request; response rows stay distinct", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    const turnRow = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude",
      promptKey: "prompt-uuid-1",
      displayMessages: [
        { role: "user", content: "show my memory files" },
        { role: "tool", content: "Read: {}", tool: "Read", kind: "call" },
      ],
      requestBody: enc("show my memory files"), responseBody: enc("here they are"),
      id: ulid(t0), tsRequest: t0,
    });
    const hookRow = call({
      source: "otel", endpoint: "otel:tool_output:Read", agent: "claude",
      promptKey: undefined,
      displayMessages: [
        { role: "tool", content: '{"file_path":"/m/MEMORY.md"}', tool: "Read", kind: "call" },
        { role: "tool", content: "the file body", tool: "Read", kind: "result" },
      ],
      requestBody: enc('Read\n{"file_path":"/m/MEMORY.md"}\nthe file body'),
      responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 500), tsRequest: t0 + 500,
    });
    // A tool_result batch split: an extra claude_code.turn row, same prompt id.
    const partial = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude",
      promptKey: "prompt-uuid-1",
      displayMessages: [{ role: "tool", content: "Bash: ls", tool: "Bash", kind: "call" }],
      requestBody: enc("Bash: ls"), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 900), tsRequest: t0 + 900,
    });
    store.insertCall(turnRow);
    store.insertCall(hookRow);
    store.insertCall(partial);
    store.linkTurns("sess-1", [{ linkKey: `row:${hookRow.id}`, promptKey: "prompt-uuid-1", ordinal: 0, seq: 0 }]);
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.length).toBe(2);
    expect(view.turns[0]!.id).toBe(turnRow.id);
    expect(view.turns[0]!.responseText).toBe("here they are");
    expect(view.turns[0]!.messages.map((m) => m.role)).toEqual(["user"]);
    expect(view.turns[0]!.responseCalls.map((c) => c.tool)).toEqual(["Read"]);
    expect(view.turns[1]!.id).toBe(partial.id);
    expect(view.turns[1]!.messages.map((m) => [m.kind, m.content])).toEqual([["result", "the file body"]]);
    expect(view.turns[1]!.messages[0]!.sourceId).toBe(hookRow.id);
    expect(view.turns[1]!.responseCalls.map((c) => c.tool)).toEqual(["Bash"]);
    store.close();
  });

  test("a final unlinked hook stays as a visible pending request with its leak", () => {
    // The vanish bug: turn row + same-prompt-id batch partial + an UNLINKED
    // hook row stamped after the partial. Anchoring on the partial appended
    // the hook cards to a turn the old fold then dropped — the captured content
    // (and its leak highlight) appeared NOWHERE, while the feed hid the row
    // too. Anchors are now surviving turn rows only.
    const store = Store.open(dir);
    const t0 = Date.now();
    const turnRow = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude",
      promptKey: "prompt-uuid-v", displayMessages: [{ role: "user", content: "read my creds" }],
      requestBody: enc("read my creds"), responseBody: enc("done"),
      id: ulid(t0), tsRequest: t0,
    });
    const partial = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude",
      promptKey: "prompt-uuid-v",
      displayMessages: [{ role: "tool", content: "Read: {}", tool: "Read", kind: "call" }],
      requestBody: enc("Read: {}"), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 900), tsRequest: t0 + 900,
    });
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const hookBody = `Read\n{"file_path":"/c"}\n${secret}`;
    const hook = call({
      source: "otel", endpoint: "otel:tool_output:Read", agent: "claude",
      promptKey: undefined,
      displayMessages: [
        { role: "tool", content: '{"file_path":"/c"}', tool: "Read", kind: "call" },
        { role: "tool", content: secret, tool: "Read", kind: "result" },
      ],
      requestBody: enc(hookBody), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 1500), tsRequest: t0 + 1500,
    });
    for (const c of [turnRow, partial, hook]) store.insertCall(c);
    store.upsertLeakEvent({
      fingerprint: "fp-vanish", sessionId: "sess-1", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "anthropic", callId: hook.id, ts: t0 + 1500,
      spanStart: hookBody.indexOf(secret), spanEnd: hookBody.indexOf(secret) + secret.length,
    });
    // no linkTurns for the hook row — the exact population that used to vanish
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.length).toBe(3);
    const pending = view.turns[2]!;
    expect(pending.id).toBe(hook.id);
    expect(pending.messages.map((m) => m.kind)).toEqual(["result"]);
    expect(pending.leaks.some((l) => l.value === secret)).toBe(true);
    store.close();
  });

  test("a keyless turn row still anchors adoption — tools never skip past a visible turn", () => {
    // A turn row can land with NULL prompt_key (older client, malformed
    // prompt record). It can't be a link target, but it IS a turn on screen —
    // adoption must stop there, not file its tools under the previous turn.
    const store = Store.open(dir);
    const t0 = Date.now();
    const turnA = codexPrompt({ id: ulid(t0), tsRequest: t0 });
    const keylessB = codexPrompt({ id: ulid(t0 + 10_000), tsRequest: t0 + 10_000, promptKey: undefined });
    const tool = codexTool("exec-uuid-k", { id: ulid(t0 + 11_000), tsRequest: t0 + 11_000 });
    for (const c of [turnA, keylessB, tool]) store.insertCall(c);
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.length).toBe(3);
    expect(view.turns[0]!.messages.length).toBe(1); // turn A untouched
    expect(view.turns[1]!.id).toBe(keylessB.id);
    expect(view.turns[1]!.messages.map((m) => m.kind ?? "user")).toEqual(["user"]);
    expect(view.turns[1]!.responseCalls.map((c) => c.callId)).toEqual(["exec-uuid-k"]);
    expect(view.turns[2]!.messages.map((m) => m.kind)).toEqual(["result"]);
    store.close();
  });

  test("a sequenced row's leaks highlight both its response call and result request (R7)", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    const prompt = codexPrompt({ id: ulid(t0), tsRequest: t0 });
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const body = `exec\ncurl -H 'x: ${secret}'\nok`;
    const tool = codexTool("c1", {
      id: ulid(t0 + 1000), tsRequest: t0 + 1000,
      displayMessages: toolCards("c1", `curl -H 'x: ${secret}'`, "ok"),
      requestBody: enc(body),
    });
    store.insertCall(prompt);
    store.insertCall(tool);
    store.upsertLeakEvent({
      fingerprint: "fp-fold", sessionId: "sess-1", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "openai", callId: tool.id, ts: t0 + 1000,
      spanStart: body.indexOf(secret), spanEnd: body.indexOf(secret) + secret.length,
    });
    store.linkTurns("sess-1", [{ linkKey: "call:c1", promptKey: "hashA", ordinal: 0, seq: 0 }]);
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns.length).toBe(2);
    expect(view.turns[0]!.responseLeaks.some((l) => l.value === secret)).toBe(true);
    expect(view.turns[1]!.leaks.some((l) => l.value === secret)).toBe(true);
    store.close();
  });

  test("claude: a hook-recovered call's arg secret still highlights (R7)", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    const secret = "AKIAZQ3DRSTUVWXY2345";
    // The turn event omitted the tool call; only the PostToolUse hook reports
    // it, so the command is recovered onto the turn's response. Its secret was
    // scanned on the hook row alone (the turn row never saw this arg) — the
    // recovered card must still carry the highlight, like the codex chain does.
    const turn = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude", promptKey: "P1",
      displayMessages: [{ role: "user", content: "do it" }],
      requestBody: enc("do it"), responseBody: enc("working"), id: ulid(t0), tsRequest: t0,
    });
    const hookBody = `Bash\ncurl -H 'x: ${secret}'\nok`;
    const hook = call({
      source: "otel", endpoint: "otel:tool_output:Bash", agent: "claude", promptKey: undefined,
      displayMessages: [
        { role: "tool", content: `curl -H 'x: ${secret}'`, tool: "Bash", kind: "call" },
        { role: "tool", content: "ok", tool: "Bash", kind: "result" },
      ],
      requestBody: enc(hookBody), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 500), tsRequest: t0 + 500,
    });
    for (const c of [turn, hook]) store.insertCall(c);
    store.upsertLeakEvent({
      fingerprint: "fp-claude-arg", sessionId: "sess-1", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "anthropic", callId: hook.id, ts: t0 + 500,
      spanStart: hookBody.indexOf(secret), spanEnd: hookBody.indexOf(secret) + secret.length,
    });
    const view = buildSessionTurns(store, "sess-1");
    const turnT = view.turns.find((x) => x.id === turn.id)!;
    expect(turnT.responseCalls.some((c) => String(c.args).includes(secret))).toBe(true);
    expect(turnT.responseLeaks.some((l) => l.value === secret)).toBe(true);
    store.close();
  });

  test("an unlinked claude hook is NOT merged into a later, unrelated prompt", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    const turn1 = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude", promptKey: "P1",
      displayMessages: [
        { role: "user", content: "Q1" },
        { role: "tool", content: '{"f":"a"}', tool: "Read", kind: "call" },
      ],
      requestBody: enc("Q1"), responseBody: enc("working1"), id: ulid(t0), tsRequest: t0,
    });
    const hookRead = call({
      source: "otel", endpoint: "otel:tool_output:Read", agent: "claude", promptKey: undefined,
      displayMessages: [
        { role: "tool", content: '{"f":"a"}', tool: "Read", kind: "call" },
        { role: "tool", content: "fileA", tool: "Read", kind: "result" },
      ],
      requestBody: enc("Read\nfileA"), responseBody: null, tsResponse: undefined,
      id: ulid(t0 + 500), tsRequest: t0 + 500,
    });
    const turn2 = call({
      source: "otel", endpoint: "otel:claude_code.turn", agent: "claude", promptKey: "P2",
      displayMessages: [
        { role: "user", content: "Q2" },
        { role: "tool", content: '{"p":"x"}', tool: "Grep", kind: "call" },
      ],
      requestBody: enc("Q2"), responseBody: enc("answer2"), id: ulid(t0 + 1000), tsRequest: t0 + 1000,
    });
    for (const c of [turn1, hookRead, turn2]) store.insertCall(c);
    // no linkTurns — the hook is unlinked (its row: link never landed)
    const view = buildSessionTurns(store, "sess-1");
    // Q2's request is only its own user message — never Q1's tool result…
    const t2 = view.turns.find((x) => x.id === turn2.id)!;
    expect(t2.messages.map((m) => m.kind ?? m.role)).toEqual(["user"]);
    // …and Q1's result rides its own standalone turn, ordered between the two.
    expect(view.turns.map((x) => x.id)).toEqual([turn1.id, hookRead.id, turn2.id]);
    expect(view.turns[1]!.messages.map((m) => [m.kind, m.content])).toEqual([["result", "fileA"]]);
    store.close();
  });

  test("a hook that opens the view (no turn row yet) keeps its command card", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    // The claude_code.turn event was lost or fell outside the window; the hook
    // is the first captured row. Its command must not vanish from the cards.
    const hook = call({
      source: "otel", endpoint: "otel:tool_output:Read", agent: "claude", promptKey: undefined,
      displayMessages: [
        { role: "tool", content: '{"file_path":"/secret/path"}', tool: "Read", kind: "call" },
        { role: "tool", content: "body", tool: "Read", kind: "result" },
      ],
      requestBody: enc("Read\nbody"), responseBody: null, tsResponse: undefined,
      id: ulid(t0), tsRequest: t0,
    });
    store.insertCall(hook);
    const view = buildSessionTurns(store, "sess-1");
    expect(view.turns).toHaveLength(1);
    expect(view.turns[0]!.messages.map((m) => m.kind)).toEqual(["call", "result"]);
    store.close();
  });
});

// The feed is the stable raw-capture ledger beneath the reconstructed session:
// an SSE-added tool row must still be there after any later refetch.
describe("listCalls — subscription tool rows stay in the feed", () => {
  test("clean and leaky tool rows are all retained", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    const prompt = call({ source: "otel", endpoint: "otel:codex:user_prompt", id: ulid(t0), tsRequest: t0, summary: '"q" → a' });
    const cleanTool = call({ source: "otel", endpoint: "otel:codex:tool_result:exec", id: ulid(t0 + 1000), tsRequest: t0 + 1000 });
    const hookTool = call({ source: "otel", endpoint: "otel:tool_output:Read", id: ulid(t0 + 2000), tsRequest: t0 + 2000 });
    const leakyTool = call({ source: "otel", endpoint: "otel:codex:tool_result:exec", id: ulid(t0 + 3000), tsRequest: t0 + 3000 });
    const wire = call({ id: ulid(t0 + 4000), tsRequest: t0 + 4000 });
    for (const c of [prompt, cleanTool, hookTool, leakyTool, wire]) store.insertCall(c);
    store.upsertLeakEvent({
      fingerprint: "fp-feed", sessionId: "sess-1", detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured", destination: "openai",
      callId: leakyTool.id, ts: t0 + 3000,
    });
    const ids = listCalls(store, 50).map((r) => r.id);
    expect(ids).toContain(prompt.id);
    expect(ids).toContain(leakyTool.id); // leaked → stays visible
    expect(ids).toContain(wire.id);
    expect(ids).toContain(cleanTool.id);
    expect(ids).toContain(hookTool.id);
    store.close();
  });
});
