import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store, type CallRecord } from "../src/core/store/store";
import { buildSessionTurns, listSessions } from "../src/viewer/session-view";
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

  test("openai-responses tool flow: calls land on their OWN turn's response; echoes stamp resent; results get names (turn clarity)", () => {
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
    // Turn 2: the fc echo is stamped resent (folds in the UI, never dropped);
    // the result knows which tool produced it.
    const t2 = turns[1]!.messages;
    expect(t2.map((m) => [m.kind, m.tool, m.resent ?? false])).toEqual([
      ["call", "bash", true],
      ["result", "bash", false],
    ]);
    expect(turns[1]!.responseText).toBe("All green.");
    store.close();
  });

  test("an fc echo whose previous response did NOT parse stays unstamped (visible, not folded)", () => {
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
    // no prev responseCalls to match → the echo must NOT be marked resent
    expect(turns[1]!.messages[0]!.resent).toBeUndefined();
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
