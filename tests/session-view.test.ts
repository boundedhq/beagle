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
    // the repeated history must NOT replay — only the new tail
    expect(v.turns[1]!.messages).toEqual([
      { role: "assistant", content: "first answer" },
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
