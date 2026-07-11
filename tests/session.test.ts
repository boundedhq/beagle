import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionResolver } from "../src/core/session/resolver";
import { Store } from "../src/core/store/store";
import type { Message } from "../src/core/exchange";

const U = (c: string): Message => ({ role: "user", content: c });
const A = (c: string): Message => ({ role: "assistant", content: c });

describe("SessionResolver", () => {
  let store: Store;
  let resolver: SessionResolver;

  beforeEach(() => {
    store = Store.open(mkdtempSync(join(tmpdir(), "beagle-sess-")));
    resolver = new SessionResolver(store);
  });

  const base = { agent: "claude-code", provider: "anthropic", runId: "run-1", ts: Date.now() };

  test("tier 1: explicit conversation id groups across runs", () => {
    const a = resolver.resolve({ ...base, convId: "conv-9" });
    const b = resolver.resolve({ ...base, runId: "run-2", convId: "conv-9" });
    expect(a.sessionId).toBe(b.sessionId);
    expect(a.tier).toBe("conv-id");
  });

  test("tier 1: Responses API previous_response_id chains", () => {
    const a = resolver.resolve({ ...base, messages: [U("start")] });
    resolver.recordResponse({ sessionId: a.sessionId, responseId: "resp_1" });
    const b = resolver.resolve({ ...base, runId: "run-2", prevResponseId: "resp_1" });
    expect(b.sessionId).toBe(a.sessionId);
    expect(b.tier).toBe("conv-id");
  });

  test("tier 2: history-prefix chaining follows a growing conversation", () => {
    const t1 = resolver.resolve({ ...base, messages: [U("q1")] });
    resolver.recordResponse({ sessionId: t1.sessionId, messages: [U("q1"), A("a1")] });
    const t2 = resolver.resolve({ ...base, messages: [U("q1"), A("a1"), U("q2")] });
    expect(t2.sessionId).toBe(t1.sessionId);
    expect(t2.tier).toBe("prefix");
    resolver.recordResponse({ sessionId: t2.sessionId, messages: [U("q1"), A("a1"), U("q2"), A("a2")] });
    const t3 = resolver.resolve({ ...base, messages: [U("q1"), A("a1"), U("q2"), A("a2"), U("q3")] });
    expect(t3.sessionId).toBe(t1.sessionId);
  });

  test("tier 2: --resume (same history, new process/run) is the same session", () => {
    const t1 = resolver.resolve({ ...base, messages: [U("q1")] });
    resolver.recordResponse({ sessionId: t1.sessionId, messages: [U("q1"), A("a1")] });
    const resumed = resolver.resolve({
      ...base,
      runId: "run-2",
      messages: [U("q1"), A("a1"), U("q2")],
    });
    expect(resumed.sessionId).toBe(t1.sessionId);
  });

  test("tier 2: /clear (fresh history, same run) is a NEW session", () => {
    const t1 = resolver.resolve({ ...base, messages: [U("q1")] });
    resolver.recordResponse({ sessionId: t1.sessionId, messages: [U("q1"), A("a1")] });
    const cleared = resolver.resolve({ ...base, messages: [U("totally new start")] });
    expect(cleared.sessionId).not.toBe(t1.sessionId);
  });

  test("tier 2: compaction breaks the prefix but links via system+first-user fuzzy hash", () => {
    const sys = "You are Claude Code.";
    const t1 = resolver.resolve({
      ...base,
      systemPrompt: sys,
      messages: [U("build the app"), A("a1"), U("q2")],
    });
    resolver.recordResponse({ sessionId: t1.sessionId, messages: [U("build the app"), A("a1"), U("q2"), A("a2")] });
    // compaction rewrote history: prefix no longer matches, same sys + first user msg
    const compacted = resolver.resolve({
      ...base,
      systemPrompt: sys,
      messages: [U("build the app"), U("[compacted summary of earlier work]"), U("q3")],
    });
    expect(compacted.sessionId).toBe(t1.sessionId);
    expect(compacted.tier).toBe("compaction-link");
  });

  test("tier 3: opaque format falls to run identity", () => {
    const a = resolver.resolve({ ...base });
    const b = resolver.resolve({ ...base });
    expect(a.sessionId).toBe(b.sessionId);
    expect(a.tier).toBe("run");
    const other = resolver.resolve({ ...base, runId: "run-2" });
    expect(other.sessionId).not.toBe(a.sessionId);
  });

  test("tier 3: no run id uses time-gap heuristic", () => {
    const t0 = Date.now();
    const a = resolver.resolve({ agent: "x", provider: "p", ts: t0 });
    const b = resolver.resolve({ agent: "x", provider: "p", ts: t0 + 60_000 });
    expect(b.sessionId).toBe(a.sessionId);
    expect(b.tier).toBe("time-gap");
    const later = resolver.resolve({ agent: "x", provider: "p", ts: t0 + 3_600_000 });
    expect(later.sessionId).not.toBe(a.sessionId);
  });

  test("sessions persist: a new resolver over the same store still chains", () => {
    const t1 = resolver.resolve({ ...base, messages: [U("q1")] });
    resolver.recordResponse({ sessionId: t1.sessionId, messages: [U("q1"), A("a1")] });
    const resolver2 = new SessionResolver(store);
    const t2 = resolver2.resolve({ ...base, messages: [U("q1"), A("a1"), U("q2")] });
    expect(t2.sessionId).toBe(t1.sessionId);
  });
});
