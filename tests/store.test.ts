import { beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store, SCHEMA_VERSION, StoreVersionError } from "../src/core/store/store";
import { SCHEMA_SQL } from "../src/core/store/schema";
import { listLeakEvents } from "../src/viewer/feed-query";
import type { CallRecord } from "../src/core/store/store";
import { ulid } from "../src/core/store/ulid";
import { DEMO_AGENT } from "../src/core/call";

function tmpRoot(): string {
  return mkdtempSync(join(tmpdir(), "beagle-store-"));
}

function fakeCall(overrides: Partial<CallRecord> = {}): CallRecord {
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
    tsResponse: Date.now() + 1200,
    status: 200,
    tokensIn: 100,
    tokensOut: 50,
    bytesReq: 1024,
    bytesResp: 2048,
    summary: "read 3 files",
    scanState: "ok",
    captureState: "ok",
    sessionTier: "conv-id",
    requestBody: new TextEncoder().encode('{"messages":[{"role":"user","content":"hello secret-xyz"}]}'),
    requestHeaders: [["content-type", "application/json"]],
    responseBody: new TextEncoder().encode('{"content":"hi"}'),
    responseHeaders: [["content-type", "application/json"]],
    sseRaw: null,
    searchText: 'messages user hello secret-xyz content hi',
    ...overrides,
  };
}

describe("Store lifecycle", () => {
  let dir: string;
  beforeEach(() => {
    dir = tmpRoot();
  });

  test("creates state dir 0700 and db 0600", () => {
    const store = Store.open(dir);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(statSync(join(dir, "beagle.db")).mode & 0o777).toBe(0o600);
    store.close();
  });

  test("stamps user_version and required pragmas", () => {
    const store = Store.open(dir);
    expect(store.pragma("user_version")).toBe(SCHEMA_VERSION);
    expect(store.pragma("journal_mode")).toBe("wal");
    expect(store.pragma("secure_delete")).toBe(1);
    // 2 = INCREMENTAL. Guards a silent ordering trap: auto_vacuum is baked
    // into the header when the file is initialized, so setting it AFTER
    // journal_mode=WAL leaves it 0 and turns every `PRAGMA incremental_vacuum`
    // into a no-op — swept pages stay on the freelist, the file never shrinks.
    expect(store.pragma("auto_vacuum")).toBe(2);
    store.close();
  });

  test("read-only open refuses a future schema version in plain language", () => {
    const store = Store.open(dir);
    store.setUserVersionForTest(SCHEMA_VERSION + 1);
    store.close();
    expect(() => Store.openReadOnly(dir)).toThrow(StoreVersionError);
    expect(() => Store.openReadOnly(dir)).toThrow(/upgrade beagle|restart the daemon/i);
  });

  test("read-only open of an OLDER store gives a clean version error, not a raw column error", () => {
    // A reader can't migrate; it must refuse an un-migrated store in plain
    // language rather than letting a new-column query throw "no such column".
    const store = Store.open(dir);
    store.setUserVersionForTest(SCHEMA_VERSION - 1);
    store.close();
    expect(() => Store.openReadOnly(dir)).toThrow(StoreVersionError);
    expect(() => Store.openReadOnly(dir)).toThrow(/restart the daemon/i);
  });

  test("read-only open works after the WAL sidecars are gone (daemon-down reads, R12)", () => {
    // A cleanly-exited daemon checkpoints and removes -wal/-shm. The CLI's
    // read commands must still open the store — and still reject writes.
    const store = Store.open(dir);
    store.insertCall(fakeCall());
    store.close();
    rmSync(join(dir, "beagle.db-wal"), { force: true });
    rmSync(join(dir, "beagle.db-shm"), { force: true });
    const ro = Store.openReadOnly(dir);
    expect(ro.queryAll<{ c: number }>("SELECT COUNT(*) AS c FROM exchanges")[0]?.c).toBe(1);
    expect(() => ro.purge({ kind: "all" })).toThrow(/readonly|read-only/i);
    ro.close();
    // and a reader must never create a missing store
    expect(() => Store.openReadOnly(join(dir, "nope"))).toThrow();
  });

  test("openOrRecover surfaces a version mismatch — never quarantines a healthy store", () => {
    // A rollback (older binary, newer store) must fail with the clean version
    // error, not shelve the entire capture history as "corruption".
    const store = Store.open(dir);
    store.insertCall(fakeCall());
    store.setUserVersionForTest(SCHEMA_VERSION + 1);
    store.close();
    expect(() => Store.openOrRecover(dir)).toThrow(StoreVersionError);
    // the history is still there, un-quarantined
    expect(statSync(join(dir, "beagle.db")).size).toBeGreaterThan(0);
  });

  test("migrates an older store forward in place, preserving captured data", () => {
    // Populate a real store, then rewind its on-disk schema to look like a v1
    // store (no v2 columns, user_version=1) so Store.open exercises migrate().
    const store = Store.open(dir);
    const call = fakeCall();
    store.insertCall(call);
    store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "sess-1", detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured",
      destination: "anthropic/m", callId: call.id, ts: Date.now(),
    });
    store.close();

    const raw = new Database(join(dir, "beagle.db"));
    raw.exec("ALTER TABLE exchanges DROP COLUMN redacted");
    raw.exec("ALTER TABLE leak_occurrences DROP COLUMN span_start");
    raw.exec("ALTER TABLE leak_occurrences DROP COLUMN span_end");
    raw.exec("ALTER TABLE payloads DROP COLUMN display_messages"); // v3 column
    raw.exec("ALTER TABLE exchanges DROP COLUMN prompt_key"); // v5 column
    raw.exec("ALTER TABLE exchanges DROP COLUMN one_shot"); // v4 column
    raw.exec("ALTER TABLE exchanges DROP COLUMN search_bytes"); // v6 column
    raw.exec("PRAGMA user_version=1");
    raw.close();

    // Reopen: should migrate additively, not quarantine or throw.
    const migrated = Store.open(dir);
    expect(migrated.pragma("user_version")).toBe(SCHEMA_VERSION);
    // Pre-migration rows survived.
    expect(migrated.getCall(call.id)?.provider).toBe("anthropic");
    expect(listLeakEvents(migrated).length).toBe(1);
    // The re-added columns now accept writes: the redact flag (v2) and the
    // Mode B display messages (v3) both round-trip through the migrated schema.
    const ex2 = fakeCall({ redacted: true, displayMessages: [{ role: "user", content: "hi" }], oneShot: true, promptKey: "p-77" });
    migrated.insertCall(ex2);
    expect(migrated.getCall(ex2.id)?.redacted).toBe(true);
    expect(migrated.getCall(ex2.id)?.displayMessages).toEqual([{ role: "user", content: "hi" }]);
    expect(migrated.getCall(ex2.id)?.oneShot).toBe(true); // v4 column round-trips post-migration
    expect(migrated.getCall(ex2.id)?.promptKey).toBe("p-77"); // v5 column round-trips post-migration
    expect(migrated.getCall(call.id)?.oneShot).toBe(false); // pre-migration row reads false, not undefined
    // v6 backfills search_bytes from the existing index, so rows captured
    // before the column existed bill their search index too. Without it they'd
    // count 0 against the size cap until they aged out — and a store big
    // enough to have hit that bug is the one that needs the cap enforced now.
    expect(
      migrated.queryAll<{ n: number }>(
        `SELECT search_bytes AS n FROM exchanges WHERE id=?`, [call.id])[0]?.n,
    ).toBe(Buffer.byteLength(call.searchText, "utf8"));
    migrated.close();
  });
});

describe("Call write/read", () => {
  let dir: string;
  beforeEach(() => (dir = tmpRoot()));

  test("insert then read back full call with payload", () => {
    const store = Store.open(dir);
    const call = fakeCall();
    store.insertCall(call);
    const got = store.getCall(call.id);
    expect(got?.provider).toBe("anthropic");
    expect(new TextDecoder().decode(got!.requestBody!)).toContain("secret-xyz");
    expect(got?.requestHeaders).toEqual([["content-type", "application/json"]]);
    store.close();
  });

  test("getCall supports unambiguous id prefix", () => {
    const store = Store.open(dir);
    const call = fakeCall();
    store.insertCall(call);
    expect(store.getCall(call.id.slice(0, 8))?.id).toBe(call.id);
    store.close();
  });

  test("literal search finds content and reports call/session grouping", () => {
    const store = Store.open(dir);
    store.insertCall(fakeCall({ sessionId: "s1" }));
    store.insertCall(fakeCall({ sessionId: "s1" }));
    store.insertCall(fakeCall({ sessionId: "s2", searchText: "nothing here" }));
    const hits = store.searchLiteral("secret-xyz");
    expect(hits.length).toBe(2);
    expect(new Set(hits.map((h) => h.sessionId))).toEqual(new Set(["s1"]));
    expect(store.searchLiteral("never-sent-string")).toEqual([]);
    store.close();
  });

  test("literal search is safe for FTS metacharacters in credentials", () => {
    const store = Store.open(dir);
    const cred = 'p@ss"word-*with(chars)';
    store.insertCall(fakeCall({ searchText: `leading ${cred} trailing` }));
    const hits = store.searchLiteral(cred);
    expect(hits.length).toBe(1);
    store.close();
  });
});

describe("attachOtelResponse (Mode B cross-batch turn stitching)", () => {
  let dir: string;
  beforeEach(() => (dir = tmpRoot()));

  // A Mode B prompt-only partial as ingestOtel stores it: no response yet.
  const promptRow = (overrides: Partial<CallRecord> = {}) =>
    fakeCall({
      source: "otel", endpoint: "otel:claude_code.turn", promptKey: "prompt-1",
      model: undefined, tokensIn: undefined, tokensOut: undefined,
      tsResponse: undefined, bytesResp: undefined, responseBody: null,
      summary: "how does memory work?", searchText: "how does memory work?",
      ...overrides,
    });

  test("a later-batch response rejoins its turn row: body, model, tokens, summary, search", () => {
    const store = Store.open(dir);
    const turn = promptRow();
    store.insertCall(turn);
    const attached = store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: turn.tsRequest + 18_000,
      model: "claude-opus-4-8", tokensIn: 4182, tokensOut: 1128,
      composeSummary: (existing) => `"${existing}" → Memory works like this…`,
      responseBody: new TextEncoder().encode("Memory works like this — the long answer"),
    });
    // Returns the stitched row's id and that it really wrote — what the daemon
    // broadcasts so an open dashboard refreshes the exact row that changed.
    expect(attached).toEqual({ id: turn.id, changed: true });
    const got = store.getCall(turn.id)!;
    expect(new TextDecoder().decode(got.responseBody!)).toContain("the long answer");
    expect(got.model).toBe("claude-opus-4-8");
    expect(got.tokensIn).toBe(4182);
    expect(got.tokensOut).toBe(1128);
    expect(got.tsResponse).toBe(turn.tsRequest + 18_000);
    // composed from the row's own question + the answer, so a stitched turn
    // reads like a one-batch one instead of showing the answer alone
    expect(got.summary).toBe('"how does memory work?" → Memory works like this…');
    // The row stays findable by the question it SENT…
    expect(store.searchLiteral("how does memory work")[0]!.callId).toBe(turn.id);
    // …and the stitch leaves the index alone: search is outbound-only, so the
    // model's answer never becomes a hit even though it now lives on this row.
    expect(store.searchLiteral("the long answer")).toEqual([]);
    store.close();
  });

  test("tokens SUM when the turn row already has some (api_request split across batches)", () => {
    const store = Store.open(dir);
    const turn = promptRow({ tokensIn: 50, tokensOut: 4 });
    store.insertCall(turn);
    store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: Date.now(),
      tokensIn: 50, tokensOut: 4, responseBody: new TextEncoder().encode("ok"),
    });
    const got = store.getCall(turn.id)!;
    expect(got.tokensIn).toBe(100);
    expect(got.tokensOut).toBe(8);
    expect(got.model).toBe(undefined); // COALESCE: absent on both sides stays absent
    store.close();
  });

  test("the answer lands on the QUESTION row, not a later tool row sharing the prompt id", () => {
    // A turn whose tool_results arrived in their own OTLP batch has several
    // rows sharing prompt_key. Taking the NEWEST hung the answer off the tool
    // row and left the question unanswered — the exact split this feature
    // exists to remove. The turn's FIRST partial is the one with the question.
    const store = Store.open(dir);
    // Explicit timestamps, as the real batches arrive: the question first, the
    // tool result seconds later (ULID ids alone can't order same-ms rows).
    const t0 = Date.now();
    const question = promptRow({ id: ulid(t0), tsRequest: t0, summary: "how does memory work?", searchText: "how does memory work?" });
    store.insertCall(question);
    const toolRow = promptRow({ id: ulid(t0 + 4000), tsRequest: t0 + 4000, summary: "Bash: ls -la", searchText: "Bash: ls -la" });
    store.insertCall(toolRow);
    store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: Date.now(),
      responseBody: new TextEncoder().encode("THE ANSWER"),
    });
    expect(new TextDecoder().decode(store.getCall(question.id)!.responseBody!)).toBe("THE ANSWER");
    expect(store.getCall(toolRow.id)!.responseBody).toBe(null); // tool row untouched
    store.close();
  });

  test("no matching turn row → null (caller inserts the partial as its own row)", () => {
    const store = Store.open(dir);
    store.insertCall(promptRow());
    const wrongPrompt = store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "other-prompt", tsResponse: Date.now(),
      responseBody: new TextEncoder().encode("x"),
    });
    const wrongSession = store.attachOtelResponse({
      sessionId: "sess-9", promptKey: "prompt-1", tsResponse: Date.now(),
      responseBody: new TextEncoder().encode("x"),
    });
    expect(wrongPrompt).toBe(null);
    expect(wrongSession).toBe(null);
    store.close();
  });

  test("an already-answered turn is never overwritten (double-attach guard)", () => {
    const store = Store.open(dir);
    const turn = promptRow();
    store.insertCall(turn);
    const first = store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: Date.now(),
      responseBody: new TextEncoder().encode("the real answer"),
    });
    const second = store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: Date.now(),
      responseBody: new TextEncoder().encode("an impostor"),
    });
    expect(first).toEqual({ id: turn.id, changed: true });
    expect(second).toBe(null);
    expect(new TextDecoder().decode(store.getCall(turn.id)!.responseBody!)).toBe("the real answer");
    store.close();
  });

  test("a stale answer never claims a NEWER identical-prompt row (rollout re-emit race)", () => {
    // Same prompt text twice ("continue", "continue") → two rows, one
    // prompt_key. A re-emitted turn-1 answer arriving after turn 2's row
    // exists must NOT attach to it: the answer predates that row, so the row
    // belongs to a later turn. Before the ts_request bound it did attach, and
    // the real turn-2 answer then hit the bytes_resp guard and was lost.
    const store = Store.open(dir);
    const t0 = Date.now();
    const turn1 = promptRow({ id: ulid(t0), tsRequest: t0 });
    store.insertCall(turn1);
    const ans1Ts = t0 + 5_000;
    expect(store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: ans1Ts,
      responseBody: new TextEncoder().encode("ANSWER ONE"),
    })).toEqual({ id: turn1.id, changed: true });
    const turn2 = promptRow({ id: ulid(t0 + 20_000), tsRequest: t0 + 20_000 });
    store.insertCall(turn2);
    // The re-emit: same answer, same production time — turn 2's row postdates it.
    expect(store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: ans1Ts,
      responseBody: new TextEncoder().encode("ANSWER ONE"),
    })).toBe(null);
    expect(store.getCall(turn2.id)!.responseBody).toBe(null);
    // The real turn-2 answer still lands on turn 2's row.
    expect(store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: t0 + 25_000,
      responseBody: new TextEncoder().encode("ANSWER TWO"),
    })).toEqual({ id: turn2.id, changed: true });
    expect(new TextDecoder().decode(store.getCall(turn1.id)!.responseBody!)).toBe("ANSWER ONE");
    expect(new TextDecoder().decode(store.getCall(turn2.id)!.responseBody!)).toBe("ANSWER TWO");
    store.close();
  });

  test("the staleness bound keeps a skew margin, and old rows still take late answers", () => {
    const store = Store.open(dir);
    const t0 = Date.now();
    // An answer predating the row by more than the margin is refused; one a
    // beat "early" (cross-source stamp imprecision) still attaches.
    const turn = promptRow({ id: ulid(t0), tsRequest: t0 });
    store.insertCall(turn);
    expect(store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: t0 - 5_000,
      responseBody: new TextEncoder().encode("stale"),
    })).toBe(null);
    expect(store.attachOtelResponse({
      sessionId: "sess-1", promptKey: "prompt-1", tsResponse: t0 - 1_000,
      responseBody: new TextEncoder().encode("close enough"),
    })).toEqual({ id: turn.id, changed: true });
    // The bound is one-sided: an answer long AFTER its row (post-retirement
    // back-fill) attaches — only answer-before-row is stale.
    const old = promptRow({ id: ulid(t0 - 3_600_000), tsRequest: t0 - 3_600_000, sessionId: "sess-old" });
    store.insertCall(old);
    expect(store.attachOtelResponse({
      sessionId: "sess-old", promptKey: "prompt-1", tsResponse: t0,
      responseBody: new TextEncoder().encode("late back-fill"),
    })).toEqual({ id: old.id, changed: true });
    store.close();
  });

  test("a wire row is never a stitch target, even with a colliding prompt_key", () => {
    // Defense in depth: stitching is a Mode B concept; the source='otel' guard
    // keeps a hypothetical wire row with the same session/key untouched.
    const store = Store.open(dir);
    store.insertCall(fakeCall({ promptKey: "prompt-1", tsResponse: undefined, bytesResp: undefined, responseBody: null }));
    expect(
      store.attachOtelResponse({
        sessionId: "sess-1", promptKey: "prompt-1", tsResponse: Date.now(),
        responseBody: new TextEncoder().encode("x"),
      }),
    ).toBe(null);
    store.close();
  });

  // Rollout answers GROW while a codex turn runs (preamble → … → final reply),
  // so their attach is a grow-only upsert instead of attach-once: a longer
  // answer for the same turn replaces the shorter one, anything else drops.
  describe("extend mode (codex rollout answers)", () => {
    const attachExtend = (store: Store, body: string, opts: { ordinal?: number; ts?: number } = {}) =>
      store.attachOtelResponse({
        sessionId: "sess-1", promptKey: "prompt-1", tsResponse: opts.ts ?? Date.now(),
        composeSummary: (existing) => (existing ? `"${existing}" → ${body}` : body),
        responseBody: new TextEncoder().encode(body),
        extend: { ordinal: opts.ordinal ?? 0 },
      });

    test("a longer answer for the same turn replaces the shorter one", () => {
      const store = Store.open(dir);
      const turn = promptRow();
      store.insertCall(turn);
      expect(attachExtend(store, "I’m checking the docs.")).toEqual({ id: turn.id, changed: true });
      expect(attachExtend(store, "I’m checking the docs.\n\nThe real answer, at last."))
        .toEqual({ id: turn.id, changed: true }); // growth is a real write — the viewer must hear about it
      const got = store.getCall(turn.id)!;
      expect(new TextDecoder().decode(got.responseBody!)).toBe("I’m checking the docs.\n\nThe real answer, at last.");
      expect(got.bytesResp).toBeGreaterThan("I’m checking the docs.".length);
      store.close();
    });

    test("an equal or shorter re-emit is handled but changes nothing, body untouched", () => {
      const store = Store.open(dir);
      const turn = promptRow();
      store.insertCall(turn);
      attachExtend(store, "the whole answer");
      // Same length again (the tailer's retry window re-emits verbatim)…
      expect(attachExtend(store, "the whole answer")).toEqual({ id: turn.id, changed: false });
      // …and a shorter view must never roll the row back.
      expect(attachExtend(store, "shorter")).toEqual({ id: turn.id, changed: false });
      expect(new TextDecoder().decode(store.getCall(turn.id)!.responseBody!)).toBe("the whole answer");
      // changed:false is load-bearing in two directions. A row id (not null)
      // keeps the caller from re-inserting the re-emit as its own row; the
      // false keeps it from telling every open dashboard to refetch a row that
      // did not move — the tailer re-emits on every poll of its retry window.
      store.close();
    });

    // The store used to compose only on the FIRST attach, so a turn that opened
    // with a codex preamble kept advertising the preamble while the row held
    // the real answer (seen in real traffic). It now composes on every write
    // and hands the callback what it needs to not nest its own output; the
    // daemon owns that judgement (see composeStitchSummary in summary.test.ts).
    const attachWith = (
      store: Store, body: string, compose: (e: string | null, h: boolean) => string | null,
    ) =>
      store.attachOtelResponse({
        sessionId: "sess-1", promptKey: "prompt-1", tsResponse: Date.now(),
        composeSummary: compose,
        responseBody: new TextEncoder().encode(body),
        extend: { ordinal: 0 },
      });

    test("composeSummary runs on growth too, and is told the row already answered", () => {
      const store = Store.open(dir);
      const turn = promptRow();
      store.insertCall(turn);
      const seen: Array<{ existing: string | null; hasResponse: boolean }> = [];
      const record = (out: string) => (e: string | null, h: boolean) => {
        seen.push({ existing: e, hasResponse: h });
        return out;
      };
      attachWith(store, "preamble", record('"q" → preamble'));
      attachWith(store, "preamble, then the real answer", record('"q" → the real answer'));
      // First call sees the bare question and hasResponse=false; the growth
      // call sees the line the first one produced, and is told so — that flag
      // is the only thing separating "compose fresh" from "don't nest".
      expect(seen).toEqual([
        { existing: "how does memory work?", hasResponse: false },
        { existing: '"q" → preamble', hasResponse: true },
      ]);
      expect(store.getCall(turn.id)!.summary).toBe('"q" → the real answer');
      store.close();
    });

    test("a null from composeSummary keeps the stored summary while the body still grows", () => {
      // The daemon's escape hatch: when it can't recognize its own composed
      // line it declines rather than risk mangling a real summary. The answer
      // must still land — declining to re-title a row can't cost the answer.
      const store = Store.open(dir);
      const turn = promptRow();
      store.insertCall(turn);
      attachWith(store, "preamble", () => '"q" → preamble');
      attachWith(store, "preamble, then the real answer", () => null);
      const got = store.getCall(turn.id)!;
      expect(new TextDecoder().decode(got.responseBody!)).toBe("preamble, then the real answer");
      expect(got.summary).toBe('"q" → preamble');
      store.close();
    });

    test("ordinal N targets the Nth row sharing the prompt key (repeated prompts)", () => {
      const store = Store.open(dir);
      const t0 = Date.now();
      const first = promptRow({ id: ulid(t0), tsRequest: t0 });
      const second = promptRow({ id: ulid(t0 + 5000), tsRequest: t0 + 5000 });
      store.insertCall(first);
      store.insertCall(second);
      expect(attachExtend(store, "part two", { ordinal: 1, ts: t0 + 6000 })).toEqual({ id: second.id, changed: true });
      expect(attachExtend(store, "part one", { ordinal: 0, ts: t0 + 1000 })).toEqual({ id: first.id, changed: true });
      expect(new TextDecoder().decode(store.getCall(first.id)!.responseBody!)).toBe("part one");
      expect(new TextDecoder().decode(store.getCall(second.id)!.responseBody!)).toBe("part two");
      // An ordinal past the last row has no target: drop-and-retry, never a wrong row.
      expect(attachExtend(store, "part three", { ordinal: 2, ts: t0 + 9000 })).toBe(null);
      store.close();
    });

    test("the staleness bound still applies under extend: an old answer can't reach a newer re-ask's row", () => {
      // Turn one's grown answer re-emitted late (recreated tailer) with its
      // ordinal somehow aligned at 0 must not see rows created AFTER it —
      // extend keeps the same ts_request bound the plain path has.
      const store = Store.open(dir);
      const t0 = Date.now();
      const newer = promptRow({ id: ulid(t0 + 60_000), tsRequest: t0 + 60_000 });
      store.insertCall(newer);
      expect(attachExtend(store, "a historical answer", { ordinal: 0, ts: t0 })).toBe(null);
      expect(store.getCall(newer.id)!.responseBody).toBe(null);
      store.close();
    });
  });
});

describe("Leak events", () => {
  let dir: string;
  beforeEach(() => (dir = tmpRoot()));

  test("upsert: first insert reports fresh, second same-key increments", () => {
    const store = Store.open(dir);
    const call = fakeCall();
    store.insertCall(call);
    const first = store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "sess-1", detector: "aws-access-key",
      secretType: "aws-key", severity: "high", confidenceTier: "structured",
      destination: "anthropic/claude-sonnet-5", callId: call.id, ts: Date.now(),
    });
    expect(first.fresh).toBe(true);
    const second = store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "sess-1", detector: "aws-access-key",
      secretType: "aws-key", severity: "high", confidenceTier: "structured",
      destination: "anthropic/claude-sonnet-5", callId: call.id, ts: Date.now(),
    });
    expect(second.fresh).toBe(false);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]?.occurrences).toBe(2);
    store.close();
  });

  test("same fingerprint, new destination is a fresh event", () => {
    const store = Store.open(dir);
    const call = fakeCall();
    store.insertCall(call);
    const base = {
      fingerprint: "fp1", sessionId: "sess-1", detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured", callId: call.id, ts: Date.now(),
    };
    store.upsertLeakEvent({ ...base, destination: "anthropic/m" });
    const r = store.upsertLeakEvent({ ...base, destination: "openai/m" });
    expect(r.fresh).toBe(true);
    expect(listLeakEvents(store).length).toBe(2);
    store.close();
  });

  test("demo events stay visible and badged but are excluded from real-leak totals", () => {
    const store = Store.open(dir);
    const demo = fakeCall({ sessionId: "demo-s", runId: "demo-r", agent: DEMO_AGENT });
    const real = fakeCall({ sessionId: "real-s", runId: "real-r" });
    store.insertSession({ id: demo.sessionId, agent: DEMO_AGENT, firstTs: 1, lastTs: 2 });
    store.insertSession({ id: real.sessionId, agent: real.agent, firstTs: 1, lastTs: 2 });
    store.insertCall(demo);
    store.insertCall(real);
    for (const [call, fingerprint] of [[demo, "demo-fp"], [real, "real-fp"]] as const) {
      store.upsertLeakEvent({
        fingerprint, sessionId: call.sessionId, detector: "d", secretType: "t",
        severity: "high", confidenceTier: "structured", destination: "x",
        callId: call.id, ts: Date.now(),
      });
    }

    expect(listLeakEvents(store).map((e) => e.demo).sort()).toEqual([false, true]);
    expect(store.countLeakEvents()).toBe(1);
    store.close();
  });
});

describe("Retention & purge", () => {
  let dir: string;
  beforeEach(() => (dir = tmpRoot()));

  test("sweep deletes payloads+exchanges past the age window, keeps leak events", () => {
    const store = Store.open(dir);
    const old = fakeCall({ tsRequest: Date.now() - 8 * 24 * 3600_000 });
    const fresh = fakeCall();
    store.insertCall(old);
    store.insertCall(fresh);
    store.upsertLeakEvent({
      fingerprint: "fp", sessionId: old.sessionId, detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured", destination: "x",
      callId: old.id, ts: old.tsRequest,
    });
    store.sweep({ payloadWindowMs: 7 * 24 * 3600_000, eventWindowMs: 90 * 24 * 3600_000, sizeCapBytes: 1 << 30 });
    expect(store.getCall(old.id)).toBeNull();
    expect(store.getCall(fresh.id)).not.toBeNull();
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]?.firstCall).toBeNull(); // FK set null, event survives
    store.close();
  });

  test("sweep enforces size cap oldest-first", () => {
    const store = Store.open(dir);
    const big = () => new Uint8Array(200_000);
    const a = fakeCall({ tsRequest: Date.now() - 3000, requestBody: big() });
    const b = fakeCall({ tsRequest: Date.now() - 2000, requestBody: big() });
    const c = fakeCall({ tsRequest: Date.now() - 1000, requestBody: big() });
    for (const e of [a, b, c]) store.insertCall(e);
    store.sweep({ payloadWindowMs: Infinity, eventWindowMs: Infinity, sizeCapBytes: 450_000 });
    expect(store.getCall(a.id)).toBeNull();
    expect(store.getCall(c.id)).not.toBeNull();
    store.close();
  });

  test("sweep bills the search index against the size cap, not payload blobs alone", () => {
    // A Mode B row indexes its whole request body, so exchanges_fts holds a
    // second copy of that text plus the trigram postings over it — several
    // times the blob the sweeper used to bill. These rows are payload-light
    // and search-heavy: counting blobs only, all three fit the cap and nothing
    // would evict.
    const store = Store.open(dir);
    const body = new Uint8Array(50_000);
    const searchText = "y".repeat(200_000);
    const mk = (ageMs: number) =>
      fakeCall({ tsRequest: Date.now() - ageMs, requestBody: body, searchText });
    const [a, b, c] = [mk(3000), mk(2000), mk(1000)];
    for (const e of [a, b, c]) store.insertCall(e);

    const cap = 1_000_000;
    // Guard the regression directly: payload bytes alone are well under the
    // cap, so a payload-only sweeper evicts nothing here.
    const payloadBytes = store.queryAll<{ n: number }>(
      `SELECT SUM(COALESCE(length(request_body),0) + COALESCE(length(response_body),0)
              + COALESCE(length(sse_raw),0)) AS n FROM payloads`,
    )[0]!.n;
    expect(payloadBytes).toBeLessThan(cap);

    store.sweep({ payloadWindowMs: Infinity, eventWindowMs: Infinity, sizeCapBytes: cap });
    expect(store.getCall(c.id)).not.toBeNull(); // newest row fits
    expect(store.getCall(b.id)).toBeNull();
    expect(store.getCall(a.id)).toBeNull();
    store.close();
  });

  test("sweep bills the stored transcript, in BYTES not characters", () => {
    // Two bugs in one test. The transcript column was billed at 0, though for a
    // Mode B row it is a second copy of the whole readable text; and it is TEXT,
    // where SQLite's length() counts CHARACTERS. Agent traffic is routinely
    // non-ASCII (CJK, emoji, accented prose) at 3-4 bytes a character, so
    // billing characters lets the store grow to several times the configured
    // cap. The CAST is what makes the unit match search_bytes.
    const store = Store.open(dir);
    const wide = "日".repeat(60_000); // 60k chars, 180k bytes
    const mk = (ageMs: number) =>
      fakeCall({
        tsRequest: Date.now() - ageMs,
        requestBody: new Uint8Array(0),
        responseBody: null,
        searchText: "",
        displayMessages: [{ role: "user", content: wide }],
      });
    const [a, b] = [mk(2000), mk(1000)];
    for (const e of [a, b]) store.insertCall(e);
    // The cap sits between the two readings: under the true byte cost of both
    // rows (~360k) but above their character count (~120k). Billing characters
    // — or not billing at all — keeps everything; billing bytes evicts the older.
    store.sweep({ payloadWindowMs: Infinity, eventWindowMs: Infinity, sizeCapBytes: 200_000 });
    expect(store.getCall(b.id)).not.toBeNull(); // newest fits
    expect(store.getCall(a.id)).toBeNull(); // older row is over the byte cap
    store.close();
  });

  test("a search-text-heavy store actually shrinks to the configured cap on disk", () => {
    // End-to-end: the cap has to bound the file the user sees in `beagle
    // status`, not an internal tally. Realistic log-like text, since the
    // trigram index's disk cost scales with content entropy.
    const store = Store.open(dir);
    const rowText = (i: number) => {
      let s = "";
      while (s.length < 64 * 1024) {
        s += `2026-07-20T14:32:${String(s.length % 60).padStart(2, "0")}Z run-${i} ` +
          `src/core/store/store.ts:${s.length % 997} export function sweep(policy) { evict(); } ` +
          `the quick brown fox jumps over the lazy dog ${i * 7919 + s.length}\n`;
      }
      return s.slice(0, 64 * 1024);
    };
    for (let i = 0; i < 24; i++) {
      store.insertCall(fakeCall({
        tsRequest: Date.now() - (24 - i) * 1000,
        requestBody: new TextEncoder().encode("{}"),
        responseBody: null,
        searchText: rowText(i),
      }));
    }
    const cap = 1_500_000;
    store.sweep({ payloadWindowMs: Infinity, eventWindowMs: Infinity, sizeCapBytes: cap });
    expect(store.countCalls()).toBeGreaterThan(0); // a cap evicts, it does not wipe
    store.close(); // folds the WAL back into the main db

    const onDisk = statSync(join(dir, "beagle.db")).size +
      (existsSync(join(dir, "beagle.db-wal")) ? statSync(join(dir, "beagle.db-wal")).size : 0);
    // Measured ~1.5 MB against the 1.5 MB cap. The 2x headroom absorbs page
    // granularity and index-entropy drift, and still fails every way this can
    // regress: un-billed search text keeps all 24 rows (~7 MB), a no-op
    // incremental_vacuum strands the freed pages on the freelist (~5 MB), and
    // skipping the fts5 merge leaves dead trigram postings behind (~4 MB).
    expect(onDisk).toBeLessThan(cap * 2);
  });

  test("a store created before the auto_vacuum ordering fix converts and shrinks", () => {
    // The shrink test above only covers stores born with INCREMENTAL baked
    // in. Older binaries opened with journal_mode=WAL first, which
    // initializes the file header with auto_vacuum=NONE — the INCREMENTAL
    // pragma after it is silently ignored, and NONE cannot be changed on an
    // existing file by pragma alone. On such a store every PRAGMA
    // incremental_vacuum is a permanent no-op: swept pages pile up on the
    // freelist and the file never shrinks. Byte-for-byte the pre-fix open
    // sequence:
    const path = join(dir, "beagle.db");
    const legacy = new Database(path, { readwrite: true, create: true });
    legacy.exec("PRAGMA journal_mode=WAL");
    legacy.exec("PRAGMA secure_delete=ON");
    legacy.exec("PRAGMA auto_vacuum=INCREMENTAL"); // too late: header already written
    legacy.exec("PRAGMA foreign_keys=ON");
    legacy.exec(SCHEMA_SQL);
    legacy.exec(`PRAGMA user_version=${SCHEMA_VERSION}`);
    // Legacy bloat: a dropped table's pages land on the freelist, where NONE
    // strands them forever. The pragma probe pins the fixture — if it ever
    // reads 2, this test is silently exercising a fresh store instead.
    legacy.exec("CREATE TABLE junk (x BLOB)");
    legacy.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 400)
                 INSERT INTO junk SELECT zeroblob(16384) FROM n`);
    legacy.exec("DROP TABLE junk");
    expect((legacy.query("PRAGMA auto_vacuum").get() as { auto_vacuum: number }).auto_vacuum).toBe(0);
    legacy.close(); // folds the WAL into the main file
    const before = statSync(path).size;

    // Reopening must detect NONE and convert with a one-time VACUUM, so the
    // header — not just this connection's pending setting — reads INCREMENTAL.
    const store = Store.open(dir);
    expect(store.pragma("auto_vacuum")).toBe(2);
    expect(store.pragma("freelist_count")).toBe(0); // the stranded pages went with it
    // And reclaim must now actually work on this file: fill, evict to a cap,
    // and the bytes on disk — not an internal tally — have to come down.
    const filler = (i: number) =>
      `row ${i} ` + "the quick brown fox jumps over the lazy dog ".repeat(1500);
    for (let i = 0; i < 12; i++) {
      store.insertCall(fakeCall({
        tsRequest: Date.now() - (12 - i) * 1000,
        requestBody: new TextEncoder().encode("{}"),
        responseBody: null,
        searchText: filler(i),
      }));
    }
    const cap = 1_000_000;
    store.sweep({ payloadWindowMs: Infinity, eventWindowMs: Infinity, sizeCapBytes: cap });
    expect(store.countCalls()).toBeGreaterThan(0); // a cap evicts, it does not wipe
    store.close();
    const onDisk = statSync(path).size +
      (existsSync(`${path}-wal`) ? statSync(`${path}-wal`).size : 0);
    // Unconverted, the ~6.5 MB of stranded junk pages alone blows this bound.
    expect(onDisk).toBeLessThan(cap * 2);
    expect(onDisk).toBeLessThan(before); // the pre-existing bloat itself was released
  });

  test("a mass eviction survives SQLite's bound-parameter ceiling", () => {
    // The eviction list used to go into one `id IN (...)`, which throws past
    // 65535 ids — SQLite indexes bound parameters with a 16-bit value. The
    // daemon's sweeper has no try/catch, so that throw takes the sweep out
    // entirely. Reachable exactly where this accounting fix bites: a large
    // over-cap store's first sweep drops everything above the cap at once.
    // 4500 rows crosses several EVICT_BATCH boundaries in ~a second; the same
    // loop is what keeps the 65535-id case from ever forming a statement.
    const store = Store.open(dir);
    const n = 4500;
    for (let i = 0; i < n; i++) {
      store.insertCall(fakeCall({
        tsRequest: Date.now() - (n - i) * 10,
        requestBody: new TextEncoder().encode("{}"),
        responseBody: null,
        searchText: `row ${i} short search text`,
      }));
    }
    expect(store.countCalls()).toBe(n);
    store.sweep({ payloadWindowMs: Infinity, eventWindowMs: Infinity, sizeCapBytes: 10_000 });
    // Evicted down to what the cap holds, and nothing threw on the way.
    expect(store.countCalls()).toBeLessThan(200);
    expect(store.countCalls()).toBeGreaterThan(0);
    store.close();
    // Explicit timeout: 4500 inserts plus a batched sweep is ~1s on a dev box
    // but ~9s on CI's Linux runner, which overran bun's 5s default and failed
    // the whole suite. The work is inherently slow, not hung — the row count
    // is what makes the EVICT_BATCH boundaries this test exists to cross.
  }, 30_000);

  test("sweep ages out sessions and runs on the payload window (R11)", () => {
    const store = Store.open(dir);
    const old = Date.now() - 8 * 24 * 3600_000;
    store.insertSession({ id: "old-s", agent: "a", provider: "p", firstTs: old, lastTs: old });
    store.insertSession({ id: "new-s", agent: "a", provider: "p", firstTs: Date.now(), lastTs: Date.now() });
    store.insertRun({ id: "old-r", agent: "a", provider: "p", upstream: "http://x", authLocation: null, extraHeaders: null, createdTs: old });
    store.sweep({ payloadWindowMs: 7 * 24 * 3600_000, eventWindowMs: Infinity, sizeCapBytes: Infinity });
    expect(store.findSessionBy("run_id", ["old-r"], { agent: "a", provider: "p" })).toBeNull();
    expect(store.listRuns().find((r) => r.id === "old-r")).toBeUndefined();
    expect(
      store.findSessionBy("head_hash", ["nope"], { agent: "a", provider: "p" }),
    ).toBeNull();
    store.close();
  });

  test("purge by session removes that session only", () => {
    const store = Store.open(dir);
    const a = fakeCall({ sessionId: "s1" });
    const b = fakeCall({ sessionId: "s2" });
    store.insertCall(a);
    store.insertCall(b);
    store.purge({ kind: "session", sessionId: "s1" });
    expect(store.getCall(a.id)).toBeNull();
    expect(store.getCall(b.id)).not.toBeNull();
    store.close();
  });

  test("demo purge removes only demo calls, events, sessions, and runs", () => {
    const store = Store.open(dir);
    const demo = fakeCall({ sessionId: "demo-s", runId: "demo-r", agent: DEMO_AGENT });
    const real = fakeCall({ sessionId: "real-s", runId: "real-r" });
    store.insertSession({ id: demo.sessionId, agent: DEMO_AGENT, firstTs: 1, lastTs: 2 });
    store.insertSession({ id: real.sessionId, agent: real.agent, firstTs: 1, lastTs: 2 });
    store.insertRun({ id: demo.runId, agent: DEMO_AGENT, provider: "loopback-demo", upstream: "http://127.0.0.1:1", authLocation: null, extraHeaders: null, createdTs: 1 });
    store.insertRun({ id: real.runId, agent: "claude-code", provider: "anthropic", upstream: "http://127.0.0.1:2", authLocation: null, extraHeaders: null, createdTs: 1 });
    store.insertCall(demo);
    store.insertCall(real);
    for (const [call, fingerprint] of [[demo, "demo-fp"], [real, "real-fp"]] as const) {
      store.upsertLeakEvent({
        fingerprint, sessionId: call.sessionId, detector: "d", secretType: "t",
        severity: "high", confidenceTier: "structured", destination: "x",
        callId: call.id, ts: Date.now(),
      });
    }

    store.purge({ kind: "demo" });
    expect(store.getCall(demo.id)).toBeNull();
    expect(store.getCall(real.id)).not.toBeNull();
    expect(listLeakEvents(store).map((e) => e.sessionId)).toEqual(["real-s"]);
    expect(store.queryAll(`SELECT id FROM sessions WHERE id='demo-s'`)).toEqual([]);
    expect(store.listRuns().map((r) => r.id)).toEqual(["real-r"]);
    store.close();
  });

  test("demo events age out before their identity session is removed", () => {
    const store = Store.open(dir);
    const old = Date.now() - 10_000;
    const demo = fakeCall({ sessionId: "demo-s", agent: DEMO_AGENT, tsRequest: old });
    store.insertSession({ id: demo.sessionId, agent: DEMO_AGENT, firstTs: old, lastTs: old });
    store.insertCall(demo);
    store.upsertLeakEvent({
      fingerprint: "demo-fp", sessionId: demo.sessionId, detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured", destination: "x",
      callId: demo.id, ts: old,
    });

    store.sweep({ payloadWindowMs: 1_000, eventWindowMs: Infinity, sizeCapBytes: Infinity });
    expect(listLeakEvents(store)).toEqual([]);
    expect(store.countLeakEvents()).toBe(0);
    store.close();
  });

  test("panic purge erases everything including leak events and FTS", () => {
    const store = Store.open(dir);
    const call = fakeCall();
    store.insertCall(call);
    store.upsertLeakEvent({
      fingerprint: "fp", sessionId: call.sessionId, detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured", destination: "x",
      callId: call.id, ts: Date.now(),
    });
    store.panicPurge();
    expect(store.getCall(call.id)).toBeNull();
    expect(listLeakEvents(store)).toEqual([]);
    expect(store.searchLiteral("secret-xyz")).toEqual([]);
    store.close();
  });
});

describe("ulid", () => {
  test("time-sortable and unique", () => {
    const a = ulid(1000);
    const b = ulid(2000);
    expect(a < b).toBe(true);
    expect(a).toHaveLength(26);
    const many = new Set(Array.from({ length: 1000 }, () => ulid()));
    expect(many.size).toBe(1000);
  });
});

// Display grouping (turn_link) — the side table that folds Mode B tool rows
// under their turn. Deliberately NOT exchanges.prompt_key (see the schema
// note): these are grouping metadata with their own lifecycle.
describe("turn_link (linkTurns + cleanup)", () => {
  let dir: string;
  beforeEach(() => (dir = tmpRoot()));
  const rows = (s: Store) =>
    s.queryAll<{ session_id: string; link_key: string; prompt_key: string; ordinal: number; seq: number }>(
      `SELECT session_id, link_key, prompt_key, ordinal, seq FROM turn_link ORDER BY link_key`,
    );

  test("upsert is idempotent and re-links update in place", () => {
    const store = Store.open(dir);
    store.linkTurns("sess-1", [
      { linkKey: "call:c1", promptKey: "k1", ordinal: 0, seq: 0 },
      { linkKey: "call:c2", promptKey: "k1", ordinal: 0, seq: 1 },
    ]);
    // The codex tailer re-emits links across its retry window — byte-identical
    // re-delivery must not error or duplicate…
    store.linkTurns("sess-1", [{ linkKey: "call:c1", promptKey: "k1", ordinal: 0, seq: 0 }]);
    expect(rows(store).length).toBe(2);
    // …and a grown/corrected link for the same key replaces its row.
    store.linkTurns("sess-1", [{ linkKey: "call:c1", promptKey: "k2", ordinal: 1, seq: 3 }]);
    expect(rows(store).find((r) => r.link_key === "call:c1")).toMatchObject({ prompt_key: "k2", ordinal: 1, seq: 3 });
    store.close();
  });

  test("purging a session removes its links; other sessions keep theirs", () => {
    const store = Store.open(dir);
    store.insertCall(fakeCall({ sessionId: "sess-a" }));
    store.insertCall(fakeCall({ sessionId: "sess-b" }));
    store.linkTurns("sess-a", [{ linkKey: "call:a1", promptKey: "k", ordinal: 0, seq: 0 }]);
    store.linkTurns("sess-b", [{ linkKey: "call:b1", promptKey: "k", ordinal: 0, seq: 0 }]);
    store.purge({ kind: "session", sessionId: "sess-a" });
    expect(rows(store).map((r) => r.session_id)).toEqual(["sess-b"]);
    store.close();
  });

  test("a row-keyed link dies with its row, even while the session lives on", () => {
    // Claude hook links are keyed row:<exchange id>. Retention can evict the
    // tool row while the session keeps newer rows — the link must not outlive
    // the row it annotates.
    const store = Store.open(dir);
    const t0 = Date.now();
    const old = fakeCall({ id: ulid(t0 - 60_000), tsRequest: t0 - 60_000 });
    const fresh = fakeCall({ id: ulid(t0), tsRequest: t0 });
    store.insertCall(old);
    store.insertCall(fresh);
    store.linkTurns("sess-1", [
      { linkKey: `row:${old.id}`, promptKey: "p", ordinal: 0, seq: 0 },
      { linkKey: `row:${fresh.id}`, promptKey: "p", ordinal: 0, seq: 0 },
    ]);
    store.purge({ kind: "before", ts: t0 - 30_000 });
    expect(rows(store).map((r) => r.link_key)).toEqual([`row:${fresh.id}`]);
    store.close();
  });

  test("purge-all leaves no links behind", () => {
    const store = Store.open(dir);
    store.insertCall(fakeCall({ sessionId: "sess-1" }));
    store.linkTurns("sess-1", [{ linkKey: "call:c1", promptKey: "k", ordinal: 0, seq: 0 }]);
    store.purge({ kind: "all" });
    expect(rows(store)).toEqual([]);
    store.close();
  });
});

describe("updateSession recency", () => {
  let dir: string;
  beforeEach(() => (dir = tmpRoot()));

  test("last_ts only moves forward — a historical re-emit never rewinds recency", () => {
    // Rollout re-emits (answers, turn links) carry frozen historical stamps
    // through the resolver; before this guard one rewound last_ts and dropped
    // a live session down the sessions list.
    const store = Store.open(dir);
    store.insertSession({ id: "s1", firstTs: 1000, lastTs: 5000 });
    store.updateSession("s1", { lastTs: 2000 }); // older — must not rewind
    expect(store.queryAll<{ t: number }>(`SELECT last_ts AS t FROM sessions WHERE id='s1'`)[0]!.t).toBe(5000);
    store.updateSession("s1", { lastTs: 9000 }); // newer — moves forward
    expect(store.queryAll<{ t: number }>(`SELECT last_ts AS t FROM sessions WHERE id='s1'`)[0]!.t).toBe(9000);
    // A no-ts update (convId/headHash only) leaves recency alone.
    store.updateSession("s1", { convId: "c" });
    expect(store.queryAll<{ t: number }>(`SELECT last_ts AS t FROM sessions WHERE id='s1'`)[0]!.t).toBe(9000);
    store.close();
  });
});
