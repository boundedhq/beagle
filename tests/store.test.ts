import { beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store, SCHEMA_VERSION, StoreVersionError } from "../src/core/store/store";
import { listLeakEvents } from "../src/viewer/feed-query";
import type { CallRecord } from "../src/core/store/store";
import { ulid } from "../src/core/store/ulid";

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

  test("migrates an older store forward in place, preserving captured data", () => {
    // Populate a real store, then rewind its on-disk schema to look like a v1
    // store (no v2 columns, user_version=1) so Store.open exercises migrate().
    const store = Store.open(dir);
    const ex = fakeCall();
    store.insertCall(ex);
    store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "sess-1", detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured",
      destination: "anthropic/m", callId: ex.id, ts: Date.now(),
    });
    store.close();

    const raw = new Database(join(dir, "beagle.db"));
    raw.exec("ALTER TABLE exchanges DROP COLUMN redacted");
    raw.exec("ALTER TABLE leak_occurrences DROP COLUMN span_start");
    raw.exec("ALTER TABLE leak_occurrences DROP COLUMN span_end");
    raw.exec("PRAGMA user_version=1");
    raw.close();

    // Reopen: should migrate additively, not quarantine or throw.
    const migrated = Store.open(dir);
    expect(migrated.pragma("user_version")).toBe(SCHEMA_VERSION);
    // Pre-migration rows survived.
    expect(migrated.getCall(ex.id)?.provider).toBe("anthropic");
    expect(listLeakEvents(migrated).length).toBe(1);
    // The re-added columns now accept writes (the redact-on-capture flag).
    const ex2 = fakeCall({ redacted: true });
    migrated.insertCall(ex2);
    expect(migrated.getCall(ex2.id)?.redacted).toBe(true);
    migrated.close();
  });
});

describe("Call write/read", () => {
  let dir: string;
  beforeEach(() => (dir = tmpRoot()));

  test("insert then read back full call with payload", () => {
    const store = Store.open(dir);
    const ex = fakeCall();
    store.insertCall(ex);
    const got = store.getCall(ex.id);
    expect(got?.provider).toBe("anthropic");
    expect(new TextDecoder().decode(got!.requestBody!)).toContain("secret-xyz");
    expect(got?.requestHeaders).toEqual([["content-type", "application/json"]]);
    store.close();
  });

  test("getCall supports unambiguous id prefix", () => {
    const store = Store.open(dir);
    const ex = fakeCall();
    store.insertCall(ex);
    expect(store.getCall(ex.id.slice(0, 8))?.id).toBe(ex.id);
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

describe("Leak events", () => {
  let dir: string;
  beforeEach(() => (dir = tmpRoot()));

  test("upsert: first insert reports fresh, second same-key increments", () => {
    const store = Store.open(dir);
    const ex = fakeCall();
    store.insertCall(ex);
    const first = store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "sess-1", detector: "aws-access-key",
      secretType: "aws-key", severity: "high", confidenceTier: "structured",
      destination: "anthropic/claude-sonnet-5", callId: ex.id, ts: Date.now(),
    });
    expect(first.fresh).toBe(true);
    const second = store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "sess-1", detector: "aws-access-key",
      secretType: "aws-key", severity: "high", confidenceTier: "structured",
      destination: "anthropic/claude-sonnet-5", callId: ex.id, ts: Date.now(),
    });
    expect(second.fresh).toBe(false);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]?.occurrences).toBe(2);
    store.close();
  });

  test("same fingerprint, new destination is a fresh event", () => {
    const store = Store.open(dir);
    const ex = fakeCall();
    store.insertCall(ex);
    const base = {
      fingerprint: "fp1", sessionId: "sess-1", detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured", callId: ex.id, ts: Date.now(),
    };
    store.upsertLeakEvent({ ...base, destination: "anthropic/m" });
    const r = store.upsertLeakEvent({ ...base, destination: "openai/m" });
    expect(r.fresh).toBe(true);
    expect(listLeakEvents(store).length).toBe(2);
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

  test("panic purge erases everything including leak events and FTS", () => {
    const store = Store.open(dir);
    const ex = fakeCall();
    store.insertCall(ex);
    store.upsertLeakEvent({
      fingerprint: "fp", sessionId: ex.sessionId, detector: "d", secretType: "t",
      severity: "high", confidenceTier: "structured", destination: "x",
      callId: ex.id, ts: Date.now(),
    });
    store.panicPurge();
    expect(store.getCall(ex.id)).toBeNull();
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
