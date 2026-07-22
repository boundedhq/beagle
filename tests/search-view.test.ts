import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store, type CallRecord } from "../src/core/store/store";
import { searchCalls } from "../src/viewer/feed-query";
import { ulid } from "../src/core/store/ulid";

// The dashboard's search view (redesign): a hit must carry enough to be
// understood in place — call metadata, how many times the term matched, and
// real context snippets around the match — so the user never has to hunt
// through the feed to learn where a result lives or where the term appeared.

let seq = 0;
function mkCall(over: Partial<CallRecord> & { searchText: string }): CallRecord {
  const ts = over.tsRequest ?? Date.now();
  return {
    id: over.id ?? ulid(ts + seq++), // unique even at identical ts
    sessionId: "s1",
    runId: "r1",
    source: "wire",
    agent: "claude-code",
    provider: "anthropic",
    model: "claude-sonnet-5",
    endpoint: "/v1/messages",
    tsRequest: ts,
    tsResponse: ts + 1,
    status: 200,
    summary: "did a thing",
    scanState: "ok",
    captureState: "ok",
    sessionTier: "prefix",
    requestBody: new TextEncoder().encode("{}"),
    requestHeaders: [],
    responseBody: null,
    responseHeaders: null,
    sseRaw: null,
    ...over,
  };
}

describe("searchCalls (viewer search projection)", () => {
  let stateDir: string;
  let store: Store;

  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-search-"));
    store = Store.open(stateDir);
  });
  afterEach(() => {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  });

  test("a hit carries call metadata and a snippet with context on both sides", () => {
    store.insertCall(
      mkCall({ searchText: "alpha beta PI Memory gamma delta", summary: "asked about memory" }),
    );
    const { hits, truncated } = searchCalls(store, "pi memory");
    expect(truncated).toBe(false);
    expect(hits).toHaveLength(1);
    const h = hits[0]!;
    expect(h.sessionId).toBe("s1");
    expect(h.agent).toBe("claude-code");
    expect(h.model).toBe("claude-sonnet-5");
    expect(h.source).toBe("wire");
    expect(h.summary).toBe("asked about memory");
    expect(h.hasLeak).toBe(false);
    expect(h.matchCount).toBe(1);
    expect(h.snippets).toHaveLength(1);
    // The match is the ORIGINAL text (its real case), not the typed term.
    expect(h.snippets[0]!.match).toBe("PI Memory");
    expect(h.snippets[0]!.pre).toBe("alpha beta ");
    expect(h.snippets[0]!.post).toBe(" gamma delta");
  });

  test("matching is case-insensitive in both directions (SQLite LIKE semantics)", () => {
    store.insertCall(mkCall({ searchText: "the pi memory subsystem" }));
    expect(searchCalls(store, "PI MEMORY").hits).toHaveLength(1);
    store.insertCall(mkCall({ searchText: "SELECT * FROM EXCHANGES" }));
    expect(searchCalls(store, "from exchanges").hits).toHaveLength(1);
  });

  test("matchCount counts every occurrence; snippets cap at 3", () => {
    const gap = "x".repeat(300); // far enough apart that windows never merge
    store.insertCall({
      ...mkCall({ searchText: ["tok", gap, "tok", gap, "tok", gap, "tok", gap, "tok"].join(" ") }),
    });
    const h = searchCalls(store, "tok").hits[0]!;
    expect(h.matchCount).toBe(5);
    expect(h.snippets).toHaveLength(3);
  });

  test("occurrences inside an already-shown window don't mint a near-duplicate snippet", () => {
    store.insertCall(mkCall({ searchText: "aa aa aa" }));
    const h = searchCalls(store, "aa").hits[0]!;
    expect(h.matchCount).toBe(3);
    expect(h.snippets).toHaveLength(1); // the one window already shows all three
  });

  test("long content: snippets clip with ellipses and collapse whitespace", () => {
    const content = `${"x".repeat(500)}\n\n  NEEDLE\t\tafter the match ${"y".repeat(500)}`;
    store.insertCall(mkCall({ searchText: content }));
    const s = searchCalls(store, "NEEDLE").hits[0]!.snippets[0]!;
    expect(s.match).toBe("NEEDLE");
    // clipped on both sides → ellipsis markers, and no raw newlines/tabs survive
    expect(s.pre.startsWith("…")).toBe(true);
    expect(s.post.endsWith("…")).toBe(true);
    for (const part of [s.pre, s.match, s.post]) {
      expect(part).not.toMatch(/[\n\t]/);
    }
    // the collapsed run before the match reads as a single space
    expect(s.pre.endsWith("x ")).toBe(true);
    expect(s.post.startsWith(" after the match")).toBe(true);
    // windows are bounded — a 1000-char body must not ship whole
    expect(s.pre.length).toBeLessThan(80);
    expect(s.post.length).toBeLessThan(120);
  });

  test("hits order newest-first", () => {
    const t0 = Date.now();
    store.insertCall(mkCall({ id: "older", tsRequest: t0 - 2000, searchText: "shared needle" }));
    store.insertCall(mkCall({ id: "newest", tsRequest: t0, searchText: "shared needle" }));
    store.insertCall(mkCall({ id: "middle", tsRequest: t0 - 1000, searchText: "shared needle" }));
    const { hits } = searchCalls(store, "needle");
    expect(hits.map((h) => h.callId)).toEqual(["newest", "middle", "older"]);
  });

  test("hasLeak reflects recorded leak occurrences on that call", () => {
    const leaky = mkCall({ id: "leaky", searchText: "with secret needle" });
    const clean = mkCall({ id: "clean2", searchText: "clean needle" });
    store.insertCall(leaky);
    store.insertCall(clean);
    store.upsertLeakEvent({
      fingerprint: "fp1", sessionId: "s1", detector: "regex", secretType: "github-pat",
      severity: "high", confidenceTier: "structured", destination: "api.anthropic.com",
      callId: "leaky", ts: Date.now(),
    });
    const byId = new Map(searchCalls(store, "needle").hits.map((h) => [h.callId, h]));
    expect(byId.get("leaky")!.hasLeak).toBe(true);
    expect(byId.get("clean2")!.hasLeak).toBe(false);
  });

  test("LIKE wildcards in the term stay literal", () => {
    store.insertCall(mkCall({ id: "pct", searchText: "progress 100% done" }));
    store.insertCall(mkCall({ id: "x", searchText: "progress 100x done" }));
    const pct = searchCalls(store, "100%");
    expect(pct.hits.map((h) => h.callId)).toEqual(["pct"]);
    store.insertCall(mkCall({ id: "underscore", searchText: "key a_c here" }));
    store.insertCall(mkCall({ id: "abc", searchText: "key abc here" }));
    expect(searchCalls(store, "a_c").hits.map((h) => h.callId)).toEqual(["underscore"]);
  });

  test("results past the cap: newest kept, truncated flagged", () => {
    const t0 = Date.now();
    for (let i = 0; i < 15; i++) {
      store.insertCall(mkCall({ id: `c${String(i).padStart(2, "0")}`, tsRequest: t0 + i, searchText: "capped needle" }));
    }
    const { hits, truncated } = searchCalls(store, "capped", 10);
    expect(truncated).toBe(true);
    expect(hits).toHaveLength(10);
    expect(hits[0]!.callId).toBe("c14"); // newest survives the cap
    expect(hits.at(-1)!.callId).toBe("c05");
  });

  test("an empty term matches nothing (never a scan-everything query)", () => {
    store.insertCall(mkCall({ searchText: "anything at all" }));
    expect(searchCalls(store, "")).toEqual({ hits: [], truncated: false });
  });

  // R7 carries into the search surface: a leak-bearing hit ships its detected
  // values so the client can red-mark them inside snippets, and a snippet
  // window never bisects a value (a half-shown token can't be highlighted).
  test("a leak-bearing hit carries its secret values for snippet highlighting", () => {
    const token = "ghp_SnippetSnippetSnippetSnippetSnip1234";
    const body = `{"messages":[{"role":"user","content":"use ${token} for the login"}]}`;
    const c = mkCall({
      id: "leaky-snip",
      searchText: `needle then ${token} inline`,
      requestBody: new TextEncoder().encode(body),
    });
    store.insertCall(c);
    const at = body.indexOf(token);
    store.upsertLeakEvent({
      fingerprint: "fp-s", sessionId: "s1", detector: "gitleaks", secretType: "github-pat",
      severity: "high", confidenceTier: "structured", destination: "api.anthropic.com",
      callId: "leaky-snip", ts: Date.now(), spanStart: at, spanEnd: at + token.length,
    });
    const h = searchCalls(store, "needle").hits[0]!;
    expect(h.hasLeak).toBe(true);
    expect(h.leaks).toEqual([{ value: token, secretType: "github-pat", tier: "structured" }]);
    // a clean hit ships no values
    store.insertCall(mkCall({ id: "clean-snip", searchText: "needle only" }));
    const clean = searchCalls(store, "needle").hits.find((x) => x.callId === "clean-snip")!;
    expect(clean.leaks).toEqual([]);
  });

  test("a redacted row's placeholders ride as its leak values — no raw body needed", () => {
    // Redact-on-capture rows carry [REDACTED:type:shorthash] placeholders in
    // body and search text alike; the placeholders ARE the highlightable
    // values, and the TYPE between the colons labels the chip (a legacy
    // hash-less "[REDACTED:type]" must parse to the same clean type).
    const c = mkCall({
      id: "redacted-row",
      searchText: "needle then [REDACTED:github-pat:ab12cd] inline",
      requestBody: new TextEncoder().encode('{"m":"use [REDACTED:github-pat:ab12cd] here"}'),
      redacted: true,
    });
    store.insertCall(c);
    store.upsertLeakEvent({
      fingerprint: "fp-r", sessionId: "s1", detector: "gitleaks", secretType: "github-pat",
      severity: "high", confidenceTier: "structured", destination: "api.anthropic.com",
      callId: "redacted-row", ts: Date.now(),
    });
    const h = searchCalls(store, "needle").hits[0]!;
    expect(h.leaks).toEqual([
      { value: "[REDACTED:github-pat:ab12cd]", secretType: "github-pat", tier: "structured" },
    ]);
    // legacy hash-less placeholder: same clean type, bracket never leaks in
    store.insertCall(mkCall({
      id: "redacted-legacy",
      searchText: "needle legacy [REDACTED:github-pat] here",
      requestBody: new TextEncoder().encode("[REDACTED:github-pat]"),
      redacted: true,
    }));
    store.upsertLeakEvent({
      fingerprint: "fp-r2", sessionId: "s1", detector: "gitleaks", secretType: "github-pat",
      severity: "high", confidenceTier: "structured", destination: "api.anthropic.com",
      callId: "redacted-legacy", ts: Date.now(),
    });
    const legacy = searchCalls(store, "needle").hits.find((x) => x.callId === "redacted-legacy")!;
    expect(legacy.leaks[0]!.secretType).toBe("github-pat");
  });

  test("one corrupt display_messages row degrades to body-only values, not a failed search", () => {
    const token = "ghp_CorruptCorruptCorruptCorruptCorr1234";
    const body = `{"content":"${token}"}`;
    store.insertCall(mkCall({
      id: "corrupt-dm",
      searchText: `needle with ${token}`,
      requestBody: new TextEncoder().encode(body),
    }));
    const at = body.indexOf(token);
    store.upsertLeakEvent({
      fingerprint: "fp-c", sessionId: "s1", detector: "gitleaks", secretType: "github-pat",
      severity: "high", confidenceTier: "structured", destination: "api.anthropic.com",
      callId: "corrupt-dm", ts: Date.now(), spanStart: at, spanEnd: at + token.length,
    });
    // Corrupt the stored transcript out from under the row — the search must
    // still answer (the old getCall path would THROW here and 500 the whole
    // request; the narrow path guards its parse).
    store.queryAll(`UPDATE payloads SET display_messages='{not json' WHERE exchange_id='corrupt-dm'`);
    const { hits } = searchCalls(store, "needle");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.leaks.map((l) => l.value)).toEqual([token]);
  });

  test("a snippet window extends rather than bisect a detected secret value", () => {
    const token = "ghp_EdgeEdgeEdgeEdgeEdgeEdgeEdgeEdge1234";
    // Place the token so the default post-window (100 chars) would cut it in
    // half: filler pushes its start to ~97 chars after the match ends.
    const text = `needle ${"a".repeat(92)}${token} trailing tail`;
    const body = `{"content":"${token}"}`;
    store.insertCall(mkCall({
      id: "edge-snip",
      searchText: text,
      requestBody: new TextEncoder().encode(body),
    }));
    const at = body.indexOf(token);
    store.upsertLeakEvent({
      fingerprint: "fp-e", sessionId: "s1", detector: "gitleaks", secretType: "github-pat",
      severity: "high", confidenceTier: "structured", destination: "api.anthropic.com",
      callId: "edge-snip", ts: Date.now(), spanStart: at, spanEnd: at + token.length,
    });
    const s = searchCalls(store, "needle").hits[0]!.snippets[0]!;
    expect(s.post).toContain(token); // whole, not beheaded at the window edge
    expect(s.post.endsWith("…")).toBe(true); // still clipped after the token
  });
});
