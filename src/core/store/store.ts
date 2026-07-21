// Store (design §4, §6.6). Single writer (the daemon); CLI/viewer open
// read-only. WAL + secure_delete so purged secrets don't linger; retention
// sweeper and purge share one code path so R11 semantics can't drift.
import { chmodSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { openDb, type Db } from "../../adapters/sqlite";
import { SCHEMA_SQL, SCHEMA_VERSION } from "./schema";
import { quarantineCorruptDb } from "./quarantine";
import { ulid } from "./ulid";

export { SCHEMA_VERSION };

export class StoreVersionError extends Error {}

// Naming note: the domain type is `Call`, but the physical SQLite table stays
// `exchanges` (and its columns `exchange_id` / `first_exchange`). The rename to
// "call" was UI/code-only — keeping the schema names avoids a data migration.
// The SQL below aliases the columns back to the Call shape (e.g. `exchange_id
// AS callId`), so the storage layer and the type stay decoupled on purpose.
export interface CallRecord {
  id: string;
  sessionId: string;
  runId: string;
  source: "wire" | "otel";
  agent?: string;
  provider?: string;
  model?: string;
  endpoint?: string;
  tsRequest: number;
  tsResponse?: number;
  status?: number;
  tokensIn?: number;
  tokensOut?: number;
  bytesReq?: number;
  bytesResp?: number;
  summary?: string;
  scanState: "ok" | "incomplete";
  captureState: "ok" | "truncated";
  sessionTier: string;
  redacted?: boolean; // true when redact-on-capture rewrote the stored body
  oneShot?: boolean; // stateless utility turn (e.g. title-gen) — no conversation identity
  promptKey?: string; // Mode B: per-turn prompt id (cross-batch turn stitching)
  requestBody: Uint8Array | null;
  requestHeaders: Array<[string, string]> | null;
  responseBody: Uint8Array | null;
  responseHeaders: Array<[string, string]> | null;
  sseRaw: Uint8Array | null;
  /** Pre-flattened display messages (Mode B's self-report structure, and the
   *  wire path's redacted projection). `detail` is redacted like `content` and
   *  is typed here so a reader can't silently skip a masked surface. */
  displayMessages?: Array<{ role: string; content: string; detail?: string }> | null;
  searchText: string;
}

export interface LeakEventInput {
  fingerprint: string;
  sessionId: string;
  detector: string;
  secretType: string;
  severity: string;
  confidenceTier: string;
  destination: string;
  callId: string;
  ts: number;
  spanStart?: number; // char span of the secret in the request body (R7 highlight)
  spanEnd?: number;
}

export interface SweepPolicy {
  payloadWindowMs: number;
  eventWindowMs: number;
  sizeCapBytes: number;
}

export type PurgeSpec =
  | { kind: "all" }
  | { kind: "session"; sessionId: string }
  | { kind: "before"; ts: number };

export interface SearchHit {
  callId: string;
  sessionId: string;
  tsRequest: number;
}

const DB_FILE = "beagle.db";

// attachOtelResponse staleness margin. An answer can only attach to a turn row
// that PREDATES it — an answer is generated after its own prompt, so a
// response-less row newer than the answer belongs to a later turn (a re-emitted
// codex-rollout answer racing a re-typed identical prompt). The margin absorbs
// cross-source timestamp imprecision (rollout ISO-ms vs OTLP ns, file-mtime
// fallback stamps), not real ordering: keep it well under the seconds a human
// takes to read an answer and re-send the same prompt.
const ATTACH_MAX_SKEW_MS = 2000;

// Disk bytes the fts5 trigram index costs per byte of indexed content —
// the stored content copy plus the trigram postings. Measured on bun:sqlite
// (fts5, tokenize='trigram'): ~2.3x for highly repetitive text, ~3.0x for
// typical agent traffic (JSON + prose + code + paths), ~5.3x for high-entropy
// text like base64 blobs. 3 tracks the typical case; the cap is a budget, not
// a hard invariant, so a rough factor beats today's implicit 0.
const FTS_DISK_FACTOR = 3;

// Page budget for the post-delete fts5 segment merge (see reclaim()). Bounds
// the work one sweep can do on a large index; a merge with nothing to do is
// free (~0.01ms), so it can run on every sweep unconditionally.
const FTS_MERGE_PAGES = 4096;

// Max ids per eviction statement. SQLite indexes bound parameters with a
// 16-bit value, so one `id IN (...)` carrying more than 65535 of them throws;
// stay well under, since deleteCallsWhere nests the list inside subqueries.
const EVICT_BATCH = 2000;

export class Store {
  private constructor(private db: Db) {}

  static open(stateDir: string): Store {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    chmodSync(stateDir, 0o700);
    const path = join(stateDir, DB_FILE);
    const db = openDb(path);
    chmodSync(path, 0o600);
    // auto_vacuum FIRST, before anything writes the header: the setting is
    // baked in when the db file is initialized, and journal_mode=WAL does that
    // initializing. Set after WAL it is silently ignored (auto_vacuum stays 0),
    // which makes every `PRAGMA incremental_vacuum` below a no-op and leaves
    // swept pages on the freelist instead of returning them to the OS.
    db.exec("PRAGMA auto_vacuum=INCREMENTAL");
    db.exec("PRAGMA journal_mode=WAL");
    db.exec("PRAGMA secure_delete=ON");
    db.exec("PRAGMA foreign_keys=ON");
    const v = pragmaNumber(db, "user_version");
    if (v > SCHEMA_VERSION) throw versionError(v); // a newer store: upgrade beagle
    // Files initialized before that ordering fix have NONE baked into the
    // header, and a pragma cannot change an existing file — only a full
    // VACUUM can (outside any transaction; it rebuilds the db with the
    // connection's PENDING auto_vacuum, pinned inside the block so this
    // can't decay into an every-open full rebuild if the pragma up top ever
    // moves). Probe the header, not user_version: the fix shipped inside
    // the v6 commit, so migrated v6 stores carry NONE too. One-time per
    // store — converted files read INCREMENTAL and skip this — but it
    // rewrites the whole db, so a multi-GB store makes this open slow,
    // once. The rebuild rides through the WAL, which keeps its high-water
    // size until close; checkpoint so conversion doesn't park a db-sized
    // -wal next to the file it just shrank (panicPurge does the same).
    // Best-effort: on failure (disk too full to rebuild, say) reclaim()
    // stays the no-op it already was and the next open retries; never
    // brick capture over a housekeeping step.
    if (pragmaNumber(db, "auto_vacuum") === 0) {
      try {
        db.exec("PRAGMA auto_vacuum=INCREMENTAL");
        db.exec("VACUUM");
        db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
      } catch { /* still NONE; retry next open */ }
    }
    db.exec(SCHEMA_SQL); // fresh DBs get every column
    if (v > 0 && v < SCHEMA_VERSION) migrate(db, v); // bring old stores forward, data intact
    db.exec(`PRAGMA user_version=${SCHEMA_VERSION}`);
    return new Store(db);
  }

  // Open, or on corruption quarantine the bad file and start fresh (§6.6):
  // capture must resume, the agent must never be blocked.
  static openOrRecover(stateDir: string): Store {
    try {
      const store = Store.open(stateDir);
      // Cheap integrity probe: a corrupt header/page fails here, not mid-write.
      store.db.get("SELECT count(*) AS n FROM sqlite_master");
      return store;
    } catch (e) {
      // A version mismatch is NOT corruption: quarantining here would silently
      // shelve the entire capture history whenever an older binary opens a
      // newer store (e.g. a rollback after a schema bump). Surface it instead.
      if (e instanceof StoreVersionError) throw e;
      quarantineCorruptDb(stateDir);
      return Store.open(stateDir);
    }
  }

  static openReadOnly(stateDir: string): Store {
    const db = openDb(join(stateDir, DB_FILE), { readonly: true });
    db.exec("PRAGMA foreign_keys=ON");
    const v = pragmaNumber(db, "user_version");
    // A read-only handle can't migrate. Require the exact schema and surface a
    // clean version error otherwise — a newer store means "upgrade beagle", an
    // older one means "restart the daemon" (Store.open migrates it in place).
    // Never let a stale schema reach a query and throw a raw "no such column".
    if (v !== SCHEMA_VERSION) {
      db.close();
      throw versionError(v);
    }
    return new Store(db);
  }

  pragma(name: string): number | string {
    if (!/^[a-z_]+$/.test(name)) throw new Error(`invalid pragma name: ${name}`);
    const row = this.db.get<Record<string, number | string>>(`PRAGMA ${name}`);
    return row ? Object.values(row)[0]! : 0;
  }

  setUserVersionForTest(v: number): void {
    this.db.exec(`PRAGMA user_version=${v}`);
  }

  private inTx<T>(fn: () => T): T {
    this.db.exec("BEGIN");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  insertCall(call: CallRecord): void {
    this.inTx(() => {
      this.db.run(
        `INSERT INTO exchanges (id, session_id, run_id, source, agent, provider, model,
           endpoint, ts_request, ts_response, status, tokens_in, tokens_out,
           bytes_req, bytes_resp, summary, scan_state, capture_state, session_tier, redacted, one_shot,
           prompt_key, search_bytes)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [call.id, call.sessionId, call.runId, call.source, call.agent ?? null, call.provider ?? null,
         call.model ?? null, call.endpoint ?? null, call.tsRequest, call.tsResponse ?? null,
         call.status ?? null, call.tokensIn ?? null, call.tokensOut ?? null, call.bytesReq ?? null,
         call.bytesResp ?? null, call.summary ?? null, call.scanState, call.captureState, call.sessionTier,
         call.redacted ? 1 : null, call.oneShot ? 1 : null, call.promptKey ?? null,
         Buffer.byteLength(call.searchText, "utf8")],
      );
      this.db.run(
        `INSERT INTO payloads (exchange_id, request_body, request_headers,
           response_body, response_headers, sse_raw, display_messages) VALUES (?,?,?,?,?,?,?)`,
        [call.id, call.requestBody, call.requestHeaders ? JSON.stringify(call.requestHeaders) : null,
         call.responseBody, call.responseHeaders ? JSON.stringify(call.responseHeaders) : null, call.sseRaw,
         call.displayMessages ? JSON.stringify(call.displayMessages) : null],
      );
      this.db.run(`INSERT INTO exchanges_fts (content, exchange_id) VALUES (?,?)`,
        [call.searchText, call.id]);
    });
  }

  // Mode B cross-batch turn stitching: Claude Code flushes a turn's prompt in
  // one OTLP batch and its response ~seconds later in another, which used to
  // land as two rows (question with no answer + detached answer). Rejoin the
  // response to its turn row via (session, prompt_key). Returns null when no
  // turn row matches — the caller falls back to inserting the partial as its
  // own row (the old behavior, nothing is ever dropped) — otherwise the target
  // row's id, plus whether this call actually WROTE to it. Those two facts
  // diverge only in extend mode, and the daemon needs both: it broadcasts the
  // id so open dashboards refresh that row, but only when `changed`. A rollout
  // answer re-emits on every poll of its retry window, and each one is
  // "handled" (never re-inserted) while writing nothing — broadcasting those
  // would make every open tab refetch on a timer for a row that never moved.
  attachOtelResponse(input: {
    sessionId: string;
    promptKey: string;
    /** When the answer was produced — also the staleness bound: only rows with
     *  ts_request at or before this (plus skew) are attach targets. */
    tsResponse: number;
    model?: string;
    tokensIn?: number;
    tokensOut?: number;
    /** Given the turn row's existing summary and whether the row already holds
     *  a response, return the combined one — or null to leave it as is. Kept a
     *  callback so summary FORMATTING stays in the daemon next to buildSummary,
     *  and the store stays a dumb writer.
     *
     *  Called on EVERY write, growth included, so it must be idempotent: handed
     *  a summary it produced earlier it has to replace the answer half, never
     *  nest the whole line inside a fresh one. `hasResponse` is how it tells
     *  the two apart — see the daemon's callback, which falls back to leaving
     *  the summary alone when it can't recognize its own output. */
    composeSummary?: (existing: string | null, hasResponse: boolean) => string | null;
    redacted?: boolean;
    responseBody: Uint8Array | null;
    /** Codex rollout answers GROW while their turn runs (preamble → … → final
     *  reply), so their attach is a grow-only upsert: a longer body for the
     *  same turn replaces the shorter one, an equal/shorter re-emit drops as
     *  done. `ordinal` picks the Nth same-key row — hash(prompt) is the only
     *  join key, so repeated identical prompts share it. */
    extend?: { ordinal: number };
  }): { id: string; changed: boolean } | null {
    return this.inTx(() => {
      // The turn's EARLIEST response-less row — the one carrying the question,
      // since a turn's user_prompt always precedes its tool_results. Ordering
      // matters: a turn whose tool_results arrived in their own batch has
      // several rows sharing this prompt_key, and picking the newest would hang
      // the answer off a tool row while the question stayed unanswered. Order
      // by ts_request, not id: ids are ULIDs, only sortable across distinct
      // milliseconds (the random suffix decides within one). bytes_resp guards
      // double-attach: a second response for an already-answered turn stays a
      // separate row rather than overwriting. The ts_request bound refuses
      // STALE attaches: a row newer than the answer is a later turn's (same
      // prompt re-typed), and taking it would both mis-attribute this answer
      // and orphan that turn's real one — refusal fails safe (no stitch, never
      // a wrong one; see ATTACH_MAX_SKEW_MS).
      //
      // Extend mode (rollout answers) swaps the bytes_resp guard for the
      // grow-only rule below — same-turn growth IS the second response — and
      // addresses the row by turn ordinal instead of "earliest unanswered":
      // the grown answer's own row is already answered, and with repeated
      // identical prompts "earliest" would land every growth on turn one. The
      // staleness bound stays: a historical answer must still never claim a
      // NEWER re-ask's row, ordinal alignment or not.
      type Target = { id: string; tokens_in: number | null; tokens_out: number | null; summary: string | null; resp_len: number | null };
      const target = input.extend
        ? this.db.get<Target>(
            `SELECT e.id, e.tokens_in, e.tokens_out, e.summary, length(p.response_body) AS resp_len
             FROM exchanges e LEFT JOIN payloads p ON p.exchange_id = e.id
             WHERE e.session_id=? AND e.prompt_key=? AND e.source='otel' AND e.ts_request <= ?
             ORDER BY e.ts_request ASC, e.id ASC LIMIT 1 OFFSET ?`,
            [input.sessionId, input.promptKey, input.tsResponse + ATTACH_MAX_SKEW_MS, input.extend.ordinal],
          )
        : this.db.get<Target>(
            `SELECT id, tokens_in, tokens_out, summary, NULL AS resp_len FROM exchanges
             WHERE session_id=? AND prompt_key=? AND source='otel'
               AND (bytes_resp IS NULL OR bytes_resp=0) AND ts_request <= ?
             ORDER BY ts_request ASC, id ASC LIMIT 1`,
            [input.sessionId, input.promptKey, input.tsResponse + ATTACH_MAX_SKEW_MS],
          );
      if (!target) return null;
      const have = target.resp_len ?? 0;
      // Re-emit or stale shorter view — keep what we have. Handled, so the
      // caller must not re-insert; unchanged, so nothing to tell the viewer.
      if (input.extend && (input.responseBody?.byteLength ?? 0) <= have) {
        return { id: target.id, changed: false };
      }
      // Compose on growth too, or a turn that opened with a codex preamble
      // ("I'm checking the docs…") keeps describing the preamble forever while
      // the row holds the real answer. The callback owns not nesting its own
      // output — it gets `have > 0` to know this row already had a response.
      const summary = input.composeSummary ? input.composeSummary(target.summary, have > 0) : null;
      this.db.run(
        `UPDATE exchanges SET ts_response=?, model=COALESCE(?, model),
           tokens_in=?, tokens_out=?, bytes_resp=?, summary=COALESCE(?, summary),
           redacted=CASE WHEN ? THEN 1 ELSE redacted END
         WHERE id=?`,
        [input.tsResponse, input.model ?? null,
         addNullable(target.tokens_in, input.tokensIn), addNullable(target.tokens_out, input.tokensOut),
         input.responseBody?.byteLength ?? 0, summary,
         input.redacted ? 1 : 0, target.id],
      );
      this.db.run(`UPDATE payloads SET response_body=? WHERE exchange_id=?`,
        [input.responseBody, target.id]);
      // The search index is deliberately NOT touched. `beagle search` is
      // outbound-only — a hit means the string was SENT — and a stitchable
      // partial is response-only by construction (the daemon's guard requires
      // no messages and zero request bytes), so it carries nothing outbound to
      // index. There is no parameter for it on purpose: with one, a future
      // caller appending the answer would silently make model-generated text
      // report as sent, the exact hole the wire path's buildSearchText closes.
      return { id: target.id, changed: true };
    });
  }

  getCall(idOrPrefix: string): CallRecord | null {
    const rows = this.db.all<Record<string, unknown>>(
      `SELECT e.*, p.request_body, p.request_headers, p.response_body,
              p.response_headers, p.sse_raw, p.display_messages
       FROM exchanges e LEFT JOIN payloads p ON p.exchange_id = e.id
       WHERE e.id LIKE ? ESCAPE '\\' LIMIT 2`,
      [escapeLike(idOrPrefix) + "%"],
    );
    if (rows.length !== 1) return null;
    return rowToCall(rows[0]!);
  }

  searchLiteral(term: string): SearchHit[] {
    return this.db.all<SearchHit>(
      `SELECT f.exchange_id AS callId, e.session_id AS sessionId,
              e.ts_request AS tsRequest
       FROM exchanges_fts f JOIN exchanges e ON e.id = f.exchange_id
       WHERE f.content LIKE ? ESCAPE '\\'
       ORDER BY e.ts_request`,
      ["%" + escapeLike(term) + "%"],
    );
  }

  upsertLeakEvent(input: LeakEventInput): { fresh: boolean; eventId: string } {
    return this.inTx(() => this.upsertLeakEventInner(input));
  }

  private upsertLeakEventInner(input: LeakEventInput): { fresh: boolean; eventId: string } {
    const existing = this.db.get<{ id: string }>(
      `SELECT id FROM leak_events WHERE fingerprint=? AND destination=? AND session_id=?`,
      [input.fingerprint, input.destination, input.sessionId],
    );
    let eventId: string;
    let fresh: boolean;
    if (existing) {
      eventId = existing.id;
      fresh = false;
      this.db.run(`UPDATE leak_events SET occurrences = occurrences + 1, last_ts=? WHERE id=?`,
        [input.ts, eventId]);
    } else {
      eventId = ulid(input.ts);
      fresh = true;
      this.db.run(
        `INSERT INTO leak_events (id, fingerprint, session_id, detector, secret_type,
           severity, confidence_tier, destination, occurrences, first_ts, last_ts, first_exchange)
         VALUES (?,?,?,?,?,?,?,?,1,?,?,?)`,
        [eventId, input.fingerprint, input.sessionId, input.detector, input.secretType,
         input.severity, input.confidenceTier, input.destination, input.ts, input.ts, input.callId],
      );
    }
    this.db.run(
      `INSERT OR IGNORE INTO leak_occurrences (event_id, exchange_id, span_start, span_end) VALUES (?,?,?,?)`,
      [eventId, input.callId, input.spanStart ?? null, input.spanEnd ?? null],
    );
    return { fresh, eventId };
  }

  /** Read-only DB handle for non-core query faces (viewer feed, CLI).
   *  Keeps display projections out of the security-path LOC budget. */
  queryAll<T = Record<string, unknown>>(sql: string, params: unknown[] = []): T[] {
    return this.db.all<T>(sql, params);
  }

  countCalls(): number { return this.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM exchanges`)?.n ?? 0; }
  countLeakEvents(): number { return this.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM leak_events`)?.n ?? 0; }

  updateCallScanState(id: string, state: "ok" | "incomplete"): void {
    this.db.run(`UPDATE exchanges SET scan_state=? WHERE id=?`, [state, id]);
  }

  fingerprintKnown(fingerprint: string): boolean {
    return this.db.get(`SELECT 1 FROM leak_events WHERE fingerprint = ? LIMIT 1`, [fingerprint]) !== null;
  }

  insertSession(s: {
    id: string; agent?: string; provider?: string; firstTs: number; lastTs: number;
    convId?: string; headHash?: string; fuzzyHash?: string; runId?: string;
  }): void {
    this.db.run(
      `INSERT INTO sessions (id, agent, provider, first_ts, last_ts, conv_id, head_hash, fuzzy_hash, run_id)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [s.id, s.agent ?? null, s.provider ?? null, s.firstTs, s.lastTs,
       s.convId ?? null, s.headHash ?? null, s.fuzzyHash ?? null, s.runId ?? null],
    );
  }

  // Absent fields keep their stored value (callers only ever set, never null).
  updateSession(id: string, f: { lastTs?: number; convId?: string; headHash?: string }): void {
    this.db.run(
      `UPDATE sessions SET last_ts=COALESCE(?,last_ts), conv_id=COALESCE(?,conv_id),
         head_hash=COALESCE(?,head_hash) WHERE id=?`,
      [f.lastTs ?? null, f.convId ?? null, f.headHash ?? null, id],
    );
  }

  // Session lookups are always scoped by agent+provider: sessions are
  // per-agent (R6 folds the agent dimension into session identity), and an
  // unscoped hash/conv-id match would let purge-by-session reach across
  // agents.
  findSessionBy(
    column: "conv_id" | "head_hash" | "fuzzy_hash" | "run_id",
    values: string[],
    scope: { agent: string; provider: string },
  ): { id: string; matched: string } | null {
    if (values.length === 0) return null;
    const qs = values.map(() => "?").join(",");
    const row = this.db.get<{ id: string; matched: string }>(
      `SELECT id, ${column} AS matched FROM sessions
       WHERE ${column} IN (${qs}) AND agent=? AND provider=?
       ORDER BY last_ts DESC LIMIT 1`,
      [...values, scope.agent, scope.provider],
    );
    return row ?? null;
  }

  findRecentSession(agent: string, provider: string, sinceTs: number): string | null {
    return (
      this.db.get<{ id: string }>(
        `SELECT id FROM sessions WHERE agent=? AND provider=? AND run_id IS NULL AND last_ts>=?
         ORDER BY last_ts DESC LIMIT 1`,
        [agent, provider, sinceTs],
      )?.id ?? null
    );
  }

  insertRun(run: {
    id: string; agent: string | null; provider: string | null; upstream: string;
    authLocation: string | null; extraHeaders: Array<[string, string]> | null; createdTs: number;
  }): void {
    this.db.run(
      `INSERT OR REPLACE INTO runs (id, agent, provider, upstream, auth_location, extra_headers, created_ts)
       VALUES (?,?,?,?,?,?,?)`,
      [run.id, run.agent, run.provider, run.upstream, run.authLocation,
       run.extraHeaders ? JSON.stringify(run.extraHeaders) : null, run.createdTs],
    );
  }

  listRuns(): Array<{
    id: string; agent: string; provider: string; upstream: string;
    authLocation?: string; extraHeaders?: Array<[string, string]>;
  }> {
    return this.db.all<Record<string, unknown>>(`SELECT * FROM runs`).map((r) => ({
      id: r.id as string,
      agent: r.agent as string,
      provider: r.provider as string,
      upstream: r.upstream as string,
      authLocation: (r.auth_location as string) ?? undefined,
      extraHeaders: r.extra_headers ? JSON.parse(r.extra_headers as string) : undefined,
    }));
  }

  sweep(policy: SweepPolicy): void {
    const now = Date.now();
    if (Number.isFinite(policy.payloadWindowMs)) {
      this.deleteCallsWhere("ts_request < ?", [now - policy.payloadWindowMs]);
    }
    if (Number.isFinite(policy.sizeCapBytes)) {
      // Oldest-first eviction until stored bytes fit the cap. A row costs its
      // payload blobs PLUS its search index: exchanges_fts keeps a second copy
      // of the row's outbound text and the trigram postings over it, which for
      // a Mode B row (search text ~= request body) outweighs the blobs. The
      // index cost is read from the stamped search_bytes rather than joined
      // from fts5 — see the schema note on why that join is O(n²).
      // The stored transcript counts too. It is a near-full second copy of the
      // row's readable text — for Mode B always, and for a wire row whenever
      // derived redaction wrote one — so leaving it out under-bills exactly the
      // rows that carry a secret, the same gap search_bytes was added to close.
      // CAST to BLOB first: length() on TEXT counts CHARACTERS, so a transcript
      // in CJK or one carrying emoji would bill about a third of its real
      // footprint while every BLOB term beside it bills bytes. Same reason
      // backfillSearchBytes casts, and it keeps the unit identical to
      // search_bytes (Buffer.byteLength, utf8).
      const rows = this.db.all<{ id: string; sz: number }>(
        `SELECT e.id AS id,
                COALESCE(length(p.request_body),0) + COALESCE(length(p.response_body),0)
                + COALESCE(length(p.sse_raw),0)
                + COALESCE(length(CAST(p.display_messages AS BLOB)),0)
                + COALESCE(e.search_bytes,0) * ? AS sz
         FROM exchanges e LEFT JOIN payloads p ON p.exchange_id = e.id
         ORDER BY e.ts_request DESC`,
        [FTS_DISK_FACTOR],
      );
      let acc = 0;
      const evict: string[] = [];
      for (const r of rows) {
        acc += r.sz;
        if (acc > policy.sizeCapBytes) evict.push(r.id);
      }
      // Batched: an over-cap store can evict far more than one statement can
      // carry (see EVICT_BATCH). That is not a corner case here — a multi-GB
      // db of small calls is exactly what this accounting fix targets, and its
      // first sweep drops everything above the cap at once. Each batch is its
      // own transaction, so a sweep interrupted midway just resumes next pass.
      for (let i = 0; i < evict.length; i += EVICT_BATCH) {
        const batch = evict.slice(i, i + EVICT_BATCH);
        this.deleteCallsWhere(`id IN (${batch.map(() => "?").join(",")})`, batch);
      }
    }
    if (Number.isFinite(policy.eventWindowMs)) {
      this.db.run(`DELETE FROM leak_events WHERE last_ts < ?`, [now - policy.eventWindowMs]);
    }
    if (Number.isFinite(policy.payloadWindowMs)) {
      // sessions and runs follow the payload window (design §4)
      const cutoff = now - policy.payloadWindowMs;
      this.db.run(`DELETE FROM sessions WHERE last_ts < ?`, [cutoff]);
      this.db.run(`DELETE FROM runs WHERE created_ts < ?`, [cutoff]);
    }
    this.reclaim();
  }

  // Hand the space a delete freed back to the OS. Order matters: fts5 keeps a
  // deleted row's trigram postings as tombstones until its segments are
  // merged, so straight after an eviction the index can still hold several
  // times the live content in dead postings — vacuuming first would find
  // almost nothing to release. Merge, then release.
  private reclaim(): void {
    this.db.run(`INSERT INTO exchanges_fts(exchanges_fts, rank) VALUES('merge', ?)`,
      [-FTS_MERGE_PAGES]);
    this.db.exec("PRAGMA incremental_vacuum");
  }

  purge(spec: PurgeSpec): void {
    if (spec.kind === "all") {
      this.deleteCallsWhere("1=1", []);
      this.db.run(`DELETE FROM leak_events`);
    } else if (spec.kind === "session") {
      this.deleteCallsWhere("session_id = ?", [spec.sessionId]);
      this.db.run(`DELETE FROM leak_events WHERE session_id = ?`, [spec.sessionId]);
    } else {
      this.deleteCallsWhere("ts_request < ?", [spec.ts]);
    }
    this.reclaim();
  }

  panicPurge(): void {
    this.purge({ kind: "all" });
    this.db.run(`DELETE FROM sessions`);
    this.db.run(`DELETE FROM runs`);
    this.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    this.db.exec("VACUUM");
  }

  close(): void {
    this.db.close();
  }

  private deleteCallsWhere(where: string, params: unknown[]): void {
    this.inTx(() => this.deleteCallsWhereInner(where, params));
  }

  private deleteCallsWhereInner(where: string, params: unknown[]): void {
    // Manual leak-table cleanup (no FKs to exchanges — see schema note).
    this.db.run(
      `UPDATE leak_events SET first_exchange = NULL
       WHERE first_exchange IN (SELECT id FROM exchanges WHERE ${where})`,
      params,
    );
    this.db.run(
      `DELETE FROM leak_occurrences WHERE exchange_id IN (SELECT id FROM exchanges WHERE ${where})`,
      params,
    );
    this.db.run(
      `DELETE FROM exchanges_fts WHERE exchange_id IN (SELECT id FROM exchanges WHERE ${where})`,
      params,
    );
    this.db.run(`DELETE FROM exchanges WHERE ${where}`, params);
  }
}

function pragmaNumber(db: Db, name: string): number {
  const row = db.get<Record<string, number>>(`PRAGMA ${name}`);
  return row ? Number(Object.values(row)[0]) : 0;
}

function versionError(found: number): StoreVersionError {
  return new StoreVersionError(
    `store is schema v${found}, this beagle speaks v${SCHEMA_VERSION} — upgrade beagle or restart the daemon`,
  );
}

// Forward, in-place migrations (data-preserving; additive columns only). Each
// ALTER is idempotent — a dup-column error on a partially-migrated store means
// it's already applied.
function migrate(db: Db, from: number): void {
  const add = (t: string, c: string) => {
    try { db.exec(`ALTER TABLE ${t} ADD COLUMN ${c}`); } catch { /* already applied */ }
  };
  if (from < 2) {
    add("leak_occurrences", "span_start INTEGER");
    add("leak_occurrences", "span_end INTEGER");
    add("exchanges", "redacted INTEGER");
  }
  if (from < 3) add("payloads", "display_messages TEXT");
  if (from < 4) add("exchanges", "one_shot INTEGER");
  if (from < 5) add("exchanges", "prompt_key TEXT");
  if (from < 6) {
    add("exchanges", "search_bytes INTEGER");
    backfillSearchBytes(db);
  }
}

// v6: stamp search_bytes on rows captured before the column existed. Without
// it they'd bill 0 for their search index until they aged out — and a store
// big enough to have hit the bug is exactly the one that needs the cap
// enforced now. One sequential pass over the index into an indexed temp table,
// then a join: correlating exchanges_fts per row would be O(n²) (exchange_id
// is UNINDEXED). Best-effort — on failure the column stays NULL, which reads
// as 0: the pre-v6 accounting, not a broken store.
function backfillSearchBytes(db: Db): void {
  try {
    db.exec("BEGIN");
    db.exec(`CREATE TEMP TABLE sb AS
               SELECT exchange_id AS id, length(CAST(content AS BLOB)) AS n FROM exchanges_fts`);
    db.exec(`CREATE INDEX temp.ix_sb ON sb(id)`);
    db.exec(`UPDATE exchanges SET search_bytes = (SELECT n FROM sb WHERE sb.id = exchanges.id)`);
    db.exec("COMMIT");
  } catch {
    try { db.exec("ROLLBACK"); } catch { /* no open tx */ }
  }
  try { db.exec(`DROP TABLE IF EXISTS temp.sb`); } catch { /* never created */ }
}

// Token counts stay NULL when neither side reported one — 0 would read as
// "measured zero tokens" in the viewer rather than "not reported".
function addNullable(a: number | null, b: number | undefined): number | null {
  if (a === null && b === undefined) return null;
  return (a ?? 0) + (b ?? 0);
}

function escapeLike(s: string): string {
  return s.replace(/[\\%_]/g, (c) => "\\" + c);
}

function rowToCall(r: Record<string, unknown>): CallRecord {
  return {
    id: r.id as string,
    sessionId: r.session_id as string,
    runId: r.run_id as string,
    source: r.source as "wire" | "otel",
    agent: (r.agent as string) ?? undefined,
    provider: (r.provider as string) ?? undefined,
    model: (r.model as string) ?? undefined,
    endpoint: (r.endpoint as string) ?? undefined,
    tsRequest: r.ts_request as number,
    tsResponse: (r.ts_response as number) ?? undefined,
    status: (r.status as number) ?? undefined,
    tokensIn: (r.tokens_in as number) ?? undefined,
    tokensOut: (r.tokens_out as number) ?? undefined,
    bytesReq: (r.bytes_req as number) ?? undefined,
    bytesResp: (r.bytes_resp as number) ?? undefined,
    summary: (r.summary as string) ?? undefined,
    scanState: r.scan_state as "ok" | "incomplete",
    captureState: r.capture_state as "ok" | "truncated",
    sessionTier: r.session_tier as string,
    redacted: Boolean(r.redacted),
    oneShot: Boolean(r.one_shot),
    promptKey: (r.prompt_key as string) ?? undefined,
    requestBody: (r.request_body as Uint8Array) ?? null,
    requestHeaders: r.request_headers ? JSON.parse(r.request_headers as string) : null,
    responseBody: (r.response_body as Uint8Array) ?? null,
    responseHeaders: r.response_headers ? JSON.parse(r.response_headers as string) : null,
    sseRaw: (r.sse_raw as Uint8Array) ?? null,
    displayMessages: r.display_messages ? JSON.parse(r.display_messages as string) : null,
    searchText: "",
  };
}
