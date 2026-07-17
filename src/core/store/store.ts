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
  requestBody: Uint8Array | null;
  requestHeaders: Array<[string, string]> | null;
  responseBody: Uint8Array | null;
  responseHeaders: Array<[string, string]> | null;
  sseRaw: Uint8Array | null;
  /** Mode B only: pre-flattened display messages (the self-report's structure). */
  displayMessages?: Array<{ role: string; content: string }> | null;
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

export class Store {
  private constructor(private db: Db) {}

  static open(stateDir: string): Store {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    chmodSync(stateDir, 0o700);
    const path = join(stateDir, DB_FILE);
    const db = openDb(path);
    chmodSync(path, 0o600);
    db.exec("PRAGMA journal_mode=WAL");
    db.exec("PRAGMA secure_delete=ON");
    db.exec("PRAGMA auto_vacuum=INCREMENTAL");
    db.exec("PRAGMA foreign_keys=ON");
    const v = pragmaNumber(db, "user_version");
    if (v > SCHEMA_VERSION) throw versionError(v); // a newer store: upgrade beagle
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
           bytes_req, bytes_resp, summary, scan_state, capture_state, session_tier, redacted, one_shot)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [call.id, call.sessionId, call.runId, call.source, call.agent ?? null, call.provider ?? null,
         call.model ?? null, call.endpoint ?? null, call.tsRequest, call.tsResponse ?? null,
         call.status ?? null, call.tokensIn ?? null, call.tokensOut ?? null, call.bytesReq ?? null,
         call.bytesResp ?? null, call.summary ?? null, call.scanState, call.captureState, call.sessionTier,
         call.redacted ? 1 : null, call.oneShot ? 1 : null],
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
      // Oldest-first eviction until payload bytes fit the cap.
      const rows = this.db.all<{ id: string; sz: number; ts: number }>(
        `SELECT e.id AS id, e.ts_request AS ts,
                COALESCE(length(p.request_body),0) + COALESCE(length(p.response_body),0)
                + COALESCE(length(p.sse_raw),0) AS sz
         FROM exchanges e LEFT JOIN payloads p ON p.exchange_id = e.id
         ORDER BY e.ts_request DESC`,
      );
      let acc = 0;
      const evict: string[] = [];
      for (const r of rows) {
        acc += r.sz;
        if (acc > policy.sizeCapBytes) evict.push(r.id);
      }
      if (evict.length > 0) {
        const qs = evict.map(() => "?").join(",");
        this.deleteCallsWhere(`id IN (${qs})`, evict);
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
    this.db.exec("PRAGMA incremental_vacuum");
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
    requestBody: (r.request_body as Uint8Array) ?? null,
    requestHeaders: r.request_headers ? JSON.parse(r.request_headers as string) : null,
    responseBody: (r.response_body as Uint8Array) ?? null,
    responseHeaders: r.response_headers ? JSON.parse(r.response_headers as string) : null,
    sseRaw: (r.sse_raw as Uint8Array) ?? null,
    displayMessages: r.display_messages ? JSON.parse(r.display_messages as string) : null,
    searchText: "",
  };
}
