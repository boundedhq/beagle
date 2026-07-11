// Store (design §4, §6.6). Single writer (the daemon); CLI/viewer open
// read-only. WAL + secure_delete so purged secrets don't linger; retention
// sweeper and purge share one code path so R11 semantics can't drift.
import { chmodSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { openDb, type Db } from "../../adapters/sqlite";
import { SCHEMA_SQL, SCHEMA_VERSION } from "./schema";
import { ulid } from "./ulid";

export { SCHEMA_VERSION };

export class StoreVersionError extends Error {}

export interface ExchangeRecord {
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
  requestBody: Uint8Array | null;
  requestHeaders: Array<[string, string]> | null;
  responseBody: Uint8Array | null;
  responseHeaders: Array<[string, string]> | null;
  sseRaw: Uint8Array | null;
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
  exchangeId: string;
  ts: number;
}

export interface LeakEvent extends Omit<LeakEventInput, "exchangeId" | "ts"> {
  id: string;
  occurrences: number;
  firstTs: number;
  lastTs: number;
  firstExchange: string | null;
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
  exchangeId: string;
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
    if (v !== 0 && v !== SCHEMA_VERSION) throw versionError(v);
    db.exec(SCHEMA_SQL);
    db.exec(`PRAGMA user_version=${SCHEMA_VERSION}`);
    return new Store(db);
  }

  static openReadOnly(stateDir: string): Store {
    const db = openDb(join(stateDir, DB_FILE), { readonly: true });
    db.exec("PRAGMA foreign_keys=ON");
    const v = pragmaNumber(db, "user_version");
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

  insertExchange(ex: ExchangeRecord): void {
    this.inTx(() => {
      this.db.run(
        `INSERT INTO exchanges (id, session_id, run_id, source, agent, provider, model,
           endpoint, ts_request, ts_response, status, tokens_in, tokens_out,
           bytes_req, bytes_resp, summary, scan_state, capture_state, session_tier)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [ex.id, ex.sessionId, ex.runId, ex.source, ex.agent ?? null, ex.provider ?? null,
         ex.model ?? null, ex.endpoint ?? null, ex.tsRequest, ex.tsResponse ?? null,
         ex.status ?? null, ex.tokensIn ?? null, ex.tokensOut ?? null, ex.bytesReq ?? null,
         ex.bytesResp ?? null, ex.summary ?? null, ex.scanState, ex.captureState, ex.sessionTier],
      );
      this.db.run(
        `INSERT INTO payloads (exchange_id, request_body, request_headers,
           response_body, response_headers, sse_raw) VALUES (?,?,?,?,?,?)`,
        [ex.id, ex.requestBody, ex.requestHeaders ? JSON.stringify(ex.requestHeaders) : null,
         ex.responseBody, ex.responseHeaders ? JSON.stringify(ex.responseHeaders) : null, ex.sseRaw],
      );
      this.db.run(`INSERT INTO exchanges_fts (content, exchange_id) VALUES (?,?)`,
        [ex.searchText, ex.id]);
    });
  }

  getExchange(idOrPrefix: string): ExchangeRecord | null {
    const rows = this.db.all<Record<string, unknown>>(
      `SELECT e.*, p.request_body, p.request_headers, p.response_body,
              p.response_headers, p.sse_raw
       FROM exchanges e LEFT JOIN payloads p ON p.exchange_id = e.id
       WHERE e.id LIKE ? ESCAPE '\\' LIMIT 2`,
      [escapeLike(idOrPrefix) + "%"],
    );
    if (rows.length !== 1) return null;
    return rowToExchange(rows[0]!);
  }

  searchLiteral(term: string): SearchHit[] {
    return this.db.all<SearchHit>(
      `SELECT f.exchange_id AS exchangeId, e.session_id AS sessionId,
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
         input.severity, input.confidenceTier, input.destination, input.ts, input.ts, input.exchangeId],
      );
    }
    this.db.run(`INSERT OR IGNORE INTO leak_occurrences (event_id, exchange_id) VALUES (?,?)`,
      [eventId, input.exchangeId]);
    return { fresh, eventId };
  }

  listExchanges(limit: number): Array<{
    id: string; sessionId: string; agent?: string; provider?: string; model?: string;
    tsRequest: number; status?: number; tokensIn?: number; tokensOut?: number;
    bytesReq?: number; summary?: string; scanState: string; captureState: string;
    sessionTier: string; source: string; hasLeak: boolean;
  }> {
    return this.db.all<Record<string, unknown>>(
      `SELECT e.id, e.session_id, e.agent, e.provider, e.model, e.ts_request,
              e.status, e.tokens_in, e.tokens_out, e.bytes_req, e.summary,
              e.scan_state, e.capture_state, e.session_tier, e.source,
              EXISTS(SELECT 1 FROM leak_occurrences lo WHERE lo.exchange_id = e.id) AS has_leak
       FROM exchanges e ORDER BY e.ts_request DESC LIMIT ?`,
      [limit],
    ).map((r) => ({
      id: r.id as string,
      sessionId: r.session_id as string,
      agent: (r.agent as string) ?? undefined,
      provider: (r.provider as string) ?? undefined,
      model: (r.model as string) ?? undefined,
      tsRequest: r.ts_request as number,
      status: (r.status as number) ?? undefined,
      tokensIn: (r.tokens_in as number) ?? undefined,
      tokensOut: (r.tokens_out as number) ?? undefined,
      bytesReq: (r.bytes_req as number) ?? undefined,
      summary: (r.summary as string) ?? undefined,
      scanState: r.scan_state as string,
      captureState: r.capture_state as string,
      sessionTier: r.session_tier as string,
      source: r.source as string,
      hasLeak: Boolean(r.has_leak),
    }));
  }

  countExchanges(): number {
    return this.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM exchanges`)?.n ?? 0;
  }

  countLeakEvents(): number {
    return this.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM leak_events`)?.n ?? 0;
  }

  updateExchangeScanState(id: string, state: "ok" | "incomplete"): void {
    this.db.run(`UPDATE exchanges SET scan_state=? WHERE id=?`, [state, id]);
  }

  fingerprintKnown(fingerprint: string): boolean {
    return (
      this.db.get<{ n: number }>(
        `SELECT COUNT(*) AS n FROM leak_events WHERE fingerprint = ?`,
        [fingerprint],
      )?.n ?? 0
    ) > 0;
  }

  listLeakEvents(): LeakEvent[] {
    return this.db.all<Record<string, unknown>>(
      `SELECT id, fingerprint, session_id, detector, secret_type, severity,
              confidence_tier, destination, occurrences, first_ts, last_ts, first_exchange
       FROM leak_events ORDER BY first_ts`,
    ).map((r) => ({
      id: r.id as string,
      fingerprint: r.fingerprint as string,
      sessionId: r.session_id as string,
      detector: r.detector as string,
      secretType: r.secret_type as string,
      severity: r.severity as string,
      confidenceTier: r.confidence_tier as string,
      destination: r.destination as string,
      occurrences: r.occurrences as number,
      firstTs: r.first_ts as number,
      lastTs: r.last_ts as number,
      firstExchange: (r.first_exchange as string) ?? null,
    }));
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

  updateSession(
    id: string,
    fields: { lastTs?: number; convId?: string; headHash?: string },
  ): void {
    if (fields.lastTs !== undefined)
      this.db.run(`UPDATE sessions SET last_ts=? WHERE id=?`, [fields.lastTs, id]);
    if (fields.convId !== undefined)
      this.db.run(`UPDATE sessions SET conv_id=? WHERE id=?`, [fields.convId, id]);
    if (fields.headHash !== undefined)
      this.db.run(`UPDATE sessions SET head_hash=? WHERE id=?`, [fields.headHash, id]);
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
      this.deleteExchangesWhere("ts_request < ?", [now - policy.payloadWindowMs]);
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
        this.deleteExchangesWhere(`id IN (${qs})`, evict);
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
      this.deleteExchangesWhere("1=1", []);
      this.db.run(`DELETE FROM leak_events`);
    } else if (spec.kind === "session") {
      this.deleteExchangesWhere("session_id = ?", [spec.sessionId]);
      this.db.run(`DELETE FROM leak_events WHERE session_id = ?`, [spec.sessionId]);
    } else {
      this.deleteExchangesWhere("ts_request < ?", [spec.ts]);
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

  private deleteExchangesWhere(where: string, params: unknown[]): void {
    this.inTx(() => this.deleteExchangesWhereInner(where, params));
  }

  private deleteExchangesWhereInner(where: string, params: unknown[]): void {
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

function escapeLike(s: string): string {
  return s.replace(/[\\%_]/g, (c) => "\\" + c);
}

function rowToExchange(r: Record<string, unknown>): ExchangeRecord {
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
    requestBody: (r.request_body as Uint8Array) ?? null,
    requestHeaders: r.request_headers ? JSON.parse(r.request_headers as string) : null,
    responseBody: (r.response_body as Uint8Array) ?? null,
    responseHeaders: r.response_headers ? JSON.parse(r.response_headers as string) : null,
    sseRaw: (r.sse_raw as Uint8Array) ?? null,
    searchText: "",
  };
}
