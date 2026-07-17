// The bun:sqlite adapter — the only place this import is allowed (runtime
// hedge, design §2). Core consumes the Db interface, never bun:sqlite.
import { Database } from "bun:sqlite";

export interface Db {
  exec(sql: string): void;
  run(sql: string, params?: unknown[]): { changes: number };
  get<T = Record<string, unknown>>(sql: string, params?: unknown[]): T | null;
  all<T = Record<string, unknown>>(sql: string, params?: unknown[]): T[];
  close(): void;
}

export function openDb(path: string, opts: { readonly?: boolean } = {}): Db {
  // "Read-only" is enforced with PRAGMA query_only, not the OS-level readonly
  // flag: a WAL database whose -shm/-wal sidecars are gone (the daemon's clean
  // exit removes them) cannot start a read transaction on a readonly handle —
  // SQLite needs to recreate the sidecars, and bun:sqlite surfaces that as
  // SQLITE_CANTOPEN. That broke every daemon-down CLI read (R12 promises
  // reads work daemon-down). A read-write handle with query_only=ON can
  // recreate the sidecars but rejects every write at the SQL layer.
  const db = new Database(path, {
    readwrite: true,
    create: !opts.readonly, // readers must never create a missing store
  });
  if (opts.readonly) db.exec("PRAGMA query_only=ON");
  return {
    exec: (sql) => db.exec(sql),
    run: (sql, params = []) => {
      const r = db.query(sql).run(...(params as never[]));
      return { changes: r.changes };
    },
    get: (sql, params = []) => (db.query(sql).get(...(params as never[])) as never) ?? null,
    all: (sql, params = []) => db.query(sql).all(...(params as never[])) as never[],
    close: () => db.close(),
  };
}
