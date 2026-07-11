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
  const db = new Database(path, {
    readonly: opts.readonly ?? false,
    create: !opts.readonly,
  });
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
