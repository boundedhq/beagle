// Schema from design §4. Version stamped in PRAGMA user_version; every
// reader checks it before querying (two binaries share this file).
export const SCHEMA_VERSION = 4; // v4: exchanges.one_shot (stateless utility turns)

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS exchanges (
  id            TEXT PRIMARY KEY,
  session_id    TEXT NOT NULL,
  run_id        TEXT NOT NULL,
  source        TEXT NOT NULL,
  agent         TEXT, provider TEXT, model TEXT, endpoint TEXT,
  ts_request    INTEGER NOT NULL,
  ts_response   INTEGER,
  status        INTEGER,
  tokens_in     INTEGER, tokens_out INTEGER,
  bytes_req     INTEGER, bytes_resp INTEGER,
  summary       TEXT,
  scan_state    TEXT NOT NULL DEFAULT 'ok',
  capture_state TEXT NOT NULL DEFAULT 'ok',
  session_tier  TEXT NOT NULL,
  redacted      INTEGER, -- 1 when redact-on-capture rewrote the body (viewer highlight)
  one_shot      INTEGER -- 1: stateless utility turn (e.g. title-gen), no conversation identity
);
CREATE INDEX IF NOT EXISTS ix_exch_session ON exchanges(session_id);
CREATE INDEX IF NOT EXISTS ix_exch_ts ON exchanges(ts_request);

CREATE TABLE IF NOT EXISTS payloads (
  exchange_id   TEXT PRIMARY KEY REFERENCES exchanges(id) ON DELETE CASCADE,
  request_body  BLOB,
  request_headers  TEXT,
  response_body BLOB,
  response_headers TEXT,
  -- Mode B only: the self-report's pre-flattened display messages (JSON of
  -- [{role,content}]); wire rows leave it NULL, redact-on-capture scrubs it.
  -- Before sse_raw on purpose: a line comment before the LAST column breaks DROP.
  display_messages TEXT,
  sse_raw       BLOB
);

CREATE TABLE IF NOT EXISTS leak_events (
  id              TEXT PRIMARY KEY,
  fingerprint     TEXT NOT NULL,
  session_id      TEXT NOT NULL,
  detector        TEXT NOT NULL,
  secret_type     TEXT NOT NULL,
  severity        TEXT NOT NULL,
  confidence_tier TEXT NOT NULL,
  destination     TEXT NOT NULL,
  occurrences     INTEGER NOT NULL DEFAULT 1,
  first_ts        INTEGER NOT NULL, last_ts INTEGER NOT NULL,
  -- No FK to exchanges: alerts fire mid-stream (R6), before the exchange row
  -- is written post-response. The sweeper nulls/cleans these manually.
  first_exchange  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_leak_fp ON leak_events(fingerprint, destination, session_id);

CREATE TABLE IF NOT EXISTS leak_occurrences (
  event_id      TEXT REFERENCES leak_events(id) ON DELETE CASCADE,
  exchange_id   TEXT, -- no FK: may be linked before the exchange row lands
  span_start    INTEGER, span_end INTEGER, -- secret's char span (R7 highlight)
  PRIMARY KEY (event_id, exchange_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id              TEXT PRIMARY KEY,
  agent TEXT, provider TEXT,
  first_ts INTEGER, last_ts INTEGER,
  conv_id         TEXT,
  head_hash       TEXT,
  fuzzy_hash      TEXT,   -- hash(system prompt + first user msg): compaction link
  run_id          TEXT    -- tier-3 floor: session keyed by process run
);
CREATE INDEX IF NOT EXISTS ix_sess_conv ON sessions(conv_id);
CREATE INDEX IF NOT EXISTS ix_sess_head ON sessions(head_hash);
CREATE INDEX IF NOT EXISTS ix_sess_fuzzy ON sessions(fuzzy_hash);
CREATE INDEX IF NOT EXISTS ix_sess_run ON sessions(run_id);

CREATE TABLE IF NOT EXISTS runs (
  id            TEXT PRIMARY KEY,
  agent TEXT, provider TEXT,
  upstream      TEXT NOT NULL,
  auth_location TEXT,
  extra_headers TEXT,
  created_ts    INTEGER NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS exchanges_fts USING fts5(
  content, exchange_id UNINDEXED, tokenize='trigram'
);
`;
