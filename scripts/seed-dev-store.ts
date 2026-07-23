// Populate a scratch store with synthetic capture data, so you can work on
// the viewer/dashboard without running a real agent session (which needs an
// installed, authenticated agent and makes a live provider call — and a fresh
// session has no leaks to render). Everything here is fabricated; the one
// "secret" is a masked synthetic AWS secret access key, not a real credential.
//
//   bun scripts/seed-dev-store.ts [dir]     # default: /tmp/beagle-dev-store
//   BEAGLE_STATE_DIR=<dir> bun src/cli/main.ts ui   # then view it
//
// Refuses to write into a directory that already holds a beagle.db — it never
// deletes anything, so it can't clobber your real store.
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { Store, type CallRecord } from "../src/core/store/store";
import { ulid } from "../src/core/store/ulid";

const dir = process.argv[2] ?? process.env.BEAGLE_STATE_DIR ?? "/tmp/beagle-dev-store";
if (existsSync(join(dir, "beagle.db"))) {
  console.error(
    `refusing to seed ${dir} — it already has a beagle.db.\n` +
      `Pick an empty directory (or delete that one yourself first).`,
  );
  process.exit(1);
}
mkdirSync(dir, { recursive: true });
const store = Store.open(dir);

const enc = (s: string) => new TextEncoder().encode(s);
const base = Date.now() - 5 * 60_000; // five minutes ago
const at = (min: number) => base + min * 60_000;

function seedCall(c: Partial<CallRecord> & Pick<CallRecord, "id" | "sessionId" | "tsRequest">): void {
  const defaults: CallRecord = {
    id: c.id,
    sessionId: c.sessionId,
    tsRequest: c.tsRequest,
    runId: "dev",
    source: "wire",
    agent: "opencode",
    provider: "openai",
    model: "gpt-5.1",
    endpoint: "/v1/chat/completions",
    tsResponse: c.tsRequest + 1800,
    status: 200,
    tokensIn: 900,
    tokensOut: 120,
    scanState: "ok",
    captureState: "ok",
    sessionTier: "prefix",
    requestHeaders: [["content-type", "application/json"]],
    responseHeaders: [["content-type", "application/json"]],
    requestBody: null,
    responseBody: null,
    sseRaw: null,
    bytesReq: 0,
    bytesResp: 0,
    searchText: "",
  };
  // c overrides defaults; the merge is a complete CallRecord at runtime (the
  // cast just discards the `undefined` that Partial adds to optional keys).
  store.insertCall({ ...defaults, ...c } as CallRecord);
}

const SYSTEM = "You are a coding agent. Read files before editing; keep diffs minimal.";
const body = (messages: unknown[]) => JSON.stringify({ model: "gpt-5.1", system: SYSTEM, messages });
const reply = (text: string) => JSON.stringify({ choices: [{ message: { role: "assistant", content: text } }] });

// Session A — a normal wire session: an ask, a tool call, then a leak turn.
const a1 = body([{ role: "user", content: "The retry test in tests/upload.test.ts is flaky on CI — fix it." }]);
seedCall({ id: ulid(at(0)), sessionId: "devA", tsRequest: at(0), requestBody: enc(a1),
  responseBody: enc(reply("Let me read the test first.")),
  summary: '"The retry test in tests/upload.test.ts…" → read the test', searchText: a1 });

// The leak turn. redact-on-capture (the default) masks the secret before it is
// written, so the stored body shows the placeholder — highlighted at its span.
const MASK = "[REDACTED:aws-secret-access-key:7f3a91d2]";
const a2 = body([{ role: "user", content: `Deploy to the prod bucket — the AWS key is ${MASK}.` }]);
const leakId = ulid(at(2));
seedCall({ id: leakId, sessionId: "devA", tsRequest: at(2), redacted: true, requestBody: enc(a2),
  responseBody: enc(reply("I won't use a pasted access key — rotate it and use a short-lived credential.")),
  summary: '"Deploy to the prod bucket — the AWS key…" → I won\'t use a pasted access key…', searchText: a2 });
const span = a2.indexOf(MASK);
store.upsertLeakEvent({ fingerprint: "dev-aws", sessionId: "devA", detector: "aws-secret-access-key",
  secretType: "aws-secret-access-key", severity: "high", confidenceTier: "structured",
  destination: "openai", callId: leakId, ts: at(2), spanStart: span, spanEnd: span + MASK.length });

// Session B — a telemetry-captured (self-reported) turn, so the `self-reported`
// badge and the `otel` provenance path render too.
const b = JSON.stringify({ messages: [{ role: "user", content: "Summarize docs/incident-42.md." }] });
seedCall({ id: ulid(at(4)), sessionId: "devB", tsRequest: at(4), source: "otel", agent: "claude",
  provider: "anthropic", model: "claude-opus-4-8", endpoint: "otlp", sessionTier: "run",
  requestHeaders: null, responseHeaders: null, requestBody: enc(b),
  responseBody: enc(JSON.stringify({ content: "The cache tier lost quorum; add a quorum alarm." })),
  summary: '"Summarize docs/incident-42.md." → The cache tier lost quorum…', searchText: b });

store.close();
console.log(
  `seeded ${dir} — 3 calls, 2 sessions, 1 (masked) leak.\n` +
    `view it:  BEAGLE_STATE_DIR=${dir} bun src/cli/main.ts ui`,
);
