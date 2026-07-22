import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync as mkdirSyncDetect, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdDetect, cmdLeaks, cmdSearch, cmdShow, cmdStatus, cmdUninstall, collapseClaudeSettings, countPossibleLeaksSince, detectLine, interpretAskAnswer, isLoopbackHookEndpoint, otelCallsArrivedSince, parseRunArgs, readCodexApiKey, resolveRunMode, runCallsArrived, watchForFirstCapture, wireCaptureLive } from "../src/cli/commands";
import { AGENT_REQUEST_URL, buildRunEnv, AGENTS } from "../src/cli/agents";
import { Store, type CallRecord } from "../src/core/store/store";
import { ulid } from "../src/core/store/ulid";

function seed(stateDir: string): { callId: string } {
  const store = Store.open(stateDir);
  const callId = ulid();
  const call: CallRecord = {
    id: callId, sessionId: "s1", runId: "r1", source: "wire",
    agent: "claude-code", provider: "anthropic", model: "claude-sonnet-5",
    endpoint: "/v1/messages", tsRequest: Date.now(), tsResponse: Date.now(),
    status: 200, tokensIn: 10, tokensOut: 5, bytesReq: 100, bytesResp: 50,
    summary: "user asked to read files", scanState: "ok", captureState: "ok",
    sessionTier: "prefix",
    requestBody: new TextEncoder().encode('{"messages":[{"role":"user","content":"my password is hunter2"}]}'),
    requestHeaders: [["content-type", "application/json"]],
    responseBody: new TextEncoder().encode('{"content":"ok"}'),
    responseHeaders: [], sseRaw: null,
    searchText: "my password is hunter2 ok",
  };
  store.insertCall(call);
  store.upsertLeakEvent({
    fingerprint: "fp1", sessionId: "s1", detector: "generic-api-key",
    secretType: "generic-api-key", severity: "medium", confidenceTier: "possible",
    destination: "anthropic", callId: callId, ts: Date.now(),
  });
  store.close();
  return { callId };
}

describe("CLI commands (headless loop, R12)", () => {
  let stateDir: string;
  let callId: string;

  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-cli-"));
    callId = seed(stateDir).callId;
  });

  test("search: definitive found-in-N answer", () => {
    const out = cmdSearch(stateDir, "hunter2");
    expect(out).toContain("found in 1 call");
    expect(out).toContain("s1");
  });

  test("search: a miss is bounded, not a categorical 'never sent'", () => {
    const out = cmdSearch(stateDir, "never-sent-credential").toLowerCase();
    expect(out).toContain("no matches");
    // The honest miss names its bound (retention prunes payloads), so it can't
    // be read as proof the string was categorically never sent. Pins the
    // bounded wording: the old "…was never sent through Beagle." carried no
    // bound and would fail here.
    expect(out).toMatch(/still in the store|pruned|retention/);
  });

  test("search: with no argument, reads the term from stdin (keeps secrets out of shell history)", () => {
    // `echo $SECRET | beagle search` / `pbpaste | beagle search` — the term
    // must never have to appear in argv, where it would land in shell
    // history and `ps` output.
    const run = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), "search"], {
      stdin: new TextEncoder().encode("hunter2\n"),
      env: { ...process.env, BEAGLE_STATE_DIR: stateDir },
    });
    expect(run.stdout.toString()).toContain("found in 1 call");
  });

  test("search: stdin longer than 256 bytes is read whole (JWT-sized terms)", () => {
    // Seed a call whose text contains a 300-char run of 'y'. Then search for
    // 301 'y's via stdin: a reader that truncates at 256 bytes would search
    // the shorter prefix and WRONGLY report "found"; a full read gives the
    // honest "no matches". This pins the difference.
    const store = Store.open(stateDir);
    store.insertCall({
      id: ulid(), sessionId: "s9", runId: "r9", source: "wire", agent: "claude-code",
      provider: "anthropic", endpoint: "/v1/messages", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "y".repeat(300),
    });
    store.close();
    const run = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), "search"], {
      stdin: new TextEncoder().encode("y".repeat(301) + "\n"),
      env: { ...process.env, BEAGLE_STATE_DIR: stateDir },
    });
    expect(run.stdout.toString().toLowerCase()).toContain("no matches");
    expect(run.exitCode).toBe(0);
  });

  test("leaks: an empty store says nothing was captured, not that it's clean", () => {
    const empty = mkdtempSync(join(tmpdir(), "beagle-cli-empty-"));
    const out = cmdLeaks(empty).toLowerCase();
    // No store = nothing captured or scanned yet. Must not read as a clean
    // scan ("no leaks recorded."), which would imply Beagle looked and found
    // nothing. Pins the "nothing captured yet" framing.
    expect(out).toContain("no captured traffic");
    expect(out).not.toContain("no leaks recorded");
  });

  test("leaks: a scanned-clean store scopes the negative to detection + capture", () => {
    const clean = mkdtempSync(join(tmpdir(), "beagle-cli-clean-"));
    const store = Store.open(clean);
    // A captured call with no leak event: scanned, nothing detected.
    store.insertCall({
      id: ulid(), sessionId: "s2", runId: "r2", source: "wire",
      agent: "claude-code", provider: "anthropic", endpoint: "/v1/messages",
      tsRequest: Date.now(), scanState: "ok", captureState: "ok",
      sessionTier: "run", requestBody: null, requestHeaders: null,
      responseBody: null, responseHeaders: null, sseRaw: null,
      searchText: "nothing secret here",
    });
    store.close();
    const out = cmdLeaks(clean).toLowerCase();
    // Must not flatly claim "no leaks" (reads as "no secrets present"): the
    // honest negative is scoped to what the detector found in the captured
    // surface. Pins that scoping.
    expect(out).toContain("no detected leaks");
    expect(out).toContain("captured");
  });

  test("leaks: groups by session with a headline and plain-English names", () => {
    const out = cmdLeaks(stateDir);
    expect(out).toContain("API key");             // plain name for humans…
    expect(out).not.toContain("generic-api-key"); // …not the detector tag
    expect(out).toContain("(possible)");          // confidence tier survives
    expect(out).toContain("anthropic");
    expect(out).toContain("session s1");          // grouped by session, full id
    expect(out).toContain("claude-code");         // agent attribution
    expect(out).toContain("user asked to read files"); // the session's title
    expect(out).toContain("beagle ui --session"); // the next step is spelled out
    expect(out).toContain(`call ${callId}`); // FULL call id — 8-char ULID prefixes collide
  });

  test("leaks: unwraps Claude Code's {\"title\":…} opening summary", () => {
    const store = Store.open(stateDir);
    const id = ulid();
    store.insertCall({
      id, sessionId: "s2", runId: "r2", source: "wire", agent: "claude",
      provider: "anthropic", endpoint: "/v1/messages", tsRequest: Date.now(),
      summary: '{"title": "Fix login bug"}', scanState: "ok", captureState: "ok",
      sessionTier: "prefix", requestBody: null, requestHeaders: null,
      responseBody: null, responseHeaders: null, sseRaw: null, searchText: "",
    });
    store.upsertLeakEvent({
      fingerprint: "fp2", sessionId: "s2", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "anthropic", callId: id, ts: Date.now(),
    });
    store.close();
    const out = cmdLeaks(stateDir);
    expect(out).toContain("Fix login bug — claude · session s2");
    expect(out).not.toContain('{"title"');
    expect(out).toContain("AWS access key"); // structured tier: no "(possible)" marker
  });

  test("leaks: the headline cap lands past a redaction placeholder, never through it", () => {
    // The leak log is where naming the secret TYPE matters most, and its 64-char
    // headline cap is tighter than any summary cap — so a placeholder straddling
    // it is ordinary, not exotic. A bare slice left `[REDACTED:aws-access-k…`:
    // unreadable as a mask, and silent about which secret it stands for.
    const store = Store.open(stateDir);
    const id = ulid();
    const placeholder = "[REDACTED:aws-access-key-id:6cc699]";
    store.insertCall({
      id, sessionId: "s3", runId: "r3", source: "wire", agent: "claude",
      provider: "anthropic", endpoint: "/v1/messages", tsRequest: Date.now(),
      summary: `${"x".repeat(50)}${placeholder} and a tail past the cap`,
      scanState: "ok", captureState: "ok", sessionTier: "prefix",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "",
    });
    store.upsertLeakEvent({
      fingerprint: "fp3", sessionId: "s3", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "anthropic", callId: id, ts: Date.now(),
    });
    store.close();
    const out = cmdLeaks(stateDir);
    expect(out).toContain(`${placeholder}…`); // whole, then the honest ellipsis
    expect(out).not.toMatch(/\[REDACTED:[^\]\n]*…/); // no bisected stump anywhere
  });

  test("show: speaks the dashboard's language and drops internals", () => {
    const out = cmdShow(stateDir, callId.slice(0, 8));
    expect(out).toContain("claude-sonnet-5");           // model
    expect(out).toContain("user asked to read files");  // summary
    expect(out).toContain("✓ observed");                // provenance, dashboard wording
    expect(out).toContain("grouped by matching message history"); // tier in plain words
    expect(out).toContain("session s1");                // full session id (deep-linkable)
    expect(out).toContain("my password is hunter2");    // the actual message sent
    expect(out).toContain("--raw for exact bytes");     // escape-hatch footer
    expect(out).not.toContain("run r1");                // internals the user can't use…
    expect(out).not.toContain("keyed by");              // …and jargon are gone
    expect(out).not.toContain("status 200");            // errors only when errors
  });

  test("show: flags the leak with a plain-English name and destination", () => {
    const store = Store.open(stateDir);
    const id = ulid();
    const body = '{"messages":[{"role":"user","content":"key is AKIAZQ3DRSTUVWXY2345 ok"}]}';
    const start = body.indexOf("AKIAZQ3DRSTUVWXY2345");
    store.insertCall({
      id, sessionId: "sL", runId: "rL", source: "wire", agent: "claude",
      provider: "anthropic", model: "claude-sonnet-5", endpoint: "/v1/messages",
      tsRequest: Date.now(), status: 200, scanState: "ok", captureState: "ok",
      sessionTier: "prefix", requestBody: new TextEncoder().encode(body),
      requestHeaders: null, responseBody: new TextEncoder().encode('{"content":"ok"}'),
      responseHeaders: null, sseRaw: null, searchText: body,
    });
    store.upsertLeakEvent({
      fingerprint: "fpL", sessionId: "sL", detector: "aws-access-key-id",
      secretType: "aws-access-key-id", severity: "high", confidenceTier: "structured",
      destination: "anthropic", callId: id, ts: Date.now(),
      spanStart: start, spanEnd: start + "AKIAZQ3DRSTUVWXY2345".length,
    });
    store.close();
    // Full id, not a prefix: this second call shares the seed's ULID timestamp
    // prefix (both minted in the same ms), so an 8-char prefix is ambiguous.
    const out = cmdShow(stateDir, id);
    expect(out).toContain("🔴");
    expect(out).toContain("secret sent to anthropic");
    expect(out).toContain("AWS access key");        // plain name…
    expect(out).not.toContain("aws-access-key-id"); // …not the detector tag
  });

  test("show: a span-less leak event (v1-era row) still flags the call", () => {
    // The seed's leak event carries no highlight spans — the 🔴 line is driven
    // by leak EVENTS, so a call that leaked must never read as clean.
    const out = cmdShow(stateDir, callId.slice(0, 8));
    expect(out).toContain("🔴 1 secret sent to anthropic");
    expect(out).toContain("API key (possible)");
  });

  test("show: --raw dumps exact bytes; --full leaves nothing collapsed", () => {
    const raw = cmdShow(stateDir, callId.slice(0, 8), { raw: true });
    expect(raw).toContain("request (raw)");
    expect(raw).toContain("my password is hunter2");
    const full = cmdShow(stateDir, callId.slice(0, 8), { full: true });
    expect(full).not.toContain("--full to show"); // system/history no longer collapsed
  });

  test("show: an unknown id explains deletion/retention, not a bare miss", () => {
    const out = cmdShow(stateDir, "ZZZZZZZZ");
    expect(out.toLowerCase()).toContain("no call");
    expect(out).toContain("deleted with its session");
    expect(out).toContain("beagle leaks"); // where the surviving record lives
  });

  test("show: an ambiguous prefix lists the candidate ids instead of a miss", () => {
    // Two calls sharing an 8-char prefix — what a same-millisecond ULID burst
    // produces (and what made `show <id from beagle leaks>` look broken).
    const store = Store.open(stateDir);
    for (const id of ["01AMBIGUOUS0000000000000A", "01AMBIGUOUS0000000000000B"]) {
      store.insertCall({
        id, sessionId: "sA", runId: "rA", source: "wire", agent: "claude",
        provider: "anthropic", endpoint: "/v1/messages", tsRequest: Date.now(),
        scanState: "ok", captureState: "ok", sessionTier: "prefix",
        requestBody: null, requestHeaders: null, responseBody: null,
        responseHeaders: null, sseRaw: null, searchText: "",
      });
    }
    store.close();
    const out = cmdShow(stateDir, "01AMBIGU");
    expect(out).toContain("2 calls match");
    expect(out).toContain("01AMBIGUOUS0000000000000A");
    expect(out).toContain("01AMBIGUOUS0000000000000B");
    expect(out).toContain("use more of the id");
  });

  test("show: traffic-derived text is stripped of terminal escapes", () => {
    const store = Store.open(stateDir);
    const id = ulid();
    store.insertCall({
      id, sessionId: "s2", runId: "r1", source: "wire", agent: "claude-code",
      provider: "anthropic", model: "m", endpoint: "/v1/messages",
      tsRequest: Date.now(), scanState: "ok", captureState: "ok", sessionTier: "run",
      summary: "evil \x1b[2J\x1b[31m wipe-your-screen summary",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "x",
    });
    store.close();
    // full id: two same-millisecond ULIDs share an 8-char prefix
    const out = cmdShow(stateDir, id);
    expect(out).not.toContain("\x1b");
    expect(out).toContain("wipe-your-screen");
  });

  test("status: trust-strip text works with no daemon running", () => {
    const out = cmdStatus(stateDir);
    expect(out.toLowerCase()).toContain("not running");
    expect(out).toContain("1 call");
    expect(out).toContain("1 detected");
    expect(out.toLowerCase()).toContain("local only");
  });

  test("status: daemon line says why the daemon is up and when it winds down", () => {
    const base = { pid: 42, proxyPort: 6410, socketPath: "sock", persistent: false };
    let out = cmdStatus(stateDir, { ...base, leases: 2, viewerOpen: true });
    expect(out).toContain("2 live sessions");
    expect(out.toLowerCase()).toContain("dashboard");
    out = cmdStatus(stateDir, { ...base, leases: 1, viewerOpen: false });
    expect(out).toContain("1 live session");
    out = cmdStatus(stateDir, { ...base, leases: 0, viewerOpen: false });
    expect(out.toLowerCase()).toContain("winds down");
  });

  test("status: a never-idle-exiting daemon says so without claiming a service install", () => {
    // `persistent` covers BOTH the installed service and a hand-run
    // `beagle daemon` (main.ts sets it from BEAGLE_EPHEMERAL, not from any
    // service marker), so the line must not assert an install that may not
    // exist — the changes row is what discloses a real one.
    const out = cmdStatus(stateDir, { pid: 42, proxyPort: 6410, socketPath: "s", persistent: true });
    expect(out.toLowerCase()).toContain("always on");
    expect(out).toContain("beagle stop");
    expect(out.toLowerCase()).not.toContain("installed service");
    expect(out.toLowerCase()).not.toContain("winds down");
  });

  test("status: says nothing about why when the daemon cannot tell us (older daemon / failed enrich)", () => {
    // ping proved it is running, but the status enrich call failed or the
    // daemon predates these fields: claim "running" and stop there rather than
    // guess "idle" at a daemon that may hold five sessions.
    const out = cmdStatus(stateDir, { pid: 42, proxyPort: 6410, socketPath: "s" });
    expect(out).toContain("running — pid 42");
    expect(out.toLowerCase()).not.toContain("idle");
    expect(out.toLowerCase()).not.toContain("winds down");
    expect(out.toLowerCase()).not.toContain("always on");
  });

  test("status: every value line is label-aligned into two columns", () => {
    const out = cmdStatus(stateDir);
    for (const line of out.split("\n")) {
      if (line === "") continue;
      // 11-char label gutter: either a label padded to the gutter or a
      // continuation line of pure indent
      expect(line.length).toBeGreaterThan(11);
      expect(line[11]).not.toBe(" ");
      expect(/^[a-z ]{11}$/.test(line.slice(0, 11))).toBe(true);
    }
  });

  test("status: discloses the Mode B content gap whenever agent-reported calls exist (R2)", () => {
    const store = Store.open(stateDir);
    const otel: CallRecord = {
      id: ulid(), sessionId: "s2", runId: "r2", source: "otel",
      agent: "claude-code", provider: "anthropic", model: "claude-sonnet-5",
      endpoint: "otlp", tsRequest: Date.now(), tsResponse: Date.now(),
      status: 200, tokensIn: 1, tokensOut: 1, bytesReq: 10, bytesResp: 10,
      summary: "otel", scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: new TextEncoder().encode("{}"), requestHeaders: [],
      responseBody: null, responseHeaders: [], sseRaw: null, searchText: "otel",
    };
    store.insertCall(otel);
    store.close();
    const out = cmdStatus(stateDir);
    expect(out).toContain("1 agent-reported (Mode B)");
    expect(out.toLowerCase()).toContain("lag");
  });

  // Codex subscription answers come from codex's own rollout log, not its OTel
  // self-report. If that log is missing (history logging off, or a CODEX_HOME
  // the daemon didn't share), the answer can't be recovered — say so, with the
  // path, rather than leave a silently answer-less turn (Phase 1.5).
  function seedCodexOtel(dir: string): void {
    const store = Store.open(dir);
    store.insertCall({
      id: ulid(), sessionId: "cx", runId: "rx", source: "otel",
      agent: "codex", provider: "openai", model: "gpt-5.6-sol",
      endpoint: "otel:codex:user_prompt", tsRequest: Date.now(), tsResponse: Date.now(),
      status: 200, tokensIn: 1, tokensOut: 1, bytesReq: 10, bytesResp: 0,
      summary: "otel", scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: new TextEncoder().encode("{}"), requestHeaders: [],
      responseBody: null, responseHeaders: [], sseRaw: null, searchText: "otel",
    });
    store.close();
  }

  test("status: warns when codex Mode B calls exist but no session logs are present", () => {
    seedCodexOtel(stateDir);
    const noLogs = join(stateDir, "no-such-codex", "sessions"); // does not exist
    const out = cmdStatus(stateDir, null, () => true, noLogs);
    expect(out.toLowerCase()).toContain("codex");
    expect(out.toLowerCase()).toContain("history logging");
    expect(out).toContain(noLogs); // shows the path, so a wrong CODEX_HOME is self-diagnosing
  });

  test("status: no codex warning when the session log directory has content", () => {
    seedCodexOtel(stateDir);
    const withLogs = mkdtempSync(join(tmpdir(), "beagle-codexlogs-"));
    writeFileSync(join(withLogs, "2026"), "x"); // any entry ⇒ codex has been logging here
    const out = cmdStatus(stateDir, null, () => true, withLogs);
    expect(out.toLowerCase()).not.toContain("history logging");
  });

  test("status: no codex warning when there are no codex Mode B calls", () => {
    // default seed() is a claude WIRE call — no codex self-report to worry about
    const noLogs = join(stateDir, "no-such-codex", "sessions");
    const out = cmdStatus(stateDir, null, () => true, noLogs);
    expect(out.toLowerCase()).not.toContain("history logging");
  });
});

describe("countPossibleLeaksSince (the run-end quiet-tier surface)", () => {
  test("counts only possible-tier leaks recorded since the timestamp", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-plk-"));
    const store = Store.open(dir);
    const now = Date.now();
    const ev = (fp: string, tier: string, ts: number) =>
      store.upsertLeakEvent({
        fingerprint: fp, sessionId: "s", detector: "generic-api-key", secretType: "generic-api-key",
        severity: "medium", confidenceTier: tier, destination: "anthropic", callId: "c-" + fp, ts,
      });
    ev("f1", "structured", now); // loud tier — excluded
    ev("f2", "possible", now);   // counts
    ev("f3", "possible", now);   // counts
    ev("f4", "possible", now - 10_000); // before the window — excluded
    store.close();
    expect(countPossibleLeaksSince(dir, now - 1_000)).toBe(2);
    // no store / nothing recorded → 0, never throws
    expect(countPossibleLeaksSince(mkdtempSync(join(tmpdir(), "beagle-plk-empty-")), 0)).toBe(0);
  });
});

describe("parseRunArgs", () => {
  const { parseRunArgs } = require("../src/cli/commands") as typeof import("../src/cli/commands");

  test("shim invocation: --real and separator", () => {
    const r = parseRunArgs(["--real", "/opt/bin/claude", "--", "-p", "hello"]);
    expect(r.realBinary).toBe("/opt/bin/claude");
    expect(r.agentArgs).toEqual(["-p", "hello"]);
    expect(r.telemetry).toBe(false);
  });

  test("--telemetry before the separator is beagle's", () => {
    const r = parseRunArgs(["--telemetry", "--", "-p", "hi"]);
    expect(r.telemetry).toBe(true);
    expect(r.agentArgs).toEqual(["-p", "hi"]);
  });

  test("--telemetry AFTER the separator belongs to the agent", () => {
    const r = parseRunArgs(["--", "--telemetry"]);
    expect(r.telemetry).toBe(false);
    expect(r.agentArgs).toEqual(["--telemetry"]);
  });

  test("no separator: beagle flags are stripped from agent args", () => {
    const r = parseRunArgs(["--telemetry", "-p", "hi"]);
    expect(r.telemetry).toBe(true);
    expect(r.agentArgs).toEqual(["-p", "hi"]);
  });
});

describe("run env mapping", () => {
  test("claude uses ANTHROPIC_BASE_URL with the run prefix", () => {
    const env = buildRunEnv("claude", 4242, "uuid-1");
    expect(env.ANTHROPIC_BASE_URL).toBe("http://127.0.0.1:4242/run/uuid-1");
  });

  test("codex redirects via a custom provider, NOT OPENAI_BASE_URL (which it ignores)", () => {
    // codex ignores OPENAI_BASE_URL (verified live) — buildRunEnv must not
    // pretend otherwise, and the wire redirect is a custom model_provider.
    expect(AGENTS.codex!.baseUrlEnv).toBeUndefined();
    expect(buildRunEnv("codex", 4242, "uuid-2")).toEqual({});
    const args = AGENTS.codex!.wireArgs!("http://127.0.0.1:4242/run/uuid-2");
    expect(args).toContain('model_provider="beagle"');
    expect(args).toContain('model_providers.beagle.base_url="http://127.0.0.1:4242/run/uuid-2"');
    expect(args).toContain('model_providers.beagle.env_key="OPENAI_API_KEY"'); // reads the user's key
    expect(args).toContain('model_providers.beagle.wire_api="responses"');
    expect(args.filter((a) => a === "-c").length).toBe(5); // every knob a -c override
  });

  test("agent registry covers the four v1 CLI agents", () => {
    expect(Object.keys(AGENTS).sort()).toEqual(["claude", "codex", "opencode", "pi"]);
  });

  test("opencode is config-driven (OPENCODE_CONFIG), not env-base-URL", () => {
    expect(AGENTS.opencode!.baseUrlEnv).toBeUndefined();
    expect(AGENTS.opencode!.config?.configEnv).toBe("OPENCODE_CONFIG");
    expect(AGENTS.opencode!.config?.baseUrlPath).toEqual(["provider", "openai", "options", "baseURL"]);
    // env-base-URL helper returns nothing for config-driven agents
    expect(buildRunEnv("opencode", 1, "x")).toEqual({});
  });

  test("pi is extension-driven: -e flag re-points whichever provider pi is signed in with", () => {
    expect(AGENTS.pi!.baseUrlEnv).toBeUndefined();
    expect(AGENTS.pi!.config).toBeUndefined();
    expect(AGENTS.pi!.extension?.flag).toBe("-e");
    // baseUrlProvider is a resolver now (login-dependent: openai vs openai-codex);
    // with no pi install it falls back to the openai API-key assumption.
    const resolveProvider = AGENTS.pi!.extension!.baseUrlProvider as (home: string) => string;
    expect(resolveProvider(mkdtempSync(join(tmpdir(), "beagle-pi-none-")))).toBe("openai");
  });
});

describe("config-driven run redirect (opencode)", () => {
  const { buildRedirectConfig, readFirstConfig } =
    require("../src/install/config-redirect") as typeof import("../src/install/config-redirect");

  test("merges an existing opencode config and injects the proxy baseURL", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-oc-"));
    const cfgDir = join(dir, ".config", "opencode");
    require("node:fs").mkdirSync(cfgDir, { recursive: true });
    require("node:fs").writeFileSync(
      join(cfgDir, "opencode.json"),
      JSON.stringify({ provider: { openai: { options: { apiKey: "sk-mine" } } }, theme: "dark" }),
    );
    const spec = AGENTS.opencode!.config!;
    const user = readFirstConfig(spec.realConfigCandidates(dir));
    const merged = buildRedirectConfig(user, spec.baseUrlPath, "http://127.0.0.1:9/run/r") as any;
    expect(merged.provider.openai.options.baseURL).toBe("http://127.0.0.1:9/run/r");
    expect(merged.provider.openai.options.apiKey).toBe("sk-mine"); // preserved
    expect(merged.theme).toBe("dark"); // preserved
  });
});

describe("Claude telemetry settings redirect", () => {
  test("multiple --settings flags collapse to the last user config plus Beagle's hook", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-claude-settings-"));
    const first = join(stateDir, "first.json");
    const second = join(stateDir, "second.json");
    writeFileSync(first, JSON.stringify({ theme: "light" }));
    writeFileSync(
      second,
      JSON.stringify({
        theme: "dark",
        hooks: { PostToolUse: [{ hooks: [{ type: "command", command: "user-hook" }] }] },
      }),
    );

    // Capture the effective settings while the Beagle-owned file still exists;
    // cmdRun deletes it as soon as this fake Claude process exits.
    const fakeAgent = join(stateDir, "argv-printer.sh");
    writeFileSync(
      fakeAgent,
      '#!/bin/sh\ncount=0\nsettings=""\nwhile [ "$#" -gt 0 ]; do\n  if [ "$1" = "--settings" ]; then\n    count=$((count + 1))\n    settings="$2"\n    shift 2\n  else\n    printf "ARG:%s\\n" "$1"\n    shift\n  fi\ndone\nprintf "COUNT:%s\\nCONFIG:" "$count"\ncat "$settings"\nprintf "\\n"\n',
    );
    chmodSync(fakeAgent, 0o755);

    const run = Bun.spawnSync(
      [
        "bun",
        join(import.meta.dir, "..", "src", "cli", "main.ts"),
        "run",
        "claude",
        "--telemetry",
        "--real",
        fakeAgent,
        "--",
        "--settings",
        first,
        "user-arg",
        "--settings",
        second,
      ],
      { env: { ...process.env, BEAGLE_STATE_DIR: stateDir } },
    );

    const stdout = run.stdout.toString();
    expect(run.exitCode).toBe(0);
    expect(stdout).toContain("ARG:user-arg");
    expect(stdout).toContain("COUNT:1");
    const effective = JSON.parse(stdout.slice(stdout.indexOf("CONFIG:") + "CONFIG:".length)) as any;
    expect(effective.theme).toBe("dark"); // Claude's last-value-wins behavior is preserved
    const commands = effective.hooks.PostToolUse.map((entry: any) => entry.hooks[0].command);
    expect(commands[0]).toBe("user-hook");
    expect(commands[1]).toContain("__hook");

    try {
      const info = JSON.parse(readFileSync(join(stateDir, "daemon.json"), "utf8")) as { socketPath: string };
      const { controlRequest } = await import("../src/daemon/control");
      await controlRequest(info.socketPath, { cmd: "shutdown" });
    } catch { /* already gone */ }
  }, 20_000);
});

describe("collapseClaudeSettings", () => {
  test("no --settings: args pass through, no user settings", () => {
    expect(collapseClaudeSettings(["--model", "opus", "hi"])).toEqual({
      userSettings: null,
      restArgs: ["--model", "opus", "hi"],
    });
  });

  test("space form: last value wins, both pairs removed from argv", () => {
    expect(collapseClaudeSettings(["--settings", "a.json", "user-arg", "--settings", "b.json"])).toEqual({
      userSettings: "b.json",
      restArgs: ["user-arg"],
    });
  });

  test("equals form is recognized and collapsed (Claude accepts --settings=x)", () => {
    // Regression: the equals form used to slip through into restArgs, where it
    // lost last-wins to Beagle's appended --settings and silently dropped the
    // user's whole settings file.
    expect(collapseClaudeSettings(["--settings=/my/settings.json", "user-arg"])).toEqual({
      userSettings: "/my/settings.json",
      restArgs: ["user-arg"],
    });
  });

  test("mixed space and equals forms preserve left-to-right last-wins", () => {
    expect(collapseClaudeSettings(["--settings", "a.json", "--settings=b.json"]).userSettings).toBe("b.json");
    expect(collapseClaudeSettings(["--settings=a.json", "--settings", "b.json"]).userSettings).toBe("b.json");
  });

  test("value-less trailing --settings is dropped, never left to swallow Beagle's flag", () => {
    // Regression: left in restArgs, a bare trailing --settings would consume
    // Beagle's own appended "--settings" as its value and turn the hook config
    // path into a positional — silently disabling tool-output capture.
    expect(collapseClaudeSettings(["user-arg", "--settings"])).toEqual({
      userSettings: null,
      restArgs: ["user-arg"],
    });
  });

  test("empty equals form yields an empty string value (not dropped)", () => {
    expect(collapseClaudeSettings(["--settings="])).toEqual({ userSettings: "", restArgs: [] });
  });
});

describe("pi extension redirect (run-level)", () => {
  test("run pi injects -e <beagle extension> before user args, deletes it after", async () => {
    const { existsSync, readFileSync, writeFileSync, chmodSync } = await import("node:fs");
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-pi-"));
    // A faithful argv printer as the fake "agent". NOT /bin/echo: GNU echo
    // eats "-e" as its own escape flag (BSD echo prints it), which is exactly
    // the argument this test needs to see.
    const fakeAgent = join(stateDir, "argv-printer.sh");
    writeFileSync(fakeAgent, '#!/bin/sh\nprintf "%s\\n" "$@"\n');
    chmodSync(fakeAgent, 0o755);
    const run = Bun.spawnSync(
      ["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"),
       "run", "pi", "--real", fakeAgent, "--", "user-arg"],
      { env: { ...process.env, BEAGLE_STATE_DIR: stateDir } },
    );
    const argv = run.stdout.toString().trim().split("\n");
    expect(argv[0]).toBe("-e"); // beagle's flag first
    expect(argv[1]).toMatch(/agent-config\/pi-[0-9a-f-]+\.ts$/); // per-RUN path (concurrent runs must not collide)
    expect(argv[2]).toBe("user-arg"); // user args after
    // the Beagle-owned extension is deleted once the agent exits
    const { readdirSync } = await import("node:fs");
    expect(readdirSync(join(stateDir, "agent-config"))).toEqual([]);

    // reap the auto-started ephemeral daemon
    try {
      const info = JSON.parse(readFileSync(join(stateDir, "daemon.json"), "utf8")) as { socketPath: string };
      const { controlRequest } = await import("../src/daemon/control");
      await controlRequest(info.socketPath, { cmd: "shutdown" });
    } catch { /* already gone */ }
  }, 20_000);
});

describe("__hook forwarder safety (Mode B tool-output hook)", () => {
  const bin = () => ["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), "__hook"];

  test("no telemetry env: silent no-op, exits 0 (a bare tool call never fails)", () => {
    const run = Bun.spawnSync(bin(), { stdin: new TextEncoder().encode('{"tool_response":"x"}') });
    expect(run.exitCode).toBe(0);
    expect(run.stdout.toString()).toBe(""); // MUST be silent — output could reach the model
    expect(run.stderr.toString()).toBe("");
  });

  test("unreachable receiver: still exits 0 promptly (best-effort; never stalls the agent)", () => {
    const t0 = Date.now();
    const run = Bun.spawnSync(bin(), {
      stdin: new TextEncoder().encode('{"session_id":"s","tool_name":"Bash","tool_response":"AKIAZQ3DRSTUVWXY2345"}'),
      // 127.0.0.1:1 refuses fast; the 2s fetch timeout bounds the worst case regardless
      env: { ...process.env, BEAGLE_HOOK_ENDPOINT: "http://127.0.0.1:1/v1/hook", BEAGLE_HOOK_TOKEN: "t" },
    });
    expect(run.exitCode).toBe(0);
    expect(run.stdout.toString()).toBe("");
    expect(Date.now() - t0).toBeLessThan(4000); // bounded by the 2s AbortSignal, not hung
  });

  test("stdin that never reaches EOF is time-bounded (the read can't hang the agent)", async () => {
    // A partial payload with stdin left OPEN: the read must not block forever
    // waiting for EOF — the 1.5s deadline cancels it, then the process exits.
    const proc = Bun.spawn(bin(), {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, BEAGLE_HOOK_ENDPOINT: "http://127.0.0.1:1/v1/hook", BEAGLE_HOOK_TOKEN: "t" },
    });
    proc.stdin.write('{"tool_response":"partial'); // never closed
    proc.stdin.flush();
    const t0 = Date.now();
    const code = await Promise.race([
      proc.exited,
      new Promise<number>((r) => setTimeout(() => { proc.kill(); r(-1); }, 6000)),
    ]);
    expect(code).toBe(0); // exited on its own (not the 6s kill fallback)
    expect(Date.now() - t0).toBeLessThan(5000); // bounded by the 1.5s stdin deadline + fetch
  });

  test("isLoopbackHookEndpoint: exact loopback allowlist over the parsed hostname", () => {
    // the one format cmdRun actually constructs, plus the other canonical loopback names
    expect(isLoopbackHookEndpoint("http://127.0.0.1:38211/v1/hook")).toBe(true);
    expect(isLoopbackHookEndpoint("http://localhost:38211/v1/hook")).toBe(true);
    expect(isLoopbackHookEndpoint("http://[::1]:38211/v1/hook")).toBe(true);
    // the URL parser canonicalizes equivalent spellings before the exact match
    expect(isLoopbackHookEndpoint("http://127.1:9/v1/hook")).toBe(true); // → 127.0.0.1
    expect(isLoopbackHookEndpoint("http://LOCALHOST:9/v1/hook")).toBe(true); // lowercased
    expect(isLoopbackHookEndpoint("http://[0:0:0:0:0:0:0:1]:9/v1/hook")).toBe(true); // → [::1]
    // everything else is refused — including hosts that merely RESOLVE to loopback
    expect(isLoopbackHookEndpoint("http://192.168.1.7:38211/v1/hook")).toBe(false);
    expect(isLoopbackHookEndpoint("http://evil.example/v1/hook")).toBe(false);
    expect(isLoopbackHookEndpoint("http://127.0.0.1.evil.example/v1/hook")).toBe(false); // prefix spoof
    expect(isLoopbackHookEndpoint("http://localhost.:9/v1/hook")).toBe(false); // trailing-dot form
    expect(isLoopbackHookEndpoint("not a url")).toBe(false);
    // scheme is pinned to the one cmdRun emits — non-http loopback is refused too
    expect(isLoopbackHookEndpoint("https://127.0.0.1:38211/v1/hook")).toBe(false);
    expect(isLoopbackHookEndpoint("file://localhost/etc/hosts")).toBe(false);
  });

  test("loopback endpoint: payload IS delivered (the allowlist doesn't break capture)", async () => {
    const hits: { method: string; path: string; token: string | null; body: string }[] = [];
    const srv = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req) {
        hits.push({ method: req.method, path: new URL(req.url).pathname, token: req.headers.get("x-beagle-run"), body: await req.text() });
        return new Response("ok");
      },
    });
    try {
      const payload = '{"session_id":"s","tool_name":"Bash","tool_response":"out"}';
      const proc = Bun.spawn(bin(), {
        stdin: new TextEncoder().encode(payload),
        stdout: "pipe",
        stderr: "pipe",
        env: { ...process.env, BEAGLE_HOOK_ENDPOINT: `http://127.0.0.1:${srv.port}/v1/hook`, BEAGLE_HOOK_TOKEN: "tok" },
      });
      expect(await proc.exited).toBe(0);
      expect(hits).toEqual([{ method: "POST", path: "/v1/hook", token: "tok", body: payload }]);
    } finally {
      srv.stop(true);
    }
  }, 10_000);

  test("non-loopback endpoint host: nothing is sent (captured output never leaves loopback)", async () => {
    // `localhost.` (trailing FQDN dot) still RESOLVES to loopback on dev/CI
    // platforms — so if the forwarder ever skipped its allowlist, this fetch
    // would connect and the receiver below would record a hit. The exact-match
    // allowlist refuses the non-canonical spelling instead of resolving it.
    let hits = 0;
    const srv = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        hits++;
        return new Response("ok");
      },
    });
    try {
      const proc = Bun.spawn(bin(), {
        stdin: new TextEncoder().encode('{"tool_response":"AKIAZQ3DRSTUVWXY2345"}'),
        stdout: "pipe",
        stderr: "pipe",
        env: { ...process.env, BEAGLE_HOOK_ENDPOINT: `http://localhost.:${srv.port}/v1/hook`, BEAGLE_HOOK_TOKEN: "t" },
      });
      expect(await proc.exited).toBe(0);
      expect(await new Response(proc.stdout).text()).toBe(""); // still silent
      expect(await new Response(proc.stderr).text()).toBe("");
      expect(hits).toBe(0); // the promise itself: no POST to a non-allowlisted host
    } finally {
      srv.stop(true);
    }
  }, 10_000);

  test("redirecting receiver: the payload is NOT re-POSTed to the Location target", async () => {
    // The allowlist vets only the FIRST hop. Bun's fetch default (`follow`)
    // re-sends a 307'd POST — body and all — to an arbitrary Location, which
    // could be off-machine; `redirect: "manual"` must stop it. `target` below
    // is loopback only so the test can observe it; it stands in for anywhere.
    let leaked = 0;
    const target = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        leaked++;
        return new Response("gotcha");
      },
    });
    let firstHop = 0;
    const redirector = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        firstHop++;
        return new Response(null, { status: 307, headers: { location: `http://127.0.0.1:${target.port}/exfil` } });
      },
    });
    try {
      const proc = Bun.spawn(bin(), {
        stdin: new TextEncoder().encode('{"tool_response":"AKIAZQ3DRSTUVWXY2345"}'),
        stdout: "pipe",
        stderr: "pipe",
        env: { ...process.env, BEAGLE_HOOK_ENDPOINT: `http://127.0.0.1:${redirector.port}/v1/hook`, BEAGLE_HOOK_TOKEN: "t" },
      });
      expect(await proc.exited).toBe(0);
      expect(await new Response(proc.stdout).text()).toBe(""); // still silent
      expect(firstHop).toBe(1); // the allowlisted hop happened
      expect(leaked).toBe(0); // the redirect was NOT followed
    } finally {
      redirector.stop(true);
      target.stop(true);
    }
  }, 10_000);
});

describe("readCodexApiKey (fail-open: supply codex's key from auth.json)", () => {
  test("reads OPENAI_API_KEY from $CODEX_HOME/auth.json; null when absent", () => {
    const h = mkdtempSync(join(tmpdir(), "beagle-cxk-"));
    writeFileSync(join(h, "auth.json"), '{"auth_mode":"apikey","OPENAI_API_KEY":"sk-fromfile"}');
    expect(readCodexApiKey(h)).toBe("sk-fromfile");
    writeFileSync(join(h, "auth.json"), '{"auth_mode":"apikey"}'); // no key field
    expect(readCodexApiKey(h)).toBeNull();
    writeFileSync(join(h, "auth.json"), "not json");
    expect(readCodexApiKey(h)).toBeNull();
    expect(readCodexApiKey(mkdtempSync(join(tmpdir(), "beagle-empty-")))).toBeNull(); // no file
  });
});

describe("cmdUninstall (safe full teardown)", () => {
  test("non-interactive without --yes: refuses to prompt (no hang), asks for --yes", async () => {
    // Pass isTTY=false explicitly (not the runner's ambient stdin) so this stays
    // deterministic — under `bun run check` in a real terminal isTTY is true,
    // which would otherwise make cmdUninstall prompt and block the whole run.
    const dir = mkdtempSync(join(tmpdir(), "beagle-uninst-nt-"));
    const store = Store.open(dir); store.close(); // a store → not the empty-noop path
    const out = await cmdUninstall(dir, false, false);
    expect(out).toContain("--yes");
    expect(existsSync(join(dir, "beagle.db"))).toBe(true); // nothing deleted
  });

  test("no daemon, watches, or store: reports nothing to remove", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-uninst-empty-"));
    const out = await cmdUninstall(dir, true);
    expect(out.toLowerCase()).toContain("nothing to remove");
  });

  test("--yes: securely erases the store and removes the state dir; names the binary step", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-uninst-"));
    // a store with a captured secret present
    const store = Store.open(dir);
    store.insertCall({
      id: ulid(), sessionId: "s1", runId: "r1", source: "wire", agent: "claude-code",
      provider: "anthropic", endpoint: "/v1/messages", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: new TextEncoder().encode("AKIAZQ3DRSTUVWXY2345"),
      requestHeaders: null, responseBody: null, responseHeaders: null, sseRaw: null,
      searchText: "AKIAZQ3DRSTUVWXY2345",
    });
    store.close();
    expect(existsSync(join(dir, "beagle.db"))).toBe(true);
    const out = await cmdUninstall(dir, true);
    expect(out).toContain("securely erased captured data");
    expect(out).toContain(`removed ${dir}`);
    expect(out).toContain("brew uninstall beagle");
    expect(existsSync(dir)).toBe(false); // exclusive dir → whole dir gone
  });

  test("removes ONLY Beagle-owned files — never the user's own files in a shared dir", async () => {
    // A user who pointed BEAGLE_STATE_DIR at a directory holding their own
    // files must NOT lose them to `rm -rf` (confirmed data loss before the fix).
    const dir = mkdtempSync(join(tmpdir(), "beagle-shared-"));
    writeFileSync(join(dir, "notes.txt"), "my precious data");
    const store = Store.open(dir); // creates beagle.db (+ config on next status)
    store.close();
    writeFileSync(join(dir, "config.json"), "{}");
    const out = await cmdUninstall(dir, true);
    expect(existsSync(dir)).toBe(true); // dir kept — it wasn't exclusively Beagle's
    expect(existsSync(join(dir, "notes.txt"))).toBe(true); // user's file survives
    expect(existsSync(join(dir, "beagle.db"))).toBe(false); // Beagle's files gone
    expect(existsSync(join(dir, "config.json"))).toBe(false);
    expect(out).toContain("kept your other files");
  });
});

describe("beagle help / detect surfaces", () => {
  function writeAppBundle(home: string, name: string, bundleId: string): void {
    const contents = join(home, "Applications", name, "Contents");
    mkdirSyncDetect(contents, { recursive: true });
    writeFileSync(join(contents, "Info.plist"),
      `<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>${bundleId}</string></dict></plist>`);
  }

  test("'beagle help' prints the command list and exits 0 (not the unknown-command path)", () => {
    for (const arg of ["help", "--help", "-h"]) {
      const run = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), arg]);
      expect(run.exitCode).toBe(0);
      expect(run.stdout.toString()).toContain("beagle run <agent>");
      expect(run.stdout.toString()).toContain("beagle stop");
    }
  });

  test("an unknown command still prints help but exits 2", () => {
    const run = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src", "cli", "main.ts"), "bogus-cmd"]);
    expect(run.exitCode).toBe(2);
  });

  test("detectLine puts the command on its own arrowed line, with a plain-English capture note", () => {
    // The command must read as "type this" — its own line, marked, not buried
    // mid-row between unlabeled facts (the old single-line format).
    const sub = detectLine("claude", "subscription");
    expect(sub).toContain("→ beagle run claude");
    expect(sub.split("\n").length).toBe(2);
    // no bare jargon: each login kind is explained in plain words
    expect(sub).toContain("subscription");
    expect(sub).toContain("usage report");
    expect(detectLine("codex", "api-key")).toContain("API key");
    expect(detectLine("codex", "api-key")).toContain("on the wire");
    expect(detectLine("codex", "unknown")).toContain("asks once");
    // the command itself is always the plain one — no flags to memorize
    expect(detectLine("codex", "unknown")).toContain("→ beagle run codex");
  });

  test("detect separates supported agents from locally recognized unsupported ones", () => {
    const home = mkdtempSync(join(tmpdir(), "beagle-detect-"));
    const bin = join(home, "bin");
    mkdirSyncDetect(bin, { recursive: true });
    for (const name of ["opencode", "aider", "gemini", "unknown-agent"]) {
      const p = join(bin, name);
      writeFileSync(p, "#!/bin/sh\n");
      chmodSync(p, 0o755);
    }
    writeAppBundle(home, "Claude.app", "com.anthropic.claudefordesktop");
    writeAppBundle(home, "Codex.app", "com.openai.codex");

    const out = cmdDetect({
      pathDirs: [bin], home, extraLocations: [], systemApplicationsDir: join(home, "system-apps"),
      xdgDataHome: join(home, "xdg-data"),
    });
    expect(out).toContain("Found 1 supported agent");
    expect(out).toContain("→ beagle run opencode");
    expect(out).toContain("Also found 4 recognized agents Beagle can't capture yet");
    expect(out).toContain("aider");
    expect(out).toContain("gemini");
    expect(out).toContain("claude-desktop");
    expect(out).toContain("codex-desktop");
    expect(out).toContain("desktop app found");
    expect(out).toContain("claude-desktop  desktop app found");
    expect(out).toContain(AGENT_REQUEST_URL);
    expect(out).not.toContain("unknown-agent");
  });

  test("detect is helpful when only a recognized unsupported agent is present", () => {
    const home = mkdtempSync(join(tmpdir(), "beagle-detect-"));
    const bin = join(home, "bin");
    mkdirSyncDetect(bin, { recursive: true });
    writeFileSync(join(bin, "aider"), "#!/bin/sh\n", { mode: 0o755 });

    const out = cmdDetect({
      pathDirs: [bin], home, extraLocations: [], systemApplicationsDir: join(home, "system-apps"),
      xdgDataHome: join(home, "xdg-data"),
    });
    expect(out).toContain("Beagle found 1 recognized agent, but can't capture it yet");
    expect(out).not.toContain("No supported agents found");
    expect(out).toContain(AGENT_REQUEST_URL);
  });

  test("detect adds no unsupported-agent section when it recognizes none", () => {
    const home = mkdtempSync(join(tmpdir(), "beagle-detect-"));
    const out = cmdDetect({
      pathDirs: [], home, extraLocations: [], systemApplicationsDir: join(home, "system-apps"),
      xdgDataHome: join(home, "xdg-data"),
    });
    expect(out).toContain("No supported agents found on your PATH");
    expect(out).not.toContain("can't capture yet");
    expect(out).not.toContain(AGENT_REQUEST_URL);
  });

  test("run gives recognized and truly unknown agents distinct refusals", () => {
    const cli = join(import.meta.dir, "..", "src", "cli", "main.ts");
    const recognized = Bun.spawnSync(["bun", cli, "run", "aider"]);
    expect(recognized.exitCode).toBe(2);
    expect(recognized.stderr.toString()).toContain("recognizes Aider, but can't capture it yet");
    expect(recognized.stderr.toString()).not.toContain("is installed");
    expect(recognized.stderr.toString()).toContain(AGENT_REQUEST_URL);

    const desktop = Bun.spawnSync(["bun", cli, "run", "codex-desktop"]);
    expect(desktop.exitCode).toBe(2);
    expect(desktop.stderr.toString()).toContain("recognizes Codex desktop app");
    expect(desktop.stderr.toString()).toContain("separate integration");

    const unknown = Bun.spawnSync(["bun", cli, "run", "some-new-agent"]);
    expect(unknown.exitCode).toBe(2);
    expect(unknown.stderr.toString()).toContain("unknown agent 'some-new-agent'");
    expect(unknown.stderr.toString()).toContain(AGENT_REQUEST_URL);
  });
});

describe("interpretAskAnswer (strict — a fumbled keystroke is never remembered)", () => {
  test("only an unambiguous 1 or 2 counts", () => {
    expect(interpretAskAnswer("1")).toBe("wire");
    expect(interpretAskAnswer(" 2 ")).toBe("telemetry");
    expect(interpretAskAnswer("")).toBeNull(); // blank Enter
    expect(interpretAskAnswer("yes")).toBeNull();
    expect(interpretAskAnswer("1)")).toBeNull();
    expect(interpretAskAnswer("12")).toBeNull();
  });
});

describe("resolveRunMode (flag > saved > detected > ask > wire)", () => {
  test("explicit flags always win", () => {
    expect(resolveRunMode({ telemetry: true, wire: false }, "wire", "api-key", true)).toEqual({ mode: "telemetry", source: "flag" });
    expect(resolveRunMode({ telemetry: false, wire: true }, "telemetry", "subscription", true)).toEqual({ mode: "wire", source: "flag" });
  });

  test("a remembered answer beats detection", () => {
    expect(resolveRunMode({ telemetry: false, wire: false }, "telemetry", "api-key", true)).toEqual({ mode: "telemetry", source: "saved" });
    expect(resolveRunMode({ telemetry: false, wire: false }, "wire", "subscription", true)).toEqual({ mode: "wire", source: "saved" });
  });

  test("detection decides when nothing is saved", () => {
    expect(resolveRunMode({ telemetry: false, wire: false }, undefined, "subscription", false)).toEqual({ mode: "telemetry", source: "detected" });
    expect(resolveRunMode({ telemetry: false, wire: false }, undefined, "api-key", false)).toEqual({ mode: "wire", source: "detected" });
  });

  test("unknown login: ask on a TTY, silently default to wire otherwise", () => {
    // non-TTY (the PATH shim, scripts) must NEVER hang on a prompt
    expect(resolveRunMode({ telemetry: false, wire: false }, undefined, "unknown", false)).toEqual({ mode: "wire", source: "default" });
    expect(resolveRunMode({ telemetry: false, wire: false }, undefined, "unknown", true)).toEqual({ mode: "ask" });
  });
});

describe("runCallsArrived (the wire zero-capture tripwire's predicate)", () => {
  test("true as soon as a row exists for the runId; false when none within the deadline", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-trip-"));
    const store = Store.open(stateDir);
    store.insertCall({
      id: ulid(), sessionId: "s1", runId: "run-covered", source: "wire", agent: "codex",
      provider: "openai", endpoint: "/v1/responses", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "x",
    });
    store.close();
    expect(await runCallsArrived(stateDir, "run-covered", 500)).toBe(true);
    // a different runId has zero rows → tripwire condition
    expect(await runCallsArrived(stateDir, "run-empty", 500)).toBe(false);
  });

  test("an absent store never cries wolf", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-trip-"));
    expect(await runCallsArrived(stateDir, "any", 300)).toBe(true);
  });

  test("hook rows never satisfy the EXPORT tripwire — a dead exporter can't hide behind tool traffic", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-trip-"));
    const store = Store.open(stateDir);
    // only a HOOK row lands (PostToolUse works, OTel export dead/diverted)
    store.insertCall({
      id: ulid(), sessionId: "s1", runId: "otel", source: "otel", agent: "claude",
      provider: "anthropic", endpoint: "otel:tool_output:Bash", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "x",
    });
    store.close();
    expect(await otelCallsArrivedSince(stateDir, Date.now() - 1000, 400)).toBe(false);
    // an EXPORT row (the turn) does satisfy it
    const s2 = Store.open(stateDir);
    s2.insertCall({
      id: ulid(), sessionId: "s1", runId: "otel", source: "otel", agent: "claude",
      provider: "anthropic", endpoint: "otel:claude_code.turn", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "y",
    });
    s2.close();
    expect(await otelCallsArrivedSince(stateDir, Date.now() - 1000, 400)).toBe(true);
  });

  test("otelCallsArrivedSince is timestamp-based — old rows don't count, deletions can't fake a zero", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "beagle-trip-"));
    const store = Store.open(stateDir);
    const old = Date.now() - 3_600_000; // an hour-old otel row from a PREVIOUS run
    store.insertCall({
      id: ulid(old), sessionId: "s1", runId: "otel", source: "otel", agent: "codex",
      provider: "openai", endpoint: "otel:codex:user_prompt", tsRequest: old,
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "old",
    });
    store.close();
    // a run that started NOW must not be satisfied by the stale row
    expect(await otelCallsArrivedSince(stateDir, Date.now(), 400)).toBe(false);
    // …but a row landing within the run window (with clock margin) counts
    const store2 = Store.open(stateDir);
    store2.insertCall({
      id: ulid(), sessionId: "s1", runId: "otel", source: "otel", agent: "codex",
      provider: "openai", endpoint: "otel:codex:user_prompt", tsRequest: Date.now(),
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "fresh",
    });
    store2.close();
    expect(await otelCallsArrivedSince(stateDir, Date.now() - 1000, 400)).toBe(true);
  });
});

describe("watchForFirstCapture + wireCaptureLive (the early 'capture active' confirmation)", () => {
  const stops: Array<() => void> = [];
  const dirs: string[] = [];
  // Stop every armed interval and remove every temp store even if an assertion
  // throws mid-test — a leaked unref'd poller won't hang bun:test, but it would
  // churn the store under later tests. Also keeps the timing tests store-free.
  const arm = (enabled: boolean, check: () => boolean, onActive: () => void, ms: number): (() => void) => {
    const stop = watchForFirstCapture(enabled, check, onActive, ms);
    stops.push(stop);
    return stop;
  };
  const tmp = (prefix: string): string => {
    const d = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(d);
    return d;
  };
  const seedWire = (stateDir: string, runId: string, tsRequest: number): void => {
    const store = Store.open(stateDir);
    store.insertCall({
      id: ulid(), sessionId: "s1", runId, source: "wire", agent: "codex",
      provider: "openai", endpoint: "/v1/responses", tsRequest,
      scanState: "ok", captureState: "ok", sessionTier: "run",
      requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "x",
    });
    store.close();
  };
  afterEach(() => {
    for (const s of stops) s();
    stops.length = 0;
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
    dirs.length = 0;
  });

  // --- the watcher mechanism, driven by a deterministic synchronous check (no
  // store I/O, so the timing assertions can't flake on a loaded CI disk) ---
  test("fires onActive exactly once when the check turns true — never re-fires", async () => {
    let live = false;
    let fires = 0;
    arm(true, () => live, () => { fires++; }, 10);
    await Bun.sleep(40);
    expect(fires).toBe(0); // check false → silence
    live = true;
    await Bun.sleep(60); // many ticks now see true, but the latch fires once
    expect(fires).toBe(1);
    live = false; // even if the row later "vanished", it stays fired-once
    await Bun.sleep(30);
    expect(fires).toBe(1);
  });

  test("enabled=false arms no poll at all — never fires even when the check is always true", async () => {
    let fires = 0;
    arm(false, () => true, () => { fires++; }, 10);
    await Bun.sleep(40);
    expect(fires).toBe(0);
  });

  test("stop() blocks a confirmation that would otherwise land after the agent exits", async () => {
    let captured = false;
    let fires = 0;
    const stop = arm(true, () => captured, () => { fires++; }, 10);
    stop(); // agent exited before anything was captured
    captured = true; // a call would now satisfy the check…
    await Bun.sleep(40);
    expect(fires).toBe(0); // …but the watcher is already stopped
  });

  test("a throwing check is swallowed — never fires, never disrupts the run", async () => {
    let fires = 0;
    arm(true, () => { throw new Error("store hiccup"); }, () => { fires++; }, 10);
    await Bun.sleep(40);
    expect(fires).toBe(0);
  });

  // --- wireCaptureLive: the run-scoped, fail-closed, index-bounded predicate ---
  test("true once a wire row for this run lands at/after t0; false before", () => {
    const stateDir = tmp("beagle-cap-");
    const t0 = Date.now();
    Store.open(stateDir).close(); // materialize an empty store
    expect(wireCaptureLive(stateDir, "run-A", t0)).toBe(false);
    seedWire(stateDir, "run-A", t0 + 1);
    expect(wireCaptureLive(stateDir, "run-A", t0)).toBe(true);
  });

  test("run-scoped: a concurrent run's captured call never trips this run's confirmation", () => {
    const stateDir = tmp("beagle-cap-");
    const t0 = Date.now();
    seedWire(stateDir, "run-OTHER", t0 + 1); // a different run captured a call
    expect(wireCaptureLive(stateDir, "run-MINE", t0)).toBe(false);
  });

  test("ignores rows older than t0 — a prior run's leftover can't fake a positive", () => {
    const stateDir = tmp("beagle-cap-");
    const t0 = Date.now();
    seedWire(stateDir, "run-A", t0 - 5_000); // same runId, but before this run started
    expect(wireCaptureLive(stateDir, "run-A", t0)).toBe(false);
  });

  test("fails CLOSED on an absent store — the deliberate opposite of the fail-open tripwire", async () => {
    const stateDir = tmp("beagle-cap-empty-");
    // A positive signal must never affirm on uncertainty:
    expect(wireCaptureLive(stateDir, "run-A", Date.now())).toBe(false);
    // …whereas runCallsArrived (the end-of-run tripwire) deliberately returns
    // true for an absent store — don't cry wolf. This asymmetry is the fix.
    expect(await runCallsArrived(stateDir, "run-A", 0)).toBe(true);
  });
});


// Status honesty for the watched-but-daemon-down state, and the service
// health warning (the "always-on daemon for the wrong store" failure).
import { mkdirSync as mkdirSync2 } from "node:fs";
import { systemdUnit as systemdUnit2 } from "../src/install/service";

describe("cmdStatus — daemon wording + service health", () => {
  const shimEntry = (dir: string) => ({
    kind: "shim", agent: "opencode", path: join(dir, "shims", "opencode"), backup: null,
  });

  test("daemon down + no watches → the DIRECT warning", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-"));
    expect(cmdStatus(dir, null, () => true)).toContain("go DIRECT (unmonitored)");
  });

  test("status is READ-ONLY: it never creates config.json, so 'modified nothing' stays true", () => {
    // Reproduced bug: cmdStatus → loadConfig created config.json on a pristine
    // dir, then the trust strip claimed 'modified nothing'. readConfig fixes it.
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-ro-"));
    const s = cmdStatus(dir, null, () => true);
    expect(existsSync(join(dir, "config.json"))).toBe(false);
    expect(s).toContain("beagle has modified nothing on this system");
  });

  test("a corrupt config.json is surfaced loudly — and status still writes nothing", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-cfgcorrupt-"));
    writeFileSync(join(dir, "config.json"), "{ truncated");
    const before = readFileSync(join(dir, "config.json"), "utf8");
    const s = cmdStatus(dir, null, () => true);
    expect(s).toContain("config.json is corrupt");
    expect(s).toContain("safe DEFAULTS");
    // Read-only invariant holds even on the corrupt path: no repair, no quarantine.
    expect(readFileSync(join(dir, "config.json"), "utf8")).toBe(before);
    expect(existsSync(join(dir, "quarantine"))).toBe(false);
  });

  test("a corrupt changes.json makes status DROP 'modified nothing' for a loud warning", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-chgcorrupt-"));
    writeFileSync(join(dir, "changes.json"), "[ {bad");
    const s = cmdStatus(dir, null, () => true);
    expect(s).toContain("changes.json is CORRUPT");
    expect(s).not.toContain("modified nothing on this system"); // the dangerous false claim
    expect(existsSync(join(dir, "quarantine"))).toBe(false); // a mere check never quarantines
  });

  test("a quarantined ledger keeps status from restoring 'modified nothing' after a heal", () => {
    // Reproduces the unwatch-on-corrupt regression: a mutating command quarantined
    // the corrupt ledger and wrote a fresh empty one — status must still not claim
    // beagle changed nothing, because it reverted nothing and the shims remain.
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-qtrail-"));
    mkdirSync(join(dir, "quarantine"), { recursive: true });
    writeFileSync(join(dir, "quarantine", "01ABCDEF-changes.json"), "corrupt-bytes");
    writeFileSync(join(dir, "changes.json"), "[]"); // valid, empty — the "healed" ledger
    const s = cmdStatus(dir, null, () => true);
    expect(s).not.toContain("modified nothing on this system");
    expect(s).toContain("quarantined");
  });

  test("a wrong-shape config.json (valid JSON, not an object) is surfaced, not shown as saved settings", () => {
    // Symmetric with the changes.json ledger: null/[]/scalar load as all-defaults,
    // which must not pass for the user's real settings.
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-cfgshape-"));
    writeFileSync(join(dir, "config.json"), "[]");
    expect(cmdStatus(dir, null, () => true)).toContain("config.json is corrupt");
  });

  test("search on a fresh install doesn't claim 'never sent' — nothing was captured", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-search-fresh-"));
    const out = cmdSearch(dir, "anything");
    expect(out).not.toContain("never sent"); // can't claim that with zero capture
    expect(out).toContain("no captured traffic yet");
    expect(out).toContain("beagle run"); // points the new user at the next step
  });

  test("daemon down + watched agents → starts-on-demand wording, not DIRECT", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-"));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([shimEntry(dir)]));
    const s = cmdStatus(dir, null, () => true);
    expect(s).toContain("starts on demand at the next watched-agent launch");
    expect(s).not.toContain("go DIRECT");
  });

  test("a service entry whose file is missing gets a warning with the fix", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-"));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      shimEntry(dir),
      { kind: "service", agent: null, path: join(dir, "beagle.service"), backup: "systemd" },
    ]));
    const s = cmdStatus(dir, null, () => true);
    expect(s).toContain("background service file is missing");
    expect(s).toContain("beagle watch opencode");
  });

  test("a service baked with a stale state dir gets the repair warning", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-"));
    const svcPath = join(dir, "beagle.service");
    writeFileSync(svcPath, systemdUnit2({ beagleBinary: "/b", stateDir: "/tmp/beagle-lease.STALE" }));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      shimEntry(dir),
      { kind: "service", agent: null, path: svcPath, backup: "systemd" },
    ]));
    const s = cmdStatus(dir, null, () => true);
    expect(s).toContain("/tmp/beagle-lease.STALE");
    expect(s).toContain("re-run `beagle watch opencode` to repair");
  });

  test("a healthy service produces no warning", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-"));
    const svcPath = join(dir, "beagle.service");
    writeFileSync(svcPath, systemdUnit2({ beagleBinary: "/b", stateDir: dir }));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      shimEntry(dir),
      { kind: "service", agent: null, path: svcPath, backup: "systemd" },
    ]));
    const s = cmdStatus(dir, null, () => true);
    expect(s).not.toContain("▲ background service");
  });

  test("a healthy but PAUSED service (beagle stop) gets the resume hint", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-status-"));
    const svcPath = join(dir, "beagle.service");
    writeFileSync(svcPath, systemdUnit2({ beagleBinary: "/b", stateDir: dir }));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      { kind: "shim", agent: "opencode", path: join(dir, "shims", "opencode"), backup: null },
      { kind: "service", agent: null, path: svcPath, backup: "systemd" },
    ]));
    const s = cmdStatus(dir, null, () => false); // service inactive
    expect(s).toContain("background service is paused");
    expect(s).toContain("beagle watch opencode");
  });
});

// findInstalledService's canonical fallback must be scoped to ITS state dir —
// a stop for a temp/test state dir once unloaded the REAL user service live.
import { findInstalledService } from "../src/cli/commands";

describe("findInstalledService scoping", () => {
  test("a temp state dir never claims a canonical unit baked for another dir", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-fis-"));
    // no manifest entry; the canonical unit (if any exists on this machine)
    // is baked for a DIFFERENT state dir → must return null, never that unit
    const found = findInstalledService(dir);
    expect(found).toBeNull();
  });

  test("a manifest entry wins regardless (unparseable unit we recorded is still ours)", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-fis-"));
    const svcPath = join(dir, "svc.plist");
    writeFileSync(svcPath, "unit");
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      { kind: "service", agent: null, path: svcPath, backup: "launchd" },
    ]));
    expect(findInstalledService(dir)).toEqual({ kind: "launchd", path: svcPath });
  });

  test("a manifest entry whose unit was RE-BAKED for another state dir is disowned", () => {
    // two state dirs shared the canonical slot; B re-baked the unit. A's stale
    // manifest entry must no longer claim it (else A's `stop` pauses B).
    const dir = mkdtempSync(join(tmpdir(), "beagle-fis-"));
    const svcPath = join(dir, "beagle.service");
    writeFileSync(svcPath, systemdUnit2({ beagleBinary: "/b", stateDir: "/some/other/state/dir" }));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      { kind: "service", agent: null, path: svcPath, backup: "systemd" },
    ]));
    expect(findInstalledService(dir)).toBeNull();
  });
});

// The stale-daemon warning must recommend the remedy that fits the install:
// `beagle stop` for a plain daemon (it refuses mid-capture; a raw kill doesn't),
// but `kill <pid>` for a service-managed one (launchd/systemd respawns it on the
// new binary; `beagle stop` would pause always-on until the next `beagle watch`).
import { staleDaemonRemedy } from "../src/cli/commands";

describe("staleDaemonRemedy", () => {
  test("plain daemon (no installed service) → beagle stop", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-remedy-"));
    const remedy = staleDaemonRemedy(dir, 4242);
    expect(remedy).toContain("beagle stop");
    expect(remedy).not.toContain("kill");
  });

  test("service-managed daemon → kill <pid>, not beagle stop", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-remedy-"));
    const unit = join(dir, "beagle.service");
    writeFileSync(unit, systemdUnit2({ beagleBinary: "/b", stateDir: dir }));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      { kind: "service", agent: null, path: unit, backup: "systemd" },
    ]));
    const remedy = staleDaemonRemedy(dir, 4242);
    expect(remedy).toContain("kill 4242");
    expect(remedy).not.toContain("beagle stop");
  });
});

// cmdStop must pause the always-on service (KeepAlive) or a stop silently
// becomes a restart — and report truthfully, verified via isActive.
import { cmdStop } from "../src/cli/commands";

describe("cmdStop — service pause", () => {
  function serviceFixture(): { dir: string; unit: string } {
    const dir = mkdtempSync(join(tmpdir(), "beagle-stop-"));
    const unit = join(dir, "beagle.service");
    writeFileSync(unit, systemdUnit2({ beagleBinary: "/b", stateDir: dir }));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      { kind: "service", agent: null, path: unit, backup: "systemd" },
    ]));
    return { dir, unit };
  }

  test("no daemon but an installed service → pauses it and says so", async () => {
    const { dir, unit } = serviceFixture();
    const deactivated: string[] = [];
    const out = await cmdStop(dir, false, {
      activate: () => {}, deactivate: (p) => deactivated.push(p.path), isActive: () => false,
    });
    expect(deactivated).toEqual([unit]); // the (c) fix — pause even with no daemon
    expect(out).toContain("Background service paused");
  });

  test("pause reports a WARNING when the service still reports active", async () => {
    const { dir } = serviceFixture();
    const out = await cmdStop(dir, false, {
      activate: () => {}, deactivate: () => {}, isActive: () => true, // deactivate didn't take
    });
    expect(out).toContain("WARNING");
    expect(out).not.toContain("Background service paused —");
  });

  test("no daemon and no service → plain message, runner never touched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-stop-"));
    const deactivated: string[] = [];
    const out = await cmdStop(dir, false, {
      activate: () => {}, deactivate: (p) => deactivated.push(p.path), isActive: () => false,
    });
    expect(out).toBe("no beagle daemon is running.");
    expect(deactivated).toEqual([]);
  });
});

// The "source ~/.zshrc" automation: a child process can never mutate its
// parent shell's PATH, so after an rc fix `beagle watch` offers a refreshed
// shell in place. TTY-gated so scripts and --yes runs never grow a subshell.
import { offerRefreshedShell } from "../src/cli/commands";

describe("offerRefreshedShell (post-rc-fix refreshed shell offer)", () => {
  test("non-TTY: never prompts, never spawns", async () => {
    let spawned = 0;
    const r = await offerRefreshedShell(false, "/bin/zsh",
      async () => { spawned++; },
      () => { throw new Error("must not read stdin without a TTY"); });
    expect(r).toBe(false);
    expect(spawned).toBe(0);
  });

  test("plain Enter takes the default — NO — and spawns nothing ([y/N])", async () => {
    // default-No, consistent with the two consent prompts above it; a reflexive
    // Enter must never grow a subshell
    let spawned = 0;
    const r = await offerRefreshedShell(true, "/bin/zsh",
      async () => { spawned++; }, () => "\n");
    expect(r).toBe(false);
    expect(spawned).toBe(0);
  });

  test("'y' accepts and spawns the user's shell", async () => {
    const spawnedWith: string[] = [];
    const r = await offerRefreshedShell(true, "/bin/zsh",
      async (sh) => { spawnedWith.push(sh); }, () => "y\n");
    expect(r).toBe(true);
    expect(spawnedWith).toEqual(["/bin/zsh"]);
  });

  test("'yes' accepts", async () => {
    let spawned = 0;
    const r = await offerRefreshedShell(true, "/bin/zsh",
      async () => { spawned++; }, () => "yes\n");
    expect(r).toBe(true);
    expect(spawned).toBe(1);
  });

  test("EOF (Ctrl-D → empty string) declines", async () => {
    let spawned = 0;
    const r = await offerRefreshedShell(true, "/bin/zsh",
      async () => { spawned++; }, () => ""); // readLineSync returns "" on EOF
    expect(r).toBe(false);
    expect(spawned).toBe(0);
  });

  test("a spawn failure (bogus $SHELL) is caught, not thrown — watch already succeeded", async () => {
    const r = await offerRefreshedShell(true, "/bin/zsh",
      async () => { throw new Error("ENOENT"); }, () => "y\n");
    expect(r).toBe(false); // swallowed, returns false rather than crashing the CLI
  });
});

// unwatch ergonomics: bare `beagle unwatch` picks from what's watched;
// --all is the "stop watching everything, keep my data" teardown.
import { cmdUnwatchAll, cmdUnwatchSelect, watchedAgents } from "../src/cli/commands";
import { mkdirSync } from "node:fs";

function watchedFixture(agents: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "beagle-unw-"));
  mkdirSync(join(dir, "shims"), { recursive: true });
  const entries = agents.map((a) => {
    const p = join(dir, "shims", a);
    writeFileSync(p, "#!/bin/sh\n");
    return { kind: "shim", agent: a, path: p, backup: null };
  });
  writeFileSync(join(dir, "changes.json"), JSON.stringify(entries));
  return dir;
}

describe("watchedAgents", () => {
  test("dedupes an agent that has BOTH a shim and a config-redirect entry", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-unw-"));
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      { kind: "shim", agent: "claude", path: join(dir, "s1"), backup: null },
      // opencode appears TWICE (shim + config-redirect) — must collapse to one,
      // or the picker would number the same agent twice
      { kind: "shim", agent: "opencode", path: join(dir, "s2"), backup: null },
      { kind: "config-redirect", agent: "opencode", path: join(dir, "c1"), backup: null },
      { kind: "config-backup", agent: "opencode", path: join(dir, "c2"), backup: null },
      { kind: "shellrc", agent: null, path: join(dir, "rc"), backup: null },
    ]));
    expect(watchedAgents(dir)).toEqual(["claude", "opencode"]);
  });
});

describe("cmdUnwatchAll", () => {
  test("nothing watched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-unw-"));
    expect(await cmdUnwatchAll(dir)).toBe("nothing is watched.");
  });

  test("removes every agent's shim and empties the manifest", async () => {
    const dir = watchedFixture(["claude", "opencode"]);
    const out = await cmdUnwatchAll(dir);
    expect(out).toContain("claude");
    expect(out).toContain("opencode");
    expect(existsSync(join(dir, "shims", "claude"))).toBe(false);
    expect(existsSync(join(dir, "shims", "opencode"))).toBe(false);
    expect(watchedAgents(dir)).toEqual([]);
  });

  test("one agent's failure is isolated — the rest still unwatch", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-unw-"));
    mkdirSync(join(dir, "shims"), { recursive: true });
    const backup = join(dir, "backup");
    writeFileSync(backup, "orig");
    const shimB = join(dir, "shims", "opencode");
    writeFileSync(shimB, "#!/bin/sh\n");
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      // codex's redirect restore targets a path whose PARENT dir is missing →
      // copyFileSync throws ENOENT inside unwatchAgent
      { kind: "config-redirect", agent: "codex", path: join(dir, "gone", "config"), backup },
      { kind: "shim", agent: "opencode", path: shimB, backup: null },
    ]));
    const out = await cmdUnwatchAll(dir);
    expect(out).toContain("failed to unwatch codex"); // isolated, not thrown
    expect(existsSync(shimB)).toBe(false); // opencode still unwatched
  });
});

describe("cmdUnwatchSelect (bare `beagle unwatch`)", () => {
  test("no TTY: prints the choices instead of hanging on a read", async () => {
    const dir = watchedFixture(["claude", "opencode"]);
    const out = await cmdUnwatchSelect(dir, false, false, () => {
      throw new Error("must not read stdin without a TTY");
    });
    expect(out).toContain("watched: claude, opencode");
    expect(watchedAgents(dir)).toEqual(["claude", "opencode"]); // untouched
  });

  test("single watched agent: plain yes/no", async () => {
    const dir = watchedFixture(["claude"]);
    await cmdUnwatchSelect(dir, false, true, () => "y\n");
    expect(watchedAgents(dir)).toEqual([]);
  });

  test("single watched agent: decline changes nothing", async () => {
    const dir = watchedFixture(["claude"]);
    const out = await cmdUnwatchSelect(dir, false, true, () => "\n");
    expect(out).toBe("cancelled — nothing changed.");
    expect(watchedAgents(dir)).toEqual(["claude"]);
  });

  test("pick by number", async () => {
    const dir = watchedFixture(["claude", "opencode"]);
    await cmdUnwatchSelect(dir, false, true, () => "2\n");
    expect(watchedAgents(dir)).toEqual(["claude"]);
  });

  test("pick by name", async () => {
    const dir = watchedFixture(["claude", "opencode"]);
    await cmdUnwatchSelect(dir, false, true, () => "claude\n");
    expect(watchedAgents(dir)).toEqual(["opencode"]);
  });

  test("'all' falls through to cmdUnwatchAll", async () => {
    const dir = watchedFixture(["claude", "opencode"]);
    await cmdUnwatchSelect(dir, false, true, () => "all\n");
    expect(watchedAgents(dir)).toEqual([]);
  });

  test("out-of-range number and garbage both cancel", async () => {
    const dir = watchedFixture(["claude", "opencode"]);
    expect(await cmdUnwatchSelect(dir, false, true, () => "7\n")).toBe("cancelled — nothing changed.");
    expect(await cmdUnwatchSelect(dir, false, true, () => "wat\n")).toBe("cancelled — nothing changed.");
    expect(watchedAgents(dir)).toEqual(["claude", "opencode"]);
  });
});

// main.ts unwatch routing + flag hygiene: the destructive sibling of watch
// must reject typos loudly and route --all / bare-invocation correctly.
import { run } from "../src/cli/main";

describe("main.ts unwatch dispatch", () => {
  const origEnv = process.env.BEAGLE_STATE_DIR;
  // `run(["unwatch"])` reads the ambient process.stdin.isTTY. Pin it FALSE so
  // these tests are deterministic wherever they run — under an interactive
  // `bun run check` (what CONTRIBUTING tells contributors to run), a real TTY
  // would route the bare `unwatch` into the picker and BLOCK on readLineSync.
  const origIsTTY = process.stdin.isTTY;
  let logs: string[];
  let errs: string[];
  const origLog = console.log;
  const origErr = console.error;
  beforeEach(() => {
    logs = []; errs = [];
    (process.stdin as { isTTY?: boolean }).isTTY = false;
    console.log = (...a: unknown[]) => { logs.push(a.join(" ")); };
    console.error = (...a: unknown[]) => { errs.push(a.join(" ")); };
  });
  function restore() {
    console.log = origLog; console.error = origErr;
    (process.stdin as { isTTY?: boolean }).isTTY = origIsTTY;
    if (origEnv === undefined) delete process.env.BEAGLE_STATE_DIR;
    else process.env.BEAGLE_STATE_DIR = origEnv;
  }
  // Unconditional restore: process.stdin.isTTY is a process-wide global, so a
  // future test that throws (or forgets a finally) must not leak isTTY=false
  // into other tests/files. afterEach runs regardless of pass/throw.
  afterEach(restore);

  test("an unknown flag is rejected with exit 2 (no state touched)", async () => {
    expect(await run(["unwatch", "--froce"])).toBe(2);
    expect(errs.join("\n")).toContain("unknown flag --froce");
  });

  test("--all with an agent is rejected with exit 2", async () => {
    expect(await run(["unwatch", "--all", "claude"])).toBe(2);
    expect(errs.join("\n")).toContain("takes no agent");
  });

  test("bare `unwatch` (no TTY) routes to the picker's choice list", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-maindispatch-"));
    mkdirSync(join(dir, "shims"), { recursive: true });
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      { kind: "shim", agent: "opencode", path: join(dir, "shims", "opencode"), backup: null },
    ]));
    process.env.BEAGLE_STATE_DIR = dir;
    // isTTY pinned false (beforeEach) → picker prints choices, never prompts
    expect(await run(["unwatch"])).toBe(0);
    expect(logs.join("\n")).toContain("watched: opencode");
  });

  test("`unwatch --all` routes to cmdUnwatchAll and removes every shim", async () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-maindispatch-"));
    mkdirSync(join(dir, "shims"), { recursive: true });
    writeFileSync(join(dir, "shims", "opencode"), "#!/bin/sh\n");
    writeFileSync(join(dir, "changes.json"), JSON.stringify([
      { kind: "shim", agent: "opencode", path: join(dir, "shims", "opencode"), backup: null },
    ]));
    process.env.BEAGLE_STATE_DIR = dir;
    expect(await run(["unwatch", "--all"])).toBe(0);
    expect(existsSync(join(dir, "shims", "opencode"))).toBe(false);
  });
});
