// CLI command surface (design §6.9): the whole product headless. Reads open
// the store read-only (work daemon-down); live actions ride the socket.
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, rmdirSync, rmSync, statSync } from "node:fs";
import { join, resolve as resolvePath } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { Store, StoreVersionError } from "../core/store/store";
import { loadConfig, readConfig, saveConfig } from "../core/config/config";
import { loadJsonFile } from "../core/fs/durable";
import { controlRequest, openLease } from "../daemon/control";
import { Notifier, stripControlChars } from "../notifier/notifier";
import { GraduationTracker } from "../install/graduation";
import { claudeAuthMode, codexAuthMode, detectAgents, knownExtraLocations, pathDirsFromEnv } from "../install/detect";
import { watchAgent, unwatchAgent, type WatchEnv, type WatchModeRequest } from "../install/watch";
import { ChangeManifest } from "../install/manifest";
import { osServiceRunner, servicePlan, serviceStateDir, type ServiceKind, type ServiceRunner } from "../install/service";
import { listLeakEvents } from "../viewer/feed-query";
import { sessionHeadlines } from "../viewer/session-view";
import { buildDetail, leakSpansFor, leakTypesFor } from "../viewer/detail";
import { secretName } from "../notifier/alert-copy";
import { clampRedacted } from "../transform/redact";
import { buildCodexOtelArgs, buildCodexOtelEnv, buildHookSettings, buildOtelEnv, mergeHookIntoSettings } from "../parsers/otlp-map";
import { codexSessionsRoot } from "../adapters/codex-rollout-tailer";
import { buildExtensionRedirect, buildRedirectConfig, readFirstConfig, writeRedirectConfig, writeRedirectExtension } from "../install/config-redirect";
import { AGENTS, buildRunEnv, runBaseUrl } from "./agents";
import { BEAGLE_VERSION } from "../core/version";

// Everything printed by these commands can embed traffic-derived text
// (summaries, session ids from parsed content) — sanitize at the boundary,
// the terminal-escape-injection rule from design §6.10.
const clean = stripControlChars;

export function defaultStateDir(): string {
  if (process.env.BEAGLE_STATE_DIR) return process.env.BEAGLE_STATE_DIR;
  const base = process.env.XDG_STATE_HOME ?? join(homedir(), ".local", "state");
  return join(base, "beagle");
}

// Opens the store read-only, or returns the plain-language problem: version
// mismatches must never surface as a stack trace on the trust-critical
// surfaces (search/leaks/show) — design §4.
function openStore(stateDir: string): Store | null | { error: string } {
  if (!existsSync(join(stateDir, "beagle.db"))) return null;
  try {
    return Store.openReadOnly(stateDir);
  } catch (e) {
    if (e instanceof StoreVersionError) return { error: e.message };
    throw e;
  }
}

function isStoreError(s: Store | null | { error: string }): s is { error: string } {
  return s !== null && "error" in s;
}

interface DaemonInfo {
  pid: number;
  proxyPort: number;
  socketPath: string;
  runningVersion?: string; // from the ping handshake, not daemon.json
  // Why the daemon is up, from the control status call (status command only).
  leases?: number;
  viewerOpen?: boolean;
  persistent?: boolean;
}

function readDaemonInfo(stateDir: string): DaemonInfo | null {
  try {
    return JSON.parse(readFileSync(join(stateDir, "daemon.json"), "utf8")) as DaemonInfo;
  } catch {
    return null;
  }
}

async function pingDaemon(stateDir: string): Promise<DaemonInfo | null> {
  const info = readDaemonInfo(stateDir);
  if (!info) return null;
  try {
    const r = await controlRequest(info.socketPath, { cmd: "ping" }, 800);
    if (!r.ok) return null;
    const version = (r.data as { version?: string } | undefined)?.version;
    return { ...info, runningVersion: version };
  } catch {
    return null;
  }
}

// The "Restart it:" remedy for a stale (old-version) running daemon. It differs
// by install: a service-managed daemon should be plain-killed so launchd/systemd
// respawns it from the new binary — `beagle stop` would instead pause always-on
// until the next `beagle watch`. A plain daemon gets `beagle stop`, which (unlike
// a raw kill) refuses while a capture is live. Service detection reads files and
// can throw; since this only feeds a non-fatal advisory, a failure falls back to
// the plain-daemon remedy rather than crash `beagle run`/`beagle ui`.
export function staleDaemonRemedy(stateDir: string, pid: number): string {
  let serviceManaged = false;
  try {
    serviceManaged = findInstalledService(stateDir) !== null;
  } catch {
    // detection I/O failed — treat as plain; advice must never abort the run.
  }
  return serviceManaged
    ? `kill ${pid}   (the service respawns it from the new binary)`
    : `beagle stop   (the next 'beagle run' starts a fresh one on the new binary)`;
}

// Ensure a daemon is up, spawning one if needed. Shared by run and ui.
async function ensureDaemon(stateDir: string): Promise<DaemonInfo | null> {
  let daemon = await pingDaemon(stateDir);
  if (daemon) {
    // A daemon left running from an OLD binary (persistent / service unit)
    // won't have this build's fixes — it's the one parsing upstreams,
    // registering runs, and scanning. Warn (don't force-restart: it may be
    // serving other agents right now) with the exact remedy.
    if (daemon.runningVersion && daemon.runningVersion !== BEAGLE_VERSION) {
      process.stderr.write(
        `beagle ▲ the running daemon is v${daemon.runningVersion} but this beagle is v${BEAGLE_VERSION} — ` +
          `it won't have this version's fixes until restarted.\n` +
          `  Restart it: ${staleDaemonRemedy(stateDir, daemon.pid)}\n`,
      );
    }
    return daemon;
  }
  // Compiled binary: argv[1] is not a script path — invoke ourselves
  // directly. Dev (bun run): re-run the entry script.
  const script = process.argv[1];
  const argv =
    script && /\.(ts|js|mjs)$/.test(script)
      ? [process.execPath, script, "daemon"]
      : [process.execPath, "daemon"];
  // Send the daemon's stderr to a log file rather than /dev/null, so a startup
  // failure (store init, listener bind, scanner spawn) leaves a trace instead
  // of an unexplained "monitoring unavailable" after a 4 s wait.
  const logPath = join(stateDir, "daemon.log");
  let errStdio: number | "ignore" = "ignore";
  try {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    errStdio = openSync(logPath, "a", 0o600);
  } catch {
    /* couldn't open the log — fall back to discarding, never block the run */
  }
  const child = Bun.spawn(argv, {
    // BEAGLE_EPHEMERAL: this auto-started daemon idle-exits once no agent
    // holds a lease and no viewer is open (§6.7), so a trial run leaves
    // nothing behind. An explicit `beagle daemon` or the service unit does not
    // set it and stays up.
    env: { ...process.env, BEAGLE_STATE_DIR: stateDir, BEAGLE_EPHEMERAL: "1" },
    stdio: ["ignore", "ignore", errStdio],
  });
  child.unref();
  if (typeof errStdio === "number") closeSync(errStdio); // the child holds its own dup
  for (let i = 0; i < 40 && !daemon; i++) {
    await Bun.sleep(100);
    daemon = await pingDaemon(stateDir);
  }
  if (!daemon) {
    const tail = daemonLogTail(logPath);
    process.stderr.write(
      `beagle ▲ the background monitor didn't come up` +
        (tail ? ` — its last output:\n${tail}\n` : `; no output was captured (see ${logPath}).\n`),
    );
  }
  return daemon;
}

/** Last few lines of the daemon log — surfaced when startup fails so the user
 *  sees the real cause, not a generic "unavailable". Bounded, best-effort. */
function daemonLogTail(path: string, lines = 15): string {
  try {
    return readFileSync(path, "utf8").trimEnd().split("\n").slice(-lines).join("\n");
  } catch {
    return "";
  }
}

// Two-column trust strip: an 11-char label gutter, values (and their wrapped
// continuations) aligned after it, blank lines between the three groups —
// coverage, what's stored, what beagle touched. Emits no ANSI escapes of its
// own and interpolates no captured traffic, which is why (unlike cmdShow) it
// needs no clean() pass.
const STATUS_GUTTER = 11;

// Why the daemon is up, or null when we cannot know — an older daemon answers
// `status` without these fields, and the enrich call may fail after ping
// already proved it running. On a strip where every claim must be true,
// unknown gets no line rather than a guessed one. `persistent` is the
// discriminator: only a daemon that reports it speaks this protocol.
function daemonWhy(d: DaemonInfo): string | null {
  if (d.persistent === undefined) return null;
  // persistent means "never idle-exits" — that covers the installed service
  // AND a hand-run `beagle daemon`, and nothing distinguishes them from here,
  // so say only what is true of both. (An installed service is disclosed by
  // the changes row.)
  if (d.persistent) return "always on — it will not wind down by itself; `beagle stop` stops it";
  const holds: string[] = [];
  const n = d.leases ?? 0;
  if (n > 0) holds.push(`${n} live session${n === 1 ? "" : "s"}`);
  if (d.viewerOpen) holds.push("an open dashboard");
  return holds.length
    ? `up for: ${holds.join(" · ")} — winds down after they end`
    : "idle — winds down within a few minutes";
}

// True if codex has written any session logs under `dir` — the source Beagle
// reads codex's assistant replies from (its OTel self-report omits them). A lone
// dotfile (e.g. a macOS .DS_Store) doesn't count as a real session log.
function hasCodexSessionLogs(dir: string): boolean {
  try {
    return existsSync(dir) && readdirSync(dir).some((name) => !name.startsWith("."));
  } catch {
    return false;
  }
}

export function cmdStatus(
  stateDir: string,
  daemonUp: DaemonInfo | null = null,
  // Injectable so tests don't shell out to launchctl/systemctl.
  isServiceActive: (kind: ServiceKind, path: string) => boolean = (kind, path) =>
    osServiceRunner.isActive?.({ kind, path }) ?? true,
  // codex's rollout-log root (the source of codex replies); injectable for tests.
  // Single source of truth is the tailer, so status looks where the daemon reads.
  codexSessions: string = codexSessionsRoot(),
): string {
  const row = (label: string, text: string) => label.padEnd(STATUS_GUTTER) + text;
  const cont = (text: string) => " ".repeat(STATUS_GUTTER) + text;
  const lines: string[] = [];

  const manifest = new ChangeManifest(stateDir);
  const watchedEntries = manifest.list().filter((e) => e.kind === "shim" || e.kind === "config-redirect");
  if (daemonUp) {
    lines.push(row("daemon", `running — pid ${daemonUp.pid} · proxy 127.0.0.1:${daemonUp.proxyPort}`));
    // Say WHY it is running, so nobody has to wonder when it will go away.
    const why = daemonWhy(daemonUp);
    if (why) lines.push(cont(why));
  } else if (watchedEntries.length > 0) {
    // With shims installed, "not running" is a between-sessions state, not a
    // coverage gap: the shim starts the daemon when the agent launches. (The
    // background service should keep one alive anyway — a warning below says
    // so if it can't.)
    lines.push(row("daemon", "not running — starts on demand at the next watched-agent launch (or `beagle ui`)"));
  } else {
    lines.push(row("daemon", "not running — new agent sessions go DIRECT (unmonitored)"));
  }
  // The background service's one job is keeping a daemon alive for THIS state
  // dir. An installed unit that is missing or baked with a different state
  // dir silently un-does the "always on" promise — say so, with the fix.
  const svcEntry = manifest.list().find((e) => e.kind === "service");
  if (svcEntry && watchedEntries.length > 0) {
    const agentHint = watchedEntries[0]?.agent ?? "<agent>";
    if (!existsSync(svcEntry.path)) {
      lines.push(cont(`▲ background service file is missing — re-run \`beagle watch ${agentHint}\` to reinstall`));
    } else {
      const baked = serviceStateDir(readFileSync(svcEntry.path, "utf8"));
      if (baked !== null && resolvePath(baked) !== resolvePath(stateDir)) {
        lines.push(
          cont(`▲ background service keeps a daemon alive for ${stripControlChars(baked)} (a stale/test path),`),
          cont(`  not this store — re-run \`beagle watch ${agentHint}\` to repair it`),
        );
      } else if (!isServiceActive((svcEntry.backup as ServiceKind) ?? "systemd", svcEntry.path)) {
        lines.push(
          cont(`▲ background service is paused (e.g. by \`beagle stop\`) — re-run \`beagle watch ${agentHint}\` to resume always-on`),
        );
      }
    }
  }
  lines.push("");

  const store = openStore(stateDir);
  if (isStoreError(store)) return lines.concat(store.error).join("\n");
  const calls = store?.countCalls() ?? 0;
  const leaks = store?.countLeakEvents() ?? 0;
  // Agent-reported (Mode B) calls carry a known content gap — disclose it here
  // (R2, spike criterion #2) whenever any exist, not just in the docs.
  // One pass over exchanges: total agent-reported (Mode B) rows, and the codex
  // subset — codex's answer is recovered from the rollout log, so a missing log
  // is a codex-only capture gap worth surfacing below. (SUM over a bool expr is
  // SQLite's conditional count; NULL only when the table is empty.)
  const otelCounts = store?.queryAll<{ otel: number | null; codex: number | null }>(
    `SELECT SUM(source='otel') AS otel,
            SUM(source='otel' AND agent='codex') AS codex
     FROM exchanges`,
  )[0];
  const otelCalls = otelCounts?.otel ?? 0;
  const codexOtelCalls = otelCounts?.codex ?? 0;
  store?.close();
  const dbPath = join(stateDir, "beagle.db");
  const sizeMb = existsSync(dbPath) ? (statSync(dbPath).size / (1 << 20)).toFixed(1) : "0.0";
  const cfg = readConfig(stateDir); // read-only: status must not create config.json

  lines.push(
    row("leaks", leaks === 0
      ? "none detected"
      : `${leaks} detected — see \`beagle leaks\``),
  );
  if (calls === 0) {
    lines.push(row("captured", "nothing yet — wrap an agent with `beagle run <agent>`"));
  } else {
    lines.push(row("captured", `${calls} call${calls === 1 ? "" : "s"} · ${sizeMb} MB store`));
    if (otelCalls > 0) {
      // Wrapped by clause, not by width: each continuation line is a complete
      // thought, so the indented block reads as two statements, not a broken one.
      lines.push(cont(`${otelCalls} agent-reported (Mode B): captured from the agent's self-report`));
      lines.push(cont("prompts and tool data still scanned · alerts can lag a few seconds"));
    }
    // Codex's self-report omits the model's reply; Beagle recovers it from the
    // rollout log. If that log is absent, the reply can't be captured — flag it
    // (with the path, so a wrong CODEX_HOME is self-diagnosing) rather than
    // leave the turn silently answer-less.
    if (codexOtelCalls > 0 && !hasCodexSessionLogs(codexSessions)) {
      lines.push(cont(`▲ codex replies unavailable — no session logs in ${codexSessions} (is codex history logging on?)`));
    }
  }
  lines.push(
    row("retention", `payloads ${cfg.payloadWindowDays} days / ${cfg.sizeCapMB} MB · leak events ${cfg.eventWindowDays} days`),
  );
  // A damaged config.json loads as safe defaults so the daemon never crashes —
  // but the user must not mistake those defaults for their saved settings.
  // "Damaged" is both unparseable JSON AND valid-JSON-of-the-wrong-shape
  // (null/scalar/array), which sanitizeConfig silently flattens to all-defaults;
  // the shape test mirrors that guard so config matches the ledger's treatment.
  const cfgLoad = loadJsonFile(join(stateDir, "config.json"));
  const configDamaged =
    cfgLoad.status === "corrupt" ||
    (cfgLoad.status === "ok" &&
      (cfgLoad.value === null || typeof cfgLoad.value !== "object" || Array.isArray(cfgLoad.value)));
  if (configDamaged) {
    lines.push(cont("▲ config.json is corrupt — the retention/redaction above are safe DEFAULTS, not your"));
    lines.push(cont("  saved settings; remove the file, or run `beagle config …` to rewrite it"));
  }
  lines.push("");

  // The ledger's corruption must stay visible even after a mutating command
  // quarantined the bad file and wrote a fresh one — otherwise `beagle unwatch`
  // on a corrupt ledger reverts nothing yet restores the reassuring "modified
  // nothing". A quarantined `*-changes.json` is that lasting signal.
  const qdir = join(stateDir, "quarantine");
  const quarantinedLedgers = existsSync(qdir)
    ? readdirSync(qdir).filter((n) => n.endsWith("-changes.json")).length
    : 0;
  lines.push(
    row("changes", manifest.corrupt
      ? "▲ changes.json is CORRUPT — cannot account for what beagle changed on this system"
      : manifest.list().length > 0
        ? `${manifest.summary()} — \`beagle unwatch <agent>\` reverts them`
        : quarantinedLedgers > 0
          ? "▲ change ledger was corrupt and quarantined — cannot vouch beagle changed nothing"
          : "none — beagle has modified nothing on this system"),
  );
  if (manifest.corrupt || quarantinedLedgers > 0) {
    lines.push(cont("  a corrupt change record was found — `beagle uninstall`/`unwatch` may not fully"));
    lines.push(cont("  reverse prior changes; check PATH shims and any service unit by hand"));
  }
  lines.push(row("privacy", "local only — outbound traffic is just your agents' own model calls"));
  lines.push(cont("no telemetry · viewer off until requested"));
  return lines.join("\n");
}

export function cmdSearch(stateDir: string, term: string): string {
  const store = openStore(stateDir);
  if (isStoreError(store)) return store.error;
  if (!store) {
    // No store = nothing captured yet. Don't claim "never sent" — Beagle has
    // observed no traffic and can't make that claim (finding: misleading on a
    // fresh install where a user is checking whether monitoring works).
    return "no captured traffic yet — nothing has been recorded to search.\nWrap a session with `beagle run <agent>` first, then search.";
  }
  const hits = store.searchLiteral(term);
  store.close();
  if (hits.length === 0) return "no matches — not in any captured call still in the store (payloads are pruned on a rolling window, so this isn't proof it was never sent).";
  const sessions = new Set(hits.map((h) => h.sessionId));
  const lines = [
    `found in ${hits.length} call${hits.length === 1 ? "" : "s"} across ${sessions.size} session${sessions.size === 1 ? "" : "s"}:`,
  ];
  for (const h of hits) {
    lines.push(`  ${h.callId.slice(0, 8)}  ${new Date(h.tsRequest).toISOString()}  session ${clean(h.sessionId).slice(0, 8)}`);
  }
  return lines.join("\n");
}

// Local, compact time ("Jul 13, 4:31 PM") — the leak log is read by a human
// deciding what to do next, not by a log parser; ISO-UTC belongs in exports.
function fmtWhen(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
  });
}

// A session's display title from its opening summary — same transform as the
// dashboard's sessionTitle() in app.js (duplicated: the buildless viewer
// can't share modules with the CLI, so keep the two in step). First strip the
// "what the agent sent" suffix buildSummary appends (— to "…" / — after N tool
// results) — feed/CLI context, not a title — then unwrap Claude Code's
// title-generation turn whose summary is literally {"title":"…"}.
function unwrapTitle(raw: string | undefined): string {
  let t = (raw ?? "").trim();
  // 200, not firstLine's 40: a redaction placeholder straddling that cap is run
  // past whole rather than cut in half, so the ask can reach 38 + clampRedacted's
  // 128-char overshoot ceiling + the ellipsis = 167. Bounded, but well over 40 —
  // and a tighter bound here would silently stop matching, dropping the title
  // back to the whole `"ask" → got` line on exactly the leak rows that matter.
  let m = t.match(/^"([^"]{1,200})" → [\s\S]*$/);
  if (m) t = m[1]!;
  else if ((m = t.match(/^\d+ [A-Za-z_][\w.-]{0,40} results? → ([\s\S]*)$/))) t = m[1]!;
  else t = t.replace(/^([\s\S]*) — (?:to "[^"]{0,80}"|after \d+ [A-Za-z_][\w.-]{0,40} results?)$/, "$1");
  t = t.trim();
  if (t.startsWith("{")) {
    try {
      const o = JSON.parse(t) as { title?: unknown };
      if (o && typeof o.title === "string") return o.title.trim();
    } catch { /* not a JSON title wrapper — use as-is */ }
  }
  return t;
}

export function cmdLeaks(stateDir: string): string {
  const store = openStore(stateDir);
  if (isStoreError(store)) return store.error;
  if (!store) return "no captured traffic yet — nothing has been scanned for leaks.\nWrap a session with `beagle run <agent>` first.";
  const events = listLeakEvents(store);
  if (events.length === 0) {
    store.close();
    return "no detected leaks in the captured traffic.";
  }

  // Group by session: one conversation is one incident to a human, and the
  // session is the unit the dashboard (and its per-session delete) works in.
  const bySession = new Map<string, typeof events>();
  for (const e of events) {
    const g = bySession.get(e.sessionId) ?? [];
    g.push(e);
    bySession.set(e.sessionId, g);
  }
  const groups = [...bySession.entries()].sort(
    (a, b) => Math.max(...b[1].map((e) => e.lastTs)) - Math.max(...a[1].map((e) => e.lastTs)),
  );

  // One query for every group's headline, not one per session.
  const headlines = sessionHeadlines(store, groups.map(([sid]) => sid));

  const lines = [
    `${events.length} leak event${events.length === 1 ? "" : "s"} across ` +
      `${groups.length} session${groups.length === 1 ? "" : "s"} — newest first:`,
  ];
  for (const [sessionId, group] of groups) {
    const head = headlines.get(sessionId) ?? {};
    const full = clean(unwrapTitle(head.title));
    // Cap the headline: stored summaries can run a sentence long, and the
    // title only needs to identify the conversation. clampRedacted, not a bare
    // slice — this is the leak log, where cutting a placeholder in half would
    // stump the one thing the line is about right where it names the type.
    const capped = full.length > 64 ? clampRedacted(full, 63) : full;
    const title = (capped.length < full.length ? capped + "…" : full) || "(untitled session)";
    const agent = head.agent ? clean(head.agent) : "unknown agent";
    lines.push("", `  ${title} — ${agent} · session ${clean(sessionId)}`);
    for (const e of group) {
      const tier = e.confidenceTier === "structured" ? "" : " (possible)";
      // Full call id: ULIDs minted in the same millisecond share their first
      // 8 chars, so a short prefix can be ambiguous to `beagle show`.
      lines.push(
        `      ${fmtWhen(e.firstTs)}   ${secretName(clean(e.secretType))}${tier} → ${clean(e.destination)}` +
          `   ×${e.occurrences}${e.firstCall ? `   call ${clean(e.firstCall)}` : ""}`,
      );
    }
  }
  store.close();
  lines.push(
    "",
    "open a session in the dashboard: beagle ui --session <id>",
    "inspect one call here in the terminal: beagle show <call-id>",
  );
  return lines.join("\n");
}

function fmtBytes(n?: number): string {
  if (n == null) return "?";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// Clip long captured content in the readable view so one giant message (a
// pasted file, a huge system prompt) can't bury the rest. --full / --raw show
// everything.
function clip(s: string, max = 4000): string {
  return s.length <= max ? s : `${s.slice(0, max)} …(+${s.length - max} more chars)`;
}

// How this call was grouped into its session, in plain words — mirrors
// groupedBy() in the dashboard (app.js) so both surfaces say the same thing.
function groupedByPhrase(tier: string): string {
  switch (tier) {
    case "conv-id": return "the request's conversation id";
    case "prefix": return "matching message history";
    case "compaction-link": return "history matched across a compaction (medium confidence)";
    case "run": return "the same run, no history match (lower confidence)";
    case "time-gap": return "recent activity — a best guess (low confidence)";
    default: return tier;
  }
}

export interface ShowOptions { full?: boolean; raw?: boolean }

const likePrefix = (p: string) => p.replace(/[\\%_]/g, (c) => `\\${c}`) + "%";

export function cmdShow(stateDir: string, idPrefix: string, opts: ShowOptions = {}): string {
  const store = openStore(stateDir);
  if (isStoreError(store)) return store.error;
  if (!store) return `no call matches '${clean(idPrefix)}' — nothing captured yet.`;
  // Resolve the prefix ourselves so each miss gets an honest, specific answer.
  // ULIDs minted in the same millisecond share their first 8 characters, so a
  // short prefix (from a burst of calls) can legitimately match several.
  const matches = store.queryAll<{ id: string }>(
    `SELECT id FROM exchanges WHERE id LIKE ? ESCAPE '\\' ORDER BY id LIMIT 11`,
    [likePrefix(idPrefix)],
  );
  if (matches.length === 0) {
    store.close();
    return (
      `no call matches '${clean(idPrefix)}' — it may have been deleted with its session,\n` +
      `or aged out by retention (leak records outlive calls; they stay in \`beagle leaks\`).`
    );
  }
  if (matches.length > 1) {
    store.close();
    const shown = matches.slice(0, 10);
    return [
      `${matches.length > 10 ? "10+" : matches.length} calls match '${clean(idPrefix)}' — use more of the id:`,
      // clean() even these: ids are beagle-minted ULIDs today, but everything
      // printed from the store goes through the §6.10 boundary, no exceptions.
      ...shown.map((m) => `  ${clean(m.id)}`),
      ...(matches.length > 10 ? ["  …"] : []),
    ].join("\n");
  }
  const call = store.getCall(matches[0]!.id);
  if (!call) {
    store.close();
    return `no call matches '${clean(idPrefix)}'.`;
  }
  const spans = leakSpansFor(store, call.id);
  // Leak EVENTS, not spans: a span-less occurrence (v1-era row) must still
  // flag — this line must never read "clean" for a call that leaked.
  const leakTypes = leakTypesFor(store, call.id);
  store.close();
  const d = buildDetail(call, spans);

  // Same words as the dashboard's detail view: "✓ observed" / "self-reported"
  // provenance, errors only when they are errors, "grouped by" in plain
  // English. Endpoint/size/tier live behind --full, like the ▸ technical fold;
  // the run id is shown nowhere (nothing a user can do takes one).
  const prov = call.source === "wire" ? "✓ observed" : "self-reported";
  const err = call.status != null && call.status >= 400 ? ` · error ${call.status}` : "";
  const toks = call.tokensIn != null || call.tokensOut != null
    ? ` · ${call.tokensIn ?? "?"} → ${call.tokensOut ?? "?"} tokens`
    : "";
  const lines = [
    `call ${call.id}   ${prov}${err}`,
    `  ${clean(call.agent ?? "?")} → ${clean(call.provider ?? "?")}${call.model ? ` · ${clean(call.model)}` : " · no model"}`,
    `  ${fmtWhen(call.tsRequest)}${toks}`,
    `  session ${clean(call.sessionId)} · grouped by ${groupedByPhrase(clean(call.sessionTier))}`,
  ];
  if (call.redacted) lines.push("  secrets masked in storage (redact-on-capture)");
  if (opts.full) {
    lines.push(
      `  technical: ${clean(call.endpoint ?? "?")} · ${fmtBytes(call.bytesReq)} sent · ` +
        `${fmtBytes(call.bytesResp)} received · grouping tier ${clean(call.sessionTier)}`,
    );
  }

  // The headline for a security tool: did this call leak, and what.
  if (leakTypes.length > 0) {
    const tiers = new Map<string, string>();
    for (const l of leakTypes) {
      if (!tiers.has(l.secretType) || l.tier === "structured") tiers.set(l.secretType, l.tier);
    }
    // clean() the rendered names too — §6.10 applies to every printed string.
    const names = [...tiers].map(
      ([t, tier]) => clean(secretName(t)) + (tier === "structured" ? "" : " (possible)"),
    );
    lines.push(
      "",
      `  🔴 ${names.length} secret${names.length === 1 ? "" : "s"} sent to ${clean(call.provider ?? "?")}: ${names.join(", ")}`,
    );
  }
  lines.push("", `  summary: ${clean(call.summary ?? "—")}`);

  if (opts.raw) {
    lines.push("", "── request (raw) ──", clean(d.requestRaw || "(empty)"));
    lines.push("", "── response (raw) ──", clean(d.responseRaw || "(empty)"));
    if (d.sseRaw) lines.push("", "── raw stream (as received) ──", clean(d.sseRaw));
  } else {
    lines.push("", "  sent —");
    if (d.system != null) {
      lines.push(opts.full
        ? `    system:\n${clean(d.system)}`
        : `    system · ${d.system.length} chars (--full to show)`);
    }
    const msgs = d.messages ?? [];
    if (msgs.length === 0) {
      lines.push("    (no parsed request content — --raw for the exact bytes)");
    } else if (opts.full) {
      for (const m of msgs) lines.push(`    ${clean(m.role)}: ${clean(m.content)}`);
    } else {
      if (msgs.length > 1) lines.push(`    (${msgs.length - 1} earlier message${msgs.length - 1 === 1 ? "" : "s"} — --full to show)`);
      const last = msgs.at(-1)!;
      lines.push(`    ${clean(last.role)}: ${clip(clean(last.content))}`);
    }
    lines.push("", "  received —");
    lines.push(d.responseText != null
      ? `    ${opts.full ? clean(d.responseText) : clip(clean(d.responseText))}`
      : "    (no readable response captured — --raw for the exact bytes)");
  }

  // Same wording as the dashboard's warnings.
  if (call.scanState !== "ok") {
    lines.push("", "  ⚠ scan incomplete — this body was not fully verified, not marked clean");
  }
  if (call.captureState !== "ok") {
    lines.push("  ⚠ capture truncated — the stored bytes are incomplete");
  }
  if (!opts.raw && !opts.full) {
    // Full session id here — the dashboard deep link matches it exactly.
    lines.push(
      "",
      "  --full for every message · --raw for exact bytes",
      `  beagle ui --session ${clean(call.sessionId)}   (the whole conversation)`,
    );
  }
  return lines.join("\n");
}

export async function cmdPurge(stateDir: string, kind: string): Promise<string> {
  const daemon = await pingDaemon(stateDir);
  if (daemon) {
    // Panic purge VACUUMs the whole file — allow it time.
    const r = await controlRequest(daemon.socketPath, { cmd: "purge", args: { kind } }, 60_000);
    return r.ok ? `purged (${kind}).` : `purge failed: ${r.error}`;
  }
  if (!existsSync(join(stateDir, "beagle.db"))) return "nothing to purge.";
  const store = Store.open(stateDir);
  if (kind === "panic") store.panicPurge();
  else store.purge({ kind: "all" });
  store.close();
  return `purged (${kind}).`;
}

/** Stop the running beagle daemon (graceful, via its control socket). An
 *  agent mid-capture holds a lease — refuse then, unless forced, so stopping
 *  can't silently drop a live session's capture. */
/** The installed background service, from the manifest OR the canonical path
 *  (an orphaned unit — recorded by an older run whose manifest was since
 *  emptied — is still real and still resurrects daemons). The canonical
 *  fallback is SCOPED: it claims the unit only when its baked state dir is
 *  THIS one — a `beagle stop` for a temp/test state dir must never touch the
 *  real install's service (a live test run did exactly that before this gate). */
export function findInstalledService(
  stateDir: string,
): { kind: ServiceKind; path: string } | null {
  const entry = new ChangeManifest(stateDir).list().find((e) => e.kind === "service");
  if (entry && existsSync(entry.path)) {
    // Scope like the canonical fallback: if the unit has since been re-baked
    // for a DIFFERENT state dir (another install re-took the shared canonical
    // slot), it's no longer ours to pause/remove. A unit we can't parse but
    // that WE recorded is still ours (baked === null → keep).
    const baked = serviceStateDir(readFileSync(entry.path, "utf8"));
    if (baked === null || resolvePath(baked) === resolvePath(stateDir)) {
      return { kind: (entry.backup as ServiceKind) ?? "systemd", path: entry.path };
    }
    return null;
  }
  const plan = servicePlan(process.platform, homedir(), process.execPath, stateDir);
  if (plan && existsSync(plan.path)) {
    const baked = serviceStateDir(readFileSync(plan.path, "utf8"));
    if (baked !== null && resolvePath(baked) === resolvePath(stateDir)) {
      return { kind: plan.kind, path: plan.path };
    }
  }
  return null;
}

export async function cmdStop(
  stateDir: string,
  force = false,
  runner: ServiceRunner = osServiceRunner,
): Promise<string> {
  // Act on OBSERVED reality, not bookkeeping: an orphaned unit at the canonical
  // path (manifest emptied by an older CLI's unwatch, etc.) must still be paused
  // or KeepAlive wins and stop is a silent restart.
  const svc = findInstalledService(stateDir);
  // Pause the always-on service and REPORT truthfully — verify with isActive
  // (deactivate is best-effort spawnQuiet) rather than assuming it worked.
  const pauseService = (): string => {
    if (!svc) return "";
    runner.deactivate(svc);
    const paused = runner.isActive ? !runner.isActive(svc) : true;
    return paused
      ? `\nBackground service paused — always-on resumes at the next \`beagle watch\` (shims still start a daemon on demand).`
      : `\nWARNING: tried to pause the background service but it still reports active — check \`beagle status\`.`;
  };

  const daemon = await pingDaemon(stateDir);
  if (!daemon) {
    // No daemon now — but an always-on service resurrects one within seconds,
    // so a stop that leaves it enabled is a silent no-op. Pause it anyway.
    return svc ? `no daemon was running.${pauseService()}` : "no beagle daemon is running.";
  }

  // Authoritative lease check right before we touch anything. If the daemon's
  // status can't be read we CANNOT confirm it's safe to pause the service
  // (whose teardown SIGTERMs the daemon lease-unaware) — refuse unforced
  // rather than risk dropping a live capture.
  let leases: number | null;
  try {
    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    leases = status.ok ? ((status.data as { leases?: number } | undefined)?.leases ?? 0) : null;
  } catch {
    leases = null;
  }
  if (!force && leases === null) {
    return "couldn't confirm capture state from the daemon — not stopping. Retry, or force with: beagle stop --force";
  }
  if (!force && leases! > 0) {
    return (
      `the daemon is capturing for ${leases} live agent session${leases === 1 ? "" : "s"} — ` +
      `stopping now would drop that capture.\nFinish those sessions first, or force with: beagle stop --force`
    );
  }

  // Pause the KeepAlive service FIRST (its teardown also kills the managed
  // daemon; leaving it enabled resurrects the daemon we're about to stop).
  // Leases were just confirmed 0 (or forced).
  const pausedNote = pauseService();
  if (await pingDaemon(stateDir)) {
    const r = await controlRequest(daemon.socketPath, { cmd: "shutdown", args: { force } });
    if (!r.ok) {
      // A capture started between the check and now (only possible unforced).
      return `a capture started just now — daemon not stopped (${r.error}).${pausedNote}\nRetry, or force with: beagle stop --force`;
    }
  }
  // confirm it actually went down (the shutdown is async on the daemon side)
  for (let i = 0; i < 20; i++) {
    await Bun.sleep(100);
    if (!(await pingDaemon(stateDir))) return `daemon stopped (pid ${daemon.pid}).${pausedNote}`;
  }
  return `asked the daemon (pid ${daemon.pid}) to stop, but it is still responding — check \`beagle status\`.${pausedNote}`;
}

/** Full, safe teardown in one command: unwatch every watched agent (restoring
 *  your PATH and removing the background service), stop the daemon, SECURELY
 *  erase captured data, then remove the state dir. Ordered so it can't orphan a
 *  shim or leave secret bytes on disk — the trap of a manual `rm -rf`. Does not
 *  remove the beagle binary itself (a running process can't reliably delete its
 *  own executable, and Beagle shouldn't guess how you installed it). */
export async function cmdUninstall(
  stateDir: string,
  yes = false,
  // Injectable (default = the real terminal) so tests exercise the
  // non-interactive path deterministically — mirrors resolveRunMode(isTTY).
  isTTY = Boolean(process.stdin.isTTY),
): Promise<string> {
  const watched = watchedAgents(stateDir);
  const hasStore = existsSync(join(stateDir, "beagle.db"));
  const daemonUp = (await pingDaemon(stateDir)) !== null;
  if (!existsSync(stateDir) || (!watched.length && !hasStore && !daemonUp)) {
    return "beagle isn't installed here — nothing to remove.";
  }

  if (!yes) {
    // No TTY to confirm on (script/CI, or a stdin that never sends): don't
    // block waiting for a keystroke — require the explicit flag instead.
    if (!isTTY) {
      return "beagle uninstall needs confirmation — re-run with --yes to proceed non-interactively.";
    }
    const plan = ["beagle uninstall will:"];
    if (watched.length) plan.push(`  • unwatch ${watched.join(", ")} — restore your PATH, remove the background service`);
    if (daemonUp) plan.push("  • stop the background daemon");
    if (hasStore) plan.push("  • securely erase all captured data");
    plan.push(`  • remove Beagle's files from ${stateDir}`);
    process.stdout.write(plan.join("\n") + "\nProceed? [y/N] ");
    if (!/^y(es)?$/i.test(readLineSync().trim())) return "cancelled — nothing changed.";
  }

  const done: string[] = [];
  const failed: string[] = [];
  // 1. Unwatch each agent FIRST (restores PATH + config, last one removes the
  //    service). Error-isolated: one agent's failure must not abort the whole
  //    uninstall and strand the daemon + un-purged secrets. Forced, since
  //    uninstall is a deliberate teardown.
  for (const agent of watched) {
    try {
      await cmdUnwatch(stateDir, agent, true);
      done.push(`unwatched ${agent}`);
    } catch {
      failed.push(agent);
    }
  }
  // 2. Stop any daemon still running (a `beagle run`-only user has one but no
  //    watches). Force: deliberate teardown.
  if ((await pingDaemon(stateDir)) !== null) await cmdStop(stateDir, true);
  // GATE: never delete the store out from under a live single-writer daemon —
  // that both corrupts and (worse) skips the secure purge, leaving secrets in
  // freed blocks. If the daemon didn't go down, stop here and delete nothing.
  if ((await pingDaemon(stateDir)) !== null) {
    return (
      "beagle uninstall stopped early — the daemon is still running and holds the store open.\n" +
      "  Run `beagle stop --force`, then `beagle uninstall` again. Nothing was deleted." +
      (failed.length ? `\n  (already unwatched: ${done.map((d) => d.replace("unwatched ", "")).join(", ") || "none"}; failed: ${failed.join(", ")})` : "")
    );
  }
  done.push("stopped the daemon");
  // 3. Secure-wipe the captured data before unlinking — `rm` alone just frees
  //    the blocks, leaving secret bytes recoverable until overwritten. The
  //    daemon is confirmed down above (never two writers on the store).
  if (hasStore) {
    try {
      const store = Store.open(stateDir);
      store.panicPurge();
      store.close();
      done.push("securely erased captured data");
    } catch {
      /* corrupt/locked: the removal below still unlinks it */
    }
  }
  // 4. Remove Beagle-OWNED entries only — NEVER `rm -rf` the whole dir, which
  //    a user may have pointed BEAGLE_STATE_DIR at and shares with their own
  //    files. Then remove the dir itself only if Beagle's files were all it
  //    held (rmdir fails on a non-empty dir — that IS the guard).
  for (const name of BEAGLE_STATE_ENTRIES) rmSync(join(stateDir, name), { recursive: true, force: true });
  let dirRemoved = false;
  try {
    rmdirSync(stateDir);
    dirRemoved = true;
  } catch {
    /* non-empty: the user keeps their own files that shared this dir */
  }
  done.push(dirRemoved ? `removed ${stateDir}` : `removed Beagle's files (kept your other files in ${stateDir})`);

  return (
    "beagle uninstalled:\n  " +
    done.join("\n  ") +
    (failed.length ? `\n  ⚠ could not unwatch: ${failed.join(", ")} — check their PATH shims by hand` : "") +
    "\n\nThe beagle binary is still installed — remove it with:\n" +
    `  brew uninstall beagle   (or: rm "${process.execPath}")`
  );
}

// Everything Beagle creates inside its state dir — the ONLY things uninstall
// deletes. Kept exhaustive on purpose: uninstall must never remove a file it
// didn't create (BEAGLE_STATE_DIR can point at a shared directory).
const BEAGLE_STATE_ENTRIES = [
  "beagle.db", "beagle.db-wal", "beagle.db-shm", // SQLite + its WAL sidecars
  "config.json", "install.key", "changes.json", "daemon.json", "control.sock",
  "graduation.json", "daemon.log", "shims", "agent-config", "quarantine",
];

// One agent's two lines: the COMMAND on its own arrowed line (it must read as
// "type this", not a description), then `note` on the next, indented to line up
// under the command. The single place this layout is defined.
function detectRow(agent: string, note: string): string {
  return `  ${agent.padEnd(10)}→ beagle run ${agent}\n${" ".repeat(14)}${note}`;
}

/** The two-line detect entry for an agent whose capture depends on its login
 *  (claude/codex): a plain-English note on the login Beagle detected and how
 *  that session gets captured — no bare "wire/telemetry" jargon. For tests. */
export function detectLine(agent: string, auth: "api-key" | "subscription" | "unknown"): string {
  const how =
    auth === "subscription"
      ? "signed in with a subscription — captured via the agent's own usage report"
      : auth === "api-key"
        ? "signed in with an API key — captured on the wire, full fidelity"
        : "couldn't tell how it's signed in — Beagle asks once on your first run";
  return detectRow(agent, how);
}

export function cmdDetect(): string {
  const found = detectAgents({
    pathDirs: pathDirsFromEnv(process.env.PATH),
    extraLocations: knownExtraLocations(homedir()),
  });
  if (found.length === 0) {
    return (
      "No supported agents found on your PATH.\n" +
      `Beagle looked for: ${Object.keys(AGENTS).join(", ")} (and ~/.claude/local for Claude Code).\n` +
      "To point one manually, set its base URL to Beagle's proxy — see the README."
    );
  }
  const lines = found.map((f) => {
    // opencode and pi wire-capture BOTH login kinds — the login detail doesn't
    // change the command or the capture, so no detection caveat is shown.
    if (f.agent === "claude" || f.agent === "codex") return detectLine(f.agent, detectAuthForRun(f.agent));
    return detectRow(f.agent, "captured on the wire, full fidelity");
  });
  return (
    `Found ${found.length} agent${found.length === 1 ? "" : "s"} — to capture one session, run the command shown:\n\n` +
    `${lines.join("\n")}\n\n` +
    `To capture every session automatically:  beagle watch <agent>`
  );
}

function buildWatchEnv(stateDir: string, yes: boolean): WatchEnv {
  return {
    stateDir,
    shimDir: join(stateDir, "shims"),
    // Compiled binary: argv0 IS beagle. Dev (bun + entry script): the shim
    // must carry BOTH parts — a bare runtime with no script is a broken shim.
    beagleBinary: process.execPath,
    beagleScript:
      process.argv[1] && /\.(ts|js|mjs)$/.test(process.argv[1]) ? process.argv[1] : undefined,
    shell: process.env.SHELL ?? "/bin/sh",
    platform: process.platform,
    home: homedir(),
    zdotdir: process.env.ZDOTDIR,
    resolveReal: (agent) => resolveRealBinary(stateDir, agent),
    runType: (agent) => {
      try {
        const shell = process.env.SHELL ?? "/bin/sh";
        // Pass the agent as a positional ($1), never interpolated into the
        // script string — so an agent name can't break out of `sh -ic`.
        const r = Bun.spawnSync([shell, "-ic", 'type "$1"', shell, agent]);
        return r.stdout.toString().trim() || r.stderr.toString().trim();
      } catch {
        return "";
      }
    },
    confirm: (diff, prompt = "Proceed? [y/N] ") => {
      process.stdout.write(diff + "\n");
      if (yes) return true;
      process.stdout.write(prompt);
      const line = readLineSync();
      return /^y(es)?$/i.test(line.trim());
    },
    // Codex records its login kind in auth.json; Claude Code leaves an
    // oauthAccount record in ~/.claude.json (presence only — no values are
    // read). Detection failing open is safe: the wire tripwire in cmdRun
    // catches a missed subscription at run time.
    detectSubscription: (agent) =>
      detectSubscriptionFor(agent, homedir(), {
        codexHome: process.env.CODEX_HOME,
        claudeConfigDir: process.env.CLAUDE_CONFIG_DIR,
        hasAnthropicApiKey: Boolean(process.env.ANTHROPIC_API_KEY),
      }),
  };
}

/** Resolve where the agent's REAL binary lives, never Beagle's own shim: once
 *  the shim dir is on the user's PATH (the whole point of watch), a naive PATH
 *  walk finds the shim first — a re-watch would then write a shim whose
 *  `--real` is itself (fork bomb on the next invocation), and `beagle run` of
 *  a watched agent would double-wrap through it. Confirmed live before this
 *  guard existed. */
export function resolveRealBinary(stateDir: string, agent: string): string | null {
  const shimDir = resolvePath(join(stateDir, "shims"));
  const found = detectAgents({
    pathDirs: pathDirsFromEnv(process.env.PATH).filter((d) => resolvePath(d) !== shimDir),
    extraLocations: knownExtraLocations(homedir()),
  });
  return found.find((f) => f.agent === agent)?.path ?? null;
}

/** Parse `beagle watch` flags. Strict: an unknown flag is an error, not a
 *  silent fallback — a typo'd --telemetry that degraded to auto could install
 *  a wire shim for a subscription user. Exported for tests. */
export function parseWatchArgs(
  rest: string[],
): { agent: string; yes: boolean; mode: WatchModeRequest } | { error: string } {
  const KNOWN = new Set(["--yes", "--telemetry", "--wire"]);
  const unknown = rest.find((a) => a.startsWith("--") && !KNOWN.has(a));
  if (unknown) return { error: `unknown flag ${unknown} — usage: beagle watch <agent> [--telemetry|--wire] [--yes]` };
  const agent = rest.find((a) => !a.startsWith("--"));
  if (!agent) return { error: "usage: beagle watch <agent> [--telemetry|--wire] [--yes]" };
  // Defense-in-depth: the agent name flows into a generated /bin/sh shim and a
  // `sh -ic` probe. It's already gated to the AGENTS allowlist downstream, but
  // pin the shape here too so a metachar/newline can never reach those sinks.
  if (!/^[a-z][a-z0-9-]*$/.test(agent)) return { error: `invalid agent name '${agent}'` };
  if (rest.includes("--telemetry") && rest.includes("--wire")) {
    return { error: "--telemetry and --wire are mutually exclusive." };
  }
  const mode: WatchModeRequest = rest.includes("--telemetry") ? "telemetry" : rest.includes("--wire") ? "wire" : "auto";
  return { agent, yes: rest.includes("--yes"), mode };
}

/** Is this agent on a subscription login the proxy can't see? Pure and
 *  home-injectable for tests; buildWatchEnv wires it with the real env. */
export function detectSubscriptionFor(
  agent: string,
  home: string,
  opts: { codexHome?: string; claudeConfigDir?: string; hasAnthropicApiKey?: boolean } = {},
): boolean {
  if (agent === "codex") return codexAuthMode(home, opts.codexHome) === "chatgpt";
  if (agent === "claude") {
    return claudeAuthMode(home, opts.hasAnthropicApiKey ?? false, opts.claudeConfigDir) === "subscription";
  }
  return false;
}

export function cmdWatch(
  stateDir: string,
  agent: string,
  yes: boolean,
  mode: WatchModeRequest = "auto",
): { ok: boolean; message: string; shellReloadHint?: boolean } {
  const env = buildWatchEnv(stateDir, yes);
  const r = watchAgent(agent, env, mode);
  if (r.applied) new GraduationTracker(stateDir).markWatched(agent);
  return { ok: r.applied, message: r.message, shellReloadHint: r.shellReloadHint };
}

/** The closest thing to "source ~/.zshrc for the user" the OS allows: a child
 *  process can never mutate its parent shell's PATH, but it CAN hand the user
 *  a fresh shell that read the updated rc — so the terminal they are sitting
 *  in (where they'll type the agent's name next) is covered immediately.
 *  Interactive-TTY only: scripts and --yes runs must never grow a subshell. */
function defaultSpawnShell(sh: string): Promise<unknown> {
  // Login + interactive: bash then reads ~/.bash_profile (where rcTargetFor
  // writes on macOS), zsh ~/.zprofile+~/.zshrc, fish config.fish — so the
  // shims are actually on PATH. `-i` alone gives a NON-login bash that reads
  // only ~/.bashrc and would miss the block on macOS.
  // Strip BEAGLE_STATE_DIR/BEAGLE_EPHEMERAL so a one-shot `BEAGLE_STATE_DIR=…
  // beagle watch` doesn't silently pin every later command in the new shell to
  // that override (an intentional, profile-set value comes back via login).
  const env = { ...process.env };
  delete env.BEAGLE_STATE_DIR;
  delete env.BEAGLE_EPHEMERAL;
  return Bun.spawn([sh, "-l", "-i"], { stdio: ["inherit", "inherit", "inherit"], env }).exited;
}

export async function offerRefreshedShell(
  isTTY = Boolean(process.stdin.isTTY),
  shell = process.env.SHELL ?? "/bin/sh",
  spawnShell: (sh: string) => Promise<unknown> = defaultSpawnShell,
  readLine: () => string = readLineSync,
): Promise<boolean> {
  if (!isTTY) return false;
  // [y/N], default No — matches the two consent prompts above it, and never
  // spawns a subshell on a reflexive Enter. EOF (Ctrl-D) also declines.
  process.stdout.write(
    "This terminal still has the old PATH. Start a refreshed shell here so it's covered now? ('exit' returns) [y/N] ",
  );
  if (!/^y(es)?$/i.test(readLine().trim())) return false;
  console.log(`(refreshed ${stripControlChars(shell)} — watched agents resolve to their shims here)`);
  try {
    await spawnShell(shell);
  } catch {
    // A bogus $SHELL (deleted binary) must not crash a watch that already
    // succeeded — fall back to the manual hint.
    console.log("couldn't start a refreshed shell — open a new terminal, or run 'exec $SHELL -l'.");
    return false;
  }
  return true;
}

/** Agents currently watched, per the manifest — the manifest entry, not the
 *  shim file, IS the watch relationship (mirrors unwatchAgent's definition,
 *  including config-redirect-only agents). */
export function watchedAgents(stateDir: string): string[] {
  return [...new Set(
    new ChangeManifest(stateDir).list()
      .filter((e) => (e.kind === "shim" || e.kind === "config-redirect") && e.agent)
      .map((e) => e.agent!),
  )];
}

async function liveLeases(stateDir: string): Promise<number> {
  const daemon = await pingDaemon(stateDir);
  if (!daemon) return 0;
  const status = await controlRequest(daemon.socketPath, { cmd: "status" });
  return (status.data as { leases?: number } | undefined)?.leases ?? 0;
}

export async function cmdUnwatch(stateDir: string, agent: string, force = false): Promise<string> {
  // Check for a live capture BEFORE touching anything: removing the last
  // agent tears down the shared background service, which kills the
  // service-managed daemon UNCONDITIONALLY (launchctl unload) — a post-hoc
  // lease check can't protect a capture that's already been dropped. Refuse a
  // deliberate unwatch mid-capture; --force overrides (uninstall forces).
  if (!force) {
    const leases = await liveLeases(stateDir);
    if (leases > 0) {
      return (
        `not unwatching ${agent} — Beagle is capturing ${leases} live session${leases === 1 ? "" : "s"} and ` +
        `unwatch would tear down the daemon and drop them.\n` +
        `Finish those sessions first, or force with: beagle unwatch ${agent} --force`
      );
    }
  }
  const r = unwatchAgent(agent, buildWatchEnv(stateDir, true));
  // Leave no trace: when the LAST agent goes, the service is removed — also
  // stop a still-running (ephemeral / manually-started) daemon that the
  // service teardown didn't. Leases were checked above (0, or forced).
  if (r.serviceRemoved) {
    const daemon = await pingDaemon(stateDir);
    if (daemon) {
      await controlRequest(daemon.socketPath, { cmd: "shutdown", args: { force: true } });
      return r.message + "\nDaemon stopped.";
    }
  }
  return r.message;
}

/** Unwatch every agent in one shot — "stop watching, keep my data"
 *  (uninstall is this plus erasing the store). One friendly lease check up
 *  front; each per-agent unwatch then passes `force` THROUGH, so an unforced
 *  --all re-checks per agent and a capture that starts mid-loop still refuses
 *  (rather than the last agent force-tearing down a live daemon). Error-
 *  isolated like uninstall: one agent's failure can't abort the rest. */
export async function cmdUnwatchAll(stateDir: string, force = false): Promise<string> {
  const agents = watchedAgents(stateDir);
  if (!agents.length) return "nothing is watched.";
  if (!force) {
    const leases = await liveLeases(stateDir);
    if (leases > 0) {
      return (
        `not unwatching — Beagle is capturing ${leases} live session${leases === 1 ? "" : "s"} and ` +
        `unwatch would tear down the daemon and drop them.\n` +
        `Finish those sessions first, or force with: beagle unwatch --all --force`
      );
    }
  }
  const out: string[] = [];
  for (const a of agents) {
    try {
      out.push(await cmdUnwatch(stateDir, a, force));
    } catch (e) {
      out.push(`failed to unwatch ${a}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return out.join("\n");
}

/** `beagle unwatch` with no agent: show what's watched and ask which.
 *  One agent → a plain yes/no; several → a numbered pick (number, name, or
 *  'all'). No TTY → print the choices instead of hanging on a read. */
export async function cmdUnwatchSelect(
  stateDir: string,
  force = false,
  isTTY = Boolean(process.stdin.isTTY),
  readLine: () => string = readLineSync,
): Promise<string> {
  const agents = watchedAgents(stateDir);
  if (!agents.length) return "nothing is watched.";
  // Agent names come from the manifest (0600, user-owned) — sanitize before
  // echoing so a doctored entry can't inject terminal escapes. Matching below
  // still uses the raw value.
  if (!isTTY) {
    return `beagle unwatch <agent> — watched: ${agents.map(stripControlChars).join(", ")} (or: beagle unwatch --all)`;
  }
  if (agents.length === 1) {
    process.stdout.write(`Unwatch ${stripControlChars(agents[0]!)}? [y/N] `);
    if (!/^y(es)?$/i.test(readLine().trim())) return "cancelled — nothing changed.";
    return cmdUnwatch(stateDir, agents[0]!, force);
  }
  process.stdout.write(
    "watched agents:\n" +
      agents.map((a, i) => `  ${i + 1}. ${stripControlChars(a)}`).join("\n") +
      `\nUnwatch which? [1-${agents.length}, name, or 'all'] `,
  );
  const ans = readLine().trim();
  if (ans.toLowerCase() === "all") return cmdUnwatchAll(stateDir, force);
  const pick = /^\d+$/.test(ans) ? agents[Number(ans) - 1] : agents.find((a) => a === ans);
  if (!pick) return "cancelled — nothing changed.";
  return cmdUnwatch(stateDir, pick, force);
}

// Reads one line from stdin (until newline or EOF, capped at 64 KB). Exported
// for `beagle search` with no argument — piping the term in keeps secrets out
// of shell history and `ps` output.
export function readLineSync(): string {
  try {
    const fs = require("node:fs") as typeof import("node:fs");
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const buf = new Uint8Array(4096);
      const n = fs.readSync(0, buf, 0, buf.length, null);
      if (n <= 0) break;
      chunks.push(buf.subarray(0, n));
      total += n;
      if (buf.subarray(0, n).includes(10) || total >= 65536) break; // \n or cap
    }
    const all = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { all.set(c, off); off += c.length; }
    const text = new TextDecoder().decode(all);
    const nl = text.indexOf("\n");
    return nl === -1 ? text : text.slice(0, nl + 1);
  } catch {
    return "";
  }
}

export async function cmdConfig(stateDir: string, args: string[]): Promise<string> {
  const cfg = loadConfig(stateDir);
  if (args.length === 0) {
    const modes = Object.entries(cfg.agentRunMode)
      .map(([a, m]) => `${a}=${m}`)
      .join(", ");
    return (
      `redact-on-capture: ${cfg.redactOnCapture}\n` +
      `excluded agents: ${cfg.excludedAgents.join(", ") || "(none)"}\n` +
      `run mode: ${modes || "(auto-detect)"}\n` +
      `retention: ${cfg.payloadWindowDays}d / ${cfg.sizeCapMB} MB payloads · ${cfg.eventWindowDays}d events`
    );
  }
  const update: Record<string, unknown> = {};
  if (args[0] === "redact-on-capture" && args[1]) {
    update.redactOnCapture = args[1] === "on" || args[1] === "true";
  } else if (args[0] === "exclude" && args[1]) {
    update.excludedAgents = [...new Set([...cfg.excludedAgents, args[1]])];
  } else if (args[0] === "unexclude" && args[1]) {
    update.excludedAgents = cfg.excludedAgents.filter((a) => a !== args[1]);
  } else if (args[0] === "run-mode" && args[1] && args[2]) {
    // The remembered answer to "API key or subscription?" — `auto` forgets it
    // so the next run re-detects (or asks again).
    if (args[2] === "auto") {
      const { [args[1]]: _drop, ...rest } = cfg.agentRunMode;
      update.agentRunMode = rest;
    } else if (args[2] === "wire" || args[2] === "telemetry") {
      update.agentRunMode = { ...cfg.agentRunMode, [args[1]]: args[2] };
    } else {
      return "usage: beagle config run-mode <agent> <wire|telemetry|auto>";
    }
  } else {
    return "usage: beagle config [redact-on-capture on|off | exclude <agent> | unexclude <agent> | run-mode <agent> <wire|telemetry|auto>]";
  }
  const daemon = await pingDaemon(stateDir);
  if (daemon) {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: update });
  } else {
    saveConfig(stateDir, { ...cfg, ...update });
  }
  return "config updated.";
}

export async function cmdUi(stateDir: string, sessionId?: string): Promise<string> {
  const daemon = await ensureDaemon(stateDir); // R1: the dashboard is always one command away
  if (!daemon) return "could not start the beagle daemon — check `beagle status`.";
  const r = await controlRequest(daemon.socketPath, { cmd: "ui" });
  if (!r.ok) return `could not start the viewer: ${r.error}`;
  let url = (r.data as { url: string }).url;
  // Deep link straight to one session's transcript (`beagle leaks` prints
  // this). The id rides the #fragment — it never reaches the server or logs.
  if (sessionId) url += `#s=${encodeURIComponent(sessionId)}`;
  // Best-effort open; the URL is printed either way.
  try {
    Bun.spawn([process.platform === "darwin" ? "open" : "xdg-open", url], {
      stdio: ["ignore", "ignore", "ignore"],
    }).unref();
  } catch { /* printing is enough */ }
  return `dashboard: ${url}\n(the link is one-time; run \`beagle ui\` again for a fresh one)`;
}

// Parses `beagle run` arguments. Beagle's own flags (--telemetry, --real)
// are recognized only BEFORE the `--` separator; everything after it belongs
// to the agent verbatim. The shim invokes:
//   beagle run <agent> [--telemetry] --real <path> -- <args...>
// (--telemetry present when the shim was installed in telemetry mode).
export function parseRunArgs(rawArgs: string[]): {
  telemetry: boolean;
  wire: boolean;
  realBinary: string | null;
  agentArgs: string[];
} {
  const sepIdx = rawArgs.indexOf("--");
  const beagleArgs = sepIdx === -1 ? rawArgs : rawArgs.slice(0, sepIdx);
  const realIdx = beagleArgs.indexOf("--real");
  return {
    telemetry: beagleArgs.includes("--telemetry"),
    wire: beagleArgs.includes("--wire"),
    realBinary: realIdx !== -1 ? (beagleArgs[realIdx + 1] ?? null) : null,
    agentArgs:
      sepIdx !== -1
        ? rawArgs.slice(sepIdx + 1)
        : rawArgs.filter(
            (a, i) => a !== "--telemetry" && a !== "--wire" && a !== "--real" && rawArgs[i - 1] !== "--real",
          ),
  };
}

/** How a telemetry-capable agent's login was detected for THIS run. */
export function detectAuthForRun(agent: string): "api-key" | "subscription" | "unknown" {
  if (agent === "claude") {
    return claudeAuthMode(homedir(), Boolean(process.env.ANTHROPIC_API_KEY), process.env.CLAUDE_CONFIG_DIR);
  }
  if (agent === "codex") {
    const m = codexAuthMode(homedir(), process.env.CODEX_HOME);
    return m === "chatgpt" ? "subscription" : m === "api-key" ? "api-key" : "unknown";
  }
  return "unknown";
}

/** Decide how `beagle run` captures a telemetry-capable agent when the user
 *  didn't say. Precedence: explicit flag > remembered answer > detected login
 *  > ask (interactive only) > wire. A wrong guess is never fatal — telemetry
 *  still captures an API-key run (lower fidelity), and a wire run that
 *  captures nothing trips the zero-capture warning. Pure; exported for tests. */
export function resolveRunMode(
  flags: { telemetry: boolean; wire: boolean },
  saved: "wire" | "telemetry" | undefined,
  detected: "api-key" | "subscription" | "unknown",
  isTTY: boolean,
): { mode: "wire" | "telemetry"; source: "flag" | "saved" | "detected" | "default" } | { mode: "ask" } {
  if (flags.telemetry) return { mode: "telemetry", source: "flag" };
  if (flags.wire) return { mode: "wire", source: "flag" };
  if (saved) return { mode: saved, source: "saved" };
  if (detected === "subscription") return { mode: "telemetry", source: "detected" };
  if (detected === "api-key") return { mode: "wire", source: "detected" };
  if (isTTY) return { mode: "ask" };
  return { mode: "wire", source: "default" };
}

/** Strict parse of the one-time login question: only an unambiguous 1 or 2
 *  counts — anything else (empty line, EOF, typo) is null so a fumbled
 *  keystroke is never remembered as an answer. Exported for tests. */
export function interpretAskAnswer(line: string): "wire" | "telemetry" | null {
  const t = line.trim();
  if (t === "1") return "wire";
  if (t === "2") return "telemetry";
  return null;
}

/** Read codex's stored API key from auth.json (honoring $CODEX_HOME) so the
 *  custom-provider redirect can authenticate when the key isn't in the env.
 *  This is the ONE place Beagle reads the key value from disk — the same key
 *  it already proxies and scrubs from storage; it is passed only to the child
 *  codex process's env, never logged or persisted. Returns null if absent. */
export function readCodexApiKey(codexHome: string | undefined): string | null {
  try {
    const dir = codexHome || join(homedir(), ".codex");
    const raw = JSON.parse(readFileSync(join(dir, "auth.json"), "utf8")) as { OPENAI_API_KEY?: unknown };
    return typeof raw?.OPENAI_API_KEY === "string" && raw.OPENAI_API_KEY.length > 0 ? raw.OPENAI_API_KEY : null;
  } catch {
    return null;
  }
}

export async function cmdRun(stateDir: string, agentName: string, rawArgs: string[]): Promise<number> {
  const spec = AGENTS[agentName];
  if (!spec) {
    console.error(`unknown agent '${agentName}' — supported: ${Object.keys(AGENTS).join(", ")}`);
    return 2;
  }
  // Mode B (R2): --telemetry watches via the agent's own OTel export instead
  // of the wire — for subscription logins (Claude Code on Claude.ai, Codex on
  // ChatGPT) whose traffic can't be proxied. Capture is labeled agent-reported.
  const { telemetry: telemetryFlag, wire: wireFlag, realBinary: realOverride, agentArgs } = parseRunArgs(rawArgs);
  if (telemetryFlag && !spec.telemetry) {
    const supported = Object.entries(AGENTS)
      .filter(([, s]) => s.telemetry)
      .map(([n]) => n)
      .join(", ");
    console.error(`--telemetry (agent self-report capture) is supported for ${supported}.`);
    return 2;
  }
  if (telemetryFlag && wireFlag) {
    console.error("--telemetry and --wire are mutually exclusive.");
    return 2;
  }
  // For agents with two capture modes, work out which one this login needs —
  // so a subscription user can type plain `beagle run claude` and have it
  // just work, instead of silently capturing nothing in wire mode.
  let telemetry = telemetryFlag;
  if (spec.telemetry && !telemetryFlag && !wireFlag) {
    const cfg = loadConfig(stateDir);
    const resolved = resolveRunMode(
      { telemetry: telemetryFlag, wire: wireFlag },
      cfg.agentRunMode[agentName],
      detectAuthForRun(agentName),
      // Never ask through the PATH shim (--real marks it): the user set up
      // watch precisely to not be interrupted — an unknown login there falls
      // through to wire + the zero-capture warning. The shim's exec keeps the
      // terminal's stdin, so a TTY check alone would NOT protect it.
      Boolean(process.stdin.isTTY) && realOverride === null,
    );
    if (resolved.mode === "ask") {
      // Beagle couldn't tell and we have a terminal: ask ONCE, remember.
      let answer: "wire" | "telemetry" | null = null;
      for (let attempt = 0; attempt < 2 && answer === null; attempt++) {
        process.stderr.write(
          `beagle: how is ${agentName} signed in? (couldn't tell automatically)\n` +
            `  [1] API key — full-fidelity proxy capture\n` +
            `  [2] Subscription (Claude.ai / ChatGPT) — the agent reports its own usage\n` +
            `choice [1/2]: `,
        );
        answer = interpretAskAnswer(readLineSync());
        if (answer === null) process.stderr.write("beagle: please answer 1 or 2.\n");
      }
      if (answer === null) {
        // Invalid/EOF: use wire for THIS run only — a fumbled keystroke must
        // not become a permanently remembered (and wrong) answer.
        telemetry = false;
        process.stderr.write(
          `beagle: no valid answer — using wire capture for this run only. ` +
            `Set it with: beagle config run-mode ${agentName} <wire|telemetry>\n`,
        );
      } else {
        telemetry = answer === "telemetry";
        // Re-read config at save time (the prompt is human-paced — a stale
        // pre-prompt snapshot could clobber a concurrent save), and route
        // through a running daemon, the config's single writer when up.
        const latest = loadConfig(stateDir);
        const agentRunMode = { ...latest.agentRunMode, [agentName]: answer };
        const running = await pingDaemon(stateDir);
        if (running) await controlRequest(running.socketPath, { cmd: "set-config", args: { agentRunMode } });
        else saveConfig(stateDir, { ...latest, agentRunMode });
        process.stderr.write(
          `beagle: saved — future runs use ${answer}. Change with: beagle config run-mode ${agentName} <wire|telemetry|auto>\n`,
        );
      }
    } else {
      telemetry = resolved.mode === "telemetry";
      if (telemetry && resolved.source === "detected") {
        process.stderr.write(
          `beagle: ${agentName} subscription login detected — capturing via its telemetry ` +
            `(agent-reported). Pass --wire to force proxy capture.\n`,
        );
      }
    }
  }
  if (!telemetry && !spec.baseUrlEnv && !spec.config && !spec.extension && !spec.wireArgs) {
    console.error(
      `${agentName} is config-driven and its config-override mechanism isn't confirmed yet — ` +
        `point it at Beagle manually for now (see the README).`,
    );
    return 2;
  }
  // No --real override (a direct `beagle run`, not the shim): resolve the
  // binary ourselves, skipping Beagle's shim dir — spawning the bare command
  // through PATH would re-enter the shim on a watched agent (double-wrap: a
  // second runId that captures nothing and trips the zero-capture warning).
  const realBinary = realOverride ?? resolveRealBinary(stateDir, agentName) ?? spec.command;

  const daemon = await ensureDaemon(stateDir);
  if (!daemon) {
    // Proxy-down: v1 fails OPEN (observe-only, nothing to protect) but says so
    // unmissably via an OS notification — a printed line dies with the first
    // alternate-screen redraw of a TUI (R2, §8 failure table).
    notifyProxyDown(agentName);
    const direct = Bun.spawn([realBinary, ...agentArgs], { stdio: ["inherit", "inherit", "inherit"] });
    return await direct.exited;
  }

  const runId = randomUUID();
  // `undefined` entries mean "remove this var from the child env" (codex needs
  // inherited OTLP compression vars gone — see buildCodexOtelEnv).
  let modeEnv: Record<string, string | undefined>;
  let finalArgs = agentArgs;
  // Beagle-owned per-run file to delete when the agent exits (redirect config,
  // pi extension, or the Mode-B hook settings). Named per RUN so concurrent
  // runs of one agent don't collide.
  let cleanupFile: string | null = null;
  // Cleared only by a fail-open branch that runs the agent WITHOUT capture (the
  // codex no-key case below) — gates the early "capture active" confirmation
  // off for a run that captures nothing by design, alongside that branch's own
  // "running WITHOUT capture" notice.
  let captureEnabled = true;
  if (telemetry) {
    // Nothing goes on the wire: point the agent's own OTel exporter at the
    // daemon's loopback receiver, authed by the per-session run token.
    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort?: number; otlpToken?: string } | undefined;
    if (!status.ok || !data?.otlpPort || !data.otlpToken) {
      console.error("could not read the telemetry receiver from the daemon — try `beagle status`.");
      return 1;
    }
    const base = `http://127.0.0.1:${data.otlpPort}`;
    if (spec.telemetry === "codex") {
      // Codex exports the full leak surface — prompt, tool commands, AND tool
      // output — inline in its own OTel stream, so no PostToolUse hook is
      // needed. Point its exporter at the receiver via `-c` config flags
      // prepended to the user's argv; the auth token rides an env var (never
      // argv, where it would leak to other local users via `ps`/audit logs).
      modeEnv = buildCodexOtelEnv(data.otlpToken);
      finalArgs = [...buildCodexOtelArgs(base), ...agentArgs];
    } else {
      modeEnv = buildOtelEnv(base, data.otlpToken);
      // Close the OTel export's tool-output blind spot: register a Beagle-owned
      // PostToolUse hook (merged via --settings, never touching the user's own
      // hooks) that forwards each tool result to the receiver so a secret in a
      // tool's OUTPUT is scanned too. Endpoint + token ride env vars the hook
      // process inherits — never argv.
      // Claude takes ONE --settings value (last wins). Keep that same meaning
      // when the flag is repeated, but collapse every pair out of the argv so no
      // later user flag can displace Beagle's merged hook and tool-output scan.
      const { userSettings, restArgs } = collapseClaudeSettings(agentArgs);
      const settings = userSettings
        ? mergeHookIntoSettings(userSettings, beagleHookCommand())
        : buildHookSettings(beagleHookCommand());
      cleanupFile = writeRedirectConfig(stateDir, `claude-hook-${runId}`, settings);
      finalArgs = [...restArgs, "--settings", cleanupFile];
      modeEnv.BEAGLE_HOOK_ENDPOINT = `${base}/v1/hook`;
      modeEnv.BEAGLE_HOOK_TOKEN = data.otlpToken;
    }
  } else {
    await controlRequest(daemon.socketPath, {
      cmd: "register-run",
      args: {
        id: runId,
        agent: agentName,
        provider: spec.provider,
        upstream: spec.resolveUpstream?.(homedir()) ?? spec.upstream,
        authLocation: spec.authLocation,
        extraHeaders: spec.extraHeaders,
      },
    });
    if (spec.config) {
      // Config-driven agent (opencode): write a Beagle-owned config that
      // merges the user's real settings with the proxy baseURL, and point the
      // agent at it — the user's real config is never touched.
      const baseUrl = runBaseUrl(daemon.proxyPort, runId);
      const userCfg = readFirstConfig(spec.config.realConfigCandidates(homedir()));
      const merged = buildRedirectConfig(userCfg, spec.config.baseUrlPath, baseUrl);
      cleanupFile = writeRedirectConfig(stateDir, `${agentName}-${runId}`, merged);
      modeEnv = { [spec.config.configEnv]: cleanupFile };
    } else if (spec.extension) {
      // Extension-driven agent (pi): generate a one-run extension that
      // re-points the provider at the proxy and load it via the agent's own
      // per-run flag. No config or auth files are touched, ever. Which provider
      // to re-point can depend on how the agent is signed in (pi: openai vs the
      // openai-codex OAuth login), so it may be a resolver — matched to the
      // upstream register-run already picked via spec.resolveUpstream.
      const baseUrl = runBaseUrl(daemon.proxyPort, runId);
      const provider =
        typeof spec.extension.baseUrlProvider === "function"
          ? spec.extension.baseUrlProvider(homedir())
          : spec.extension.baseUrlProvider;
      const source = buildExtensionRedirect(provider, baseUrl);
      cleanupFile = writeRedirectExtension(stateDir, `${agentName}-${runId}`, source);
      finalArgs = [spec.extension.flag, cleanupFile, ...agentArgs];
      modeEnv = {};
    } else if (spec.wireArgs) {
      // Arg-driven redirect (codex): it ignores OPENAI_BASE_URL, so prepend
      // `-c` flags defining a custom provider pointed at the proxy. The custom
      // provider authenticates via env_key=OPENAI_API_KEY.
      //
      // Fail-open guard (R2, §8 — Beagle must never break the agent): if the
      // key lives ONLY in codex's auth.json (the `codex login --api-key` flow,
      // no env var), the custom provider errors with "Missing environment
      // variable" and codex dies. So supply the key from the same auth.json we
      // read for detection — the key Beagle already proxies, and scrubs before
      // storing. If there's no key anywhere, don't redirect at all: run codex
      // direct (uncaptured, warned) rather than break it.
      const key = process.env.OPENAI_API_KEY || readCodexApiKey(process.env.CODEX_HOME);
      if (key) {
        finalArgs = [...spec.wireArgs(runBaseUrl(daemon.proxyPort, runId)), ...agentArgs];
        modeEnv = process.env.OPENAI_API_KEY ? {} : { OPENAI_API_KEY: key };
      } else {
        // No key to authenticate the redirect — leave codex untouched.
        finalArgs = agentArgs;
        modeEnv = {};
        captureEnabled = false;
        process.stderr.write(
          `beagle ▲ ${agentName} has no OPENAI_API_KEY (env or ~/.codex/auth.json) — running WITHOUT capture.\n` +
            `  Export OPENAI_API_KEY (or 'codex login --api-key') to enable proxy capture.\n`,
        );
      }
    } else {
      modeEnv = buildRunEnv(agentName, daemon.proxyPort, runId);
    }
  }
  // Graduation is recorded here (not in execAgent) so the nudge can be
  // ordered AFTER the zero-capture check below — printing "watch codex" and
  // "this run captured nothing" back-to-back would be contradictory advice.
  const grad = new GraduationTracker(stateDir);
  const shouldNudge = grad.recordRunAndCheck(agentName);
  const t0 = Date.now();
  // Positive mid-session feedback: the moment the FIRST call for this run is
  // actually captured, print a one-time "capture active" line — so a long
  // session isn't left believing it's watched only to discover at the very end
  // that it wasn't.
  //
  // WIRE MODE ONLY. Telemetry (Mode B) rows are all stored under a shared
  // runId ("otel") behind one daemon-wide token, so the store can't attribute a
  // captured call to THIS run; a time-scoped check would let a concurrent
  // telemetry run trip a false "capture active" and mask a dead exporter — the
  // exact failure this exists to catch (honesty over reassurance). We make the
  // positive claim only where it's run-attributable; telemetry still gets the
  // accurate end-of-run check below. The predicate fails CLOSED (silent on an
  // unreadable store) — the opposite of the end-of-run tripwire's fail-open —
  // so a store hiccup can never manufacture a false "watched" claim. For a
  // full-screen TUI agent the line may be wiped by the next alt-screen redraw
  // (R2), like the daemon-down notice — best-effort. Excluded agents are
  // skipped (arm-time config read; the end-of-run block re-reads at report
  // time). stopWatch rides a .finally so a spawn failure can't leave it firing.
  const stopWatch = watchForFirstCapture(
    !telemetry && captureEnabled && !loadConfig(stateDir).excludedAgents.includes(agentName),
    () => wireCaptureLive(stateDir, runId, t0),
    () => process.stderr.write(`beagle ● capture active — ${agentName} traffic is being watched.\n`),
  );
  const exitCode = await execAgent(daemon.socketPath, realBinary, finalArgs, modeEnv, cleanupFile).finally(stopWatch);
  // Both modes have silent zero-capture failure modes the agent itself never
  // surfaces — say so loudly rather than let the user believe the run was
  // watched. Gated the same way for both: near-instant runs (--help, version
  // checks) are skipped — a real model turn can finish in ~5s, so the bar
  // must sit well under that — and so is an agent the user deliberately
  // excluded from capture (zero rows there is configured behavior, not a
  // failure). A rare false positive remains (e.g. `codex login`, which sends
  // no model traffic) — the right trade against silently unwatched runs.
  // Re-read at report time (not the watcher's arm-time snapshot): a mid-run
  // exclusion should still suppress the end-of-run warning and the nudge.
  const excluded = loadConfig(stateDir).excludedAgents.includes(agentName);
  let warned = false;
  if (Date.now() - t0 >= 3_000 && !excluded) {
    if (telemetry) {
      // Telemetry: agent version without OTel export, or a user env/config
      // that displaces the exporter.
      if (!(await otelCallsArrivedSince(stateDir, t0))) {
        warned = true;
        process.stderr.write(
          `beagle ▲ nothing arrived from ${agentName}'s telemetry this run — it was likely NOT captured.\n` +
            `  Check \`beagle status\`, and that your ${agentName} version supports telemetry export.\n`,
        );
      }
    } else if (!(await runCallsArrived(stateDir, runId))) {
      // Wire: the big one is a subscription login — its traffic never crosses
      // the proxy, so the run "works" while Beagle sees nothing.
      const savedWire = loadConfig(stateDir).agentRunMode[agentName] === "wire";
      const alt = spec.telemetry
        ? `  If ${agentName} signs in with a subscription (not an API key), the proxy can't see its traffic —\n` +
          `  use: beagle run ${agentName} --telemetry   (or: beagle watch ${agentName} --telemetry)\n` +
          (savedWire
            ? `  Note: a saved answer is forcing wire mode — reset it with: beagle config run-mode ${agentName} auto\n`
            : "")
        : `  Check \`beagle status\` for coverage.\n`;
      warned = true;
      process.stderr.write(
        `beagle ▲ no traffic from this ${agentName} run went through Beagle — it was NOT captured.\n` + alt,
      );
    }
  }
  // Quiet-tier detections (R5) never fire an OS alert, so a session's only
  // trace of them would otherwise be `beagle leaks`. Surface a per-session
  // count in the terminal — visible without the notification spam that
  // motivated keeping the "possible" tier quiet. Skipped when a warning above
  // already fired (nothing was captured, so there are no leaks to report), and
  // gated on the same ~instant-run threshold the tripwire uses — a sub-3s run
  // can't have produced a leak, so don't open the store to count zero.
  if (!warned && !excluded && Date.now() - t0 >= 3_000) {
    const possible = countPossibleLeaksSince(stateDir, t0);
    if (possible > 0) {
      warned = true; // a security notice outranks the graduation nudge below
      process.stderr.write(
        `beagle ▲ ${possible} possible secret${possible === 1 ? "" : "s"} flagged this session ` +
          `(lower-confidence, not alerted) — review with: beagle leaks\n`,
      );
    }
  }
  // Graduation nudge AFTER the agent exits (R2: full-screen TUIs wipe earlier
  // output) and only when capture actually worked — a warning above already
  // names the right command, and nudging toward watching a failing mode would
  // contradict it. Excluded agents aren't nudged either: recommending
  // always-on watching for an agent the user configured Beagle to ignore
  // would be nonsense.
  if (shouldNudge && !warned && !excluded) {
    process.stderr.write(graduationNudge(agentName, telemetry));
  }
  return exitCode;
}

// Did the agent's OTel EXPORT land anything at or after `since`?
// Timestamp-based, not a before/after COUNT diff — a concurrent retention
// sweep or purge deleting old rows must never turn a captured run into a false
// "nothing arrived". Hook rows (otel:tool_output:*) are EXCLUDED: the
// PostToolUse hook posts independently of the OTel exporter, so counting them
// would mask a dead/diverted export — the exact failure this warns about —
// for any run that used a tool. Exports are batched, so the last batch can
// trail the agent's exit — poll briefly before concluding zero. The 10s clock
// margin absorbs agent-reported timestamps trailing our local t0 without
// letting a PREVIOUS run's rows mask a newly-dead exporter for a whole minute.
// (Another concurrent Mode B run can still match — fine: best-effort tripwire,
// not an accounting.) Exported for tests.
export async function otelCallsArrivedSince(stateDir: string, since: number, deadlineMs = 4000): Promise<boolean> {
  const cutoff = since - 10_000;
  const t0 = Date.now();
  for (;;) {
    const store = openStore(stateDir);
    if (store === null || isStoreError(store)) return true; // unreadable → don't cry wolf
    let n = -1;
    try {
      n = store.queryAll<{ n: number }>(
        "SELECT COUNT(*) AS n FROM exchanges WHERE source='otel' AND ts_request>=? " +
          "AND endpoint NOT LIKE 'otel:tool_output:%'",
        [cutoff],
      )[0]?.n ?? 0;
    } catch {
      n = -1;
    } finally {
      store.close();
    }
    if (n !== 0) return true;
    if (Date.now() - t0 >= deadlineMs) return false;
    await Bun.sleep(250);
  }
}

// Did any WIRE call land for this specific run? Rows are keyed by the run's
// UUID, so no before/after dance is needed. Short poll to absorb write lag.
// Exported for tests (the wire zero-capture tripwire's core predicate).
export async function runCallsArrived(stateDir: string, runId: string, deadlineMs = 2000): Promise<boolean> {
  const t0 = Date.now();
  for (;;) {
    const store = openStore(stateDir);
    if (store === null || isStoreError(store)) return true; // unreadable → don't cry wolf
    let n = -1;
    try {
      n = store.queryAll<{ n: number }>("SELECT COUNT(*) AS n FROM exchanges WHERE run_id=?", [runId])[0]?.n ?? 0;
    } catch {
      n = -1;
    } finally {
      store.close();
    }
    if (n !== 0) return true;
    if (Date.now() - t0 >= deadlineMs) return false;
    await Bun.sleep(250);
  }
}

// One cheap store check for the live "capture active" watcher: has a WIRE call
// for THIS run landed at or after the run started? Two deliberate differences
// from the end-of-run tripwire runCallsArrived:
//   1. Fails CLOSED. runCallsArrived returns true on a null/unreadable store so
//      it never cries wolf; a POSITIVE signal must do the opposite — on any
//      missing store or read error return false and stay silent, never affirm
//      capture we can't verify (honesty over reassurance).
//   2. Rides the ts_request index. run_id is unindexed, so a bare COUNT on it
//      full-scans the exchanges table every poll; bounding by ts_request>=t0
//      (t0 = run start) restricts the scan to a small recent slice regardless
//      of store size, and LIMIT 1 makes it a bare existence check. run_id is a
//      fresh per-run UUID, so it — not the ts bound — is what guarantees no
//      concurrent run can match; the ts_request floor is only an index hint.
//      That floor is a heuristic, not an invariant: t0 (this process) and
//      ts_request (the daemon, moments later) are independent wall-clock reads,
//      so a backward clock step between them could push a genuine capture below
//      t0 and hide it here for the whole run. It degrades SAFELY — only ever
//      under-claiming, never a false "active" (run_id still scopes it) — and the
//      end-of-run runCallsArrived tripwire has no ts bound, so real capture is
//      still confirmed there. Exported for tests.
export function wireCaptureLive(stateDir: string, runId: string, sinceTs: number): boolean {
  const store = openStore(stateDir);
  if (store === null || isStoreError(store)) return false; // fail closed
  try {
    return (
      store.queryAll<{ one: number }>(
        "SELECT 1 AS one FROM exchanges WHERE ts_request>=? AND run_id=? LIMIT 1",
        [sinceTs, runId],
      ).length > 0
    );
  } catch {
    return false; // read error → stay silent, never a false "capture active"
  } finally {
    store.close();
  }
}

// The positive counterpart to the zero-capture tripwires above: while the agent
// runs, poll `check` and the FIRST time it returns true, fire `onActive` exactly
// once — Beagle is a trust tool, so a long session needs mid-run proof it's
// watched, not only an end-of-run warning when it ISN'T. `check` is synchronous
// (bun:sqlite is): the `done` latch plus clearInterval give exactly-once, and a
// setInterval tick can't re-enter a sync callback, so no overlap guard is
// needed. Returns a stop() the caller MUST invoke when the agent exits: the
// interval is unref'd (it can never keep the process alive past the agent) and
// `done` blocks any fire after stop(). `enabled` false — telemetry, an excluded
// agent, or a fail-open no-capture run — arms nothing. A throw from `check` is
// swallowed: a transient store hiccup must never disrupt the run. Exported for
// tests.
export function watchForFirstCapture(
  enabled: boolean,
  check: () => boolean,
  onActive: () => void,
  intervalMs = 500,
): () => void {
  if (!enabled) return () => {};
  let done = false;
  const timer = setInterval(() => {
    if (done) return;
    let live = false;
    try {
      live = check();
    } catch {
      live = false; // a transient store hiccup must never disrupt the run
    }
    if (live) {
      done = true;
      clearInterval(timer);
      onActive();
    }
  }, intervalMs);
  timer.unref?.();
  return () => {
    done = true; // block any later tick from firing post-exit
    clearInterval(timer);
  };
}

// Count quiet-tier ("possible") leak events recorded since `sinceTs` — the
// per-session surface for detections that never fired an OS alert (R5).
// Read-only, non-core. Exported for tests.
export function countPossibleLeaksSince(stateDir: string, sinceTs: number): number {
  const store = openStore(stateDir);
  if (store === null || isStoreError(store)) return 0;
  try {
    return (
      store.queryAll<{ n: number }>(
        "SELECT COUNT(*) AS n FROM leak_events WHERE confidence_tier='possible' AND last_ts >= ?",
        [sinceTs],
      )[0]?.n ?? 0
    );
  } catch {
    return 0;
  } finally {
    store.close();
  }
}

/** The one-time graduation nudge (design §6.12): shown after the 3rd wrapper
 *  run. Mode-aware — `beagle watch` supports both wire and telemetry shims, so
 *  the suggested command matches how THIS run was captured (a telemetry user
 *  pointed at a wire watch would silently lose coverage). Exported for tests. */
export function graduationNudge(agent: string, telemetry: boolean): string {
  const cmd = `beagle watch ${agent}${telemetry ? " --telemetry" : ""}`;
  return (
    `\nbeagle: you've run ${agent} under Beagle a few times.\n` +
    `  Watch it automatically so you never have to prefix again? Run: ${cmd}\n` +
    `  (one-time nudge; it won't ask again)\n\n`
  );
}

/** Pull every user `--settings` out of Claude's argv, returning the winning
 *  value (last wins, matching Claude) and the remaining args. Handles both the
 *  space form (`--settings x`) and the equals form (`--settings=x`) — Claude
 *  accepts both — and drops a value-less trailing `--settings`. The point is
 *  that `restArgs` contains NO `--settings`, so the flag Beagle appends after it
 *  can never be displaced by a later user flag (which would silently disable
 *  tool-output scanning) nor lose last-wins to a user flag (silently dropping
 *  the user's own settings). */
export function collapseClaudeSettings(agentArgs: string[]): {
  userSettings: string | null;
  restArgs: string[];
} {
  let userSettings: string | null = null;
  const restArgs: string[] = [];
  for (let i = 0; i < agentArgs.length; i++) {
    const arg = agentArgs[i]!;
    if (arg === "--settings") {
      if (agentArgs[i + 1] !== undefined) userSettings = agentArgs[++i]!;
    } else if (arg.startsWith("--settings=")) {
      userSettings = arg.slice("--settings=".length);
    } else {
      restArgs.push(arg);
    }
  }
  return { userSettings, restArgs };
}

// The shell command Claude Code runs for the tool-output hook: this same
// beagle binary in `__hook` mode. Compiled → the binary; dev → bun + the entry
// script. Paths quoted so a space in an install path can't split the command.
function beagleHookCommand(): string {
  const self = process.execPath;
  const script = process.argv[1];
  return script && /\.(ts|js|mjs)$/.test(script)
    ? `"${self}" "${script}" __hook`
    : `"${self}" __hook`;
}

// The hook receiver is ALWAYS plain-http loopback — cmdRun constructs
// BEAGLE_HOOK_ENDPOINT from `http://127.0.0.1:<otlpPort>` and nothing else
// sets it legitimately. If the env var names any other scheme or host
// (misconfiguration, or a hostile parent env trying to redirect the capture),
// POSTing the tool output there would itself be the leak Beagle exists to
// prevent — so the forwarder refuses to send. Exact match on the parsed
// hostname: the URL parser canonicalizes equivalent spellings (`127.1`,
// `LOCALHOST`, long-form `::1`) first, and anything left non-canonical
// (`localhost.`, `127.0.0.1.evil.example`) is refused rather than resolved —
// a sub-2s best-effort hook must never do DNS to find out where a name
// points. Exported for tests.
export function isLoopbackHookEndpoint(endpoint: string): boolean {
  try {
    const u = new URL(endpoint);
    return u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "[::1]" || u.hostname === "localhost");
  } catch {
    return false; // unparseable → refuse (and stay silent, per the hook contract)
  }
}

// PostToolUse hook forwarder (Mode B tool-output capture). Reads Claude Code's
// hook JSON from stdin and POSTs it to the daemon's loopback receiver — and
// ONLY to loopback (isLoopbackHookEndpoint): captured data never leaves the
// machine, even if the endpoint env var says otherwise. Silent and ALWAYS
// exits 0 — a hook must never disrupt the agent or feed output back into its
// context.
export async function cmdHookForward(): Promise<number> {
  try {
    const endpoint = process.env.BEAGLE_HOOK_ENDPOINT;
    const token = process.env.BEAGLE_HOOK_TOKEN;
    if (endpoint && token && isLoopbackHookEndpoint(endpoint)) {
      // Bounded read (size AND time): a runaway or never-closing tool output
      // can't balloon or hang this short-lived process. The read cap matches
      // the receiver's body cap — anything larger wouldn't be accepted anyway.
      const body = await readStdinCapped(32 << 20, 1500);
      if (body) {
        // Hard timeout: PostToolUse runs synchronously inside the agent's loop,
        // so a hung/slow receiver must NEVER stall the agent. Best-effort.
        // redirect "manual": the loopback allowlist only vets the FIRST hop —
        // following a 307/308 would re-POST the captured body to an arbitrary
        // Location, possibly off-machine. The real receiver never redirects.
        await fetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json", "x-beagle-run": token },
          body,
          redirect: "manual",
          signal: AbortSignal.timeout(2000),
        }).catch(() => {});
      }
    }
  } catch {
    /* best-effort: never surface an error to the agent */
  }
  return 0;
}

// Read stdin up to `cap` bytes OR `deadlineMs`, whichever comes first, then
// stop. Bounds both memory (a huge payload) and time (stdin that never reaches
// EOF) so the hook can't balloon or hang the agent — the whole point of a hook
// forwarder is to never disrupt the agent.
async function readStdinCapped(cap: number, deadlineMs: number): Promise<string> {
  const reader = (Bun.stdin.stream() as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  // On the deadline, cancel the reader — the pending read() then resolves done.
  const timer = setTimeout(() => void reader.cancel().catch(() => {}), deadlineMs);
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      chunks.push(value);
      total += value.length;
      if (total >= cap) break;
    }
  } finally {
    clearTimeout(timer);
    reader.cancel().catch(() => {});
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

async function execAgent(
  socketPath: string,
  realBinary: string,
  agentArgs: string[],
  modeEnv: Record<string, string | undefined>,
  redirectCfg: string | null,
): Promise<number> {
  // Hold a lease for the agent's lifetime so an auto-started ephemeral daemon
  // stays up while we're watching, then winds down after we exit (§6.7). Both
  // wire and telemetry modes need this — Mode B registers no run.
  const lease = await openLease(socketPath).catch(() => null);

  try {
    // An `undefined` modeEnv entry REMOVES the var from the child env (an
    // inherited var can break the agent-side capture — see buildCodexOtelEnv).
    const childEnv: Record<string, string | undefined> = { ...process.env, ...modeEnv };
    for (const k of Object.keys(childEnv)) if (childEnv[k] === undefined) delete childEnv[k];
    const child = Bun.spawn([realBinary, ...agentArgs], {
      env: childEnv as Record<string, string>,
      stdio: ["inherit", "inherit", "inherit"],
    });
    return await child.exited;
  } finally {
    lease?.end(); // release the daemon liveness hold
    // The redirect config merged in the user's real provider key — it is only
    // needed for the agent's lifetime, so delete it even if the spawn failed,
    // rather than leave a plaintext secret in the state dir between runs.
    if (redirectCfg) rmSync(redirectCfg, { force: true });
  }
}

function notifyProxyDown(agent: string): void {
  const notifier = new Notifier();
  notifier.notify({
    title: "Beagle isn't running",
    body: `${agent} is NOT being monitored — its traffic is going direct to the provider.`,
  });
  process.stderr.write(`beagle ▲ not running — ${agent} is NOT being monitored (traffic goes direct).\n`);
}
