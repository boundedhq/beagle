// CLI command surface (design §6.9): the whole product headless. Reads open
// the store read-only (work daemon-down); live actions ride the socket.
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { join, resolve as resolvePath } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { Store, StoreVersionError } from "../core/store/store";
import { loadConfig, saveConfig } from "../core/config/config";
import { controlRequest, openLease } from "../daemon/control";
import { Notifier, stripControlChars } from "../notifier/notifier";
import { GraduationTracker } from "../install/graduation";
import { claudeAuthMode, codexAuthMode, detectAgents, knownExtraLocations, pathDirsFromEnv } from "../install/detect";
import { watchAgent, unwatchAgent, type WatchEnv, type WatchModeRequest } from "../install/watch";
import { ChangeManifest } from "../install/manifest";
import { listLeakEvents } from "../viewer/feed-query";
import { buildCodexOtelArgs, buildCodexOtelEnv, buildHookSettings, buildOtelEnv, mergeHookIntoSettings } from "../parsers/otlp-map";
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
          `  Restart it: kill ${daemon.pid} && beagle status   (a plain 'beagle run' will start a fresh one)\n`,
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
  const child = Bun.spawn(argv, {
    // BEAGLE_EPHEMERAL: this auto-started daemon idle-exits once no agent
    // holds a lease and no viewer is open (§6.7), so a trial run leaves
    // nothing behind. An explicit `beagle daemon` or the service unit does not
    // set it and stays up.
    env: { ...process.env, BEAGLE_STATE_DIR: stateDir, BEAGLE_EPHEMERAL: "1" },
    stdio: ["ignore", "ignore", "ignore"],
  });
  child.unref();
  for (let i = 0; i < 40 && !daemon; i++) {
    await Bun.sleep(100);
    daemon = await pingDaemon(stateDir);
  }
  return daemon;
}

export function cmdStatus(stateDir: string, daemonUp: DaemonInfo | null = null): string {
  const lines: string[] = [];
  if (daemonUp) {
    lines.push(`daemon: running (pid ${daemonUp.pid}, proxy 127.0.0.1:${daemonUp.proxyPort})`);
  } else {
    lines.push("daemon: not running — agents launched now go DIRECT (unmonitored)");
  }
  const store = openStore(stateDir);
  if (isStoreError(store)) return lines.concat(store.error).join("\n");
  const calls = store?.countCalls() ?? 0;
  const leaks = store?.countLeakEvents() ?? 0;
  // Agent-reported (Mode B) calls carry a known content gap — disclose it here
  // (R2, spike criterion #2) whenever any exist, not just in the docs.
  const otelCalls = store?.queryAll<{ n: number }>(
    "SELECT COUNT(*) AS n FROM exchanges WHERE source='otel'",
  )[0]?.n ?? 0;
  store?.close();
  const dbPath = join(stateDir, "beagle.db");
  const sizeMb = existsSync(dbPath) ? (statSync(dbPath).size / (1 << 20)).toFixed(1) : "0.0";
  const cfg = loadConfig(stateDir);
  lines.push(`calls: ${calls} · leaks: ${leaks} · store: ${sizeMb} MB`);
  if (otelCalls > 0) {
    lines.push(
      `  ${otelCalls} agent-reported (Mode B, --telemetry): self-report — prompts, ` +
        `tool inputs, and tool outputs are scanned; alerts lag seconds`,
    );
  }
  lines.push(
    `retention: ${cfg.payloadWindowDays}d / ${cfg.sizeCapMB} MB payloads · ${cfg.eventWindowDays}d leak events`,
  );
  const manifest = new ChangeManifest(stateDir);
  lines.push(manifest.summary() + (manifest.list().length ? " (beagle unwatch <agent> to revert)" : ""));
  lines.push(
    "local only · outbound connections: only your model providers · telemetry: none · viewer: off until requested",
  );
  return lines.join("\n");
}

export function cmdSearch(stateDir: string, term: string): string {
  const store = openStore(stateDir);
  if (isStoreError(store)) return store.error;
  if (!store) return "no capture store yet — nothing has been recorded, so: no matches (never sent).";
  const hits = store.searchLiteral(term);
  store.close();
  if (hits.length === 0) return "no matches — that string was never sent through Beagle.";
  const sessions = new Set(hits.map((h) => h.sessionId));
  const lines = [
    `found in ${hits.length} call${hits.length === 1 ? "" : "s"} across ${sessions.size} session${sessions.size === 1 ? "" : "s"}:`,
  ];
  for (const h of hits) {
    lines.push(`  ${h.callId.slice(0, 8)}  ${new Date(h.tsRequest).toISOString()}  session ${clean(h.sessionId).slice(0, 8)}`);
  }
  return lines.join("\n");
}

export function cmdLeaks(stateDir: string): string {
  const store = openStore(stateDir);
  if (isStoreError(store)) return store.error;
  if (!store) return "no leaks recorded.";
  const events = listLeakEvents(store);
  store.close();
  if (events.length === 0) return "no leaks recorded.";
  const lines = [`${events.length} leak event${events.length === 1 ? "" : "s"}:`];
  for (const e of events) {
    const tier = e.confidenceTier === "structured" ? "" : " (possible)";
    lines.push(
      `  ${new Date(e.firstTs).toISOString()}  ${clean(e.secretType)}${tier} → ${clean(e.destination)}` +
        `  ×${e.occurrences}${e.firstCall ? `  first: ${e.firstCall.slice(0, 8)}` : ""}`,
    );
  }
  return lines.join("\n");
}

export function cmdShow(stateDir: string, idPrefix: string): string {
  const store = openStore(stateDir);
  if (isStoreError(store)) return store.error;
  const call = store?.getCall(idPrefix) ?? null;
  store?.close();
  if (!call) return `no call matches '${idPrefix}' (prefix may be ambiguous or unknown).`;
  const lines = [
    `call ${call.id}`,
    `  ${clean(call.agent ?? "?")} → ${clean(call.provider ?? "?")}${call.model ? `/${clean(call.model)}` : ""}  ${clean(call.endpoint ?? "")}`,
    `  at ${new Date(call.tsRequest).toISOString()}  status ${call.status ?? "?"}  tokens ${call.tokensIn ?? "?"}→${call.tokensOut ?? "?"}`,
    `  session ${call.sessionId.slice(0, 8)} (keyed by ${call.sessionTier})  run ${clean(call.runId)}`,
    `  summary: ${clean(call.summary ?? "—")}`,
  ];
  if (call.scanState !== "ok") {
    lines.push("  ⚠ scan timed out — treated as unverified, not clean");
  }
  if (call.captureState !== "ok") {
    lines.push("  ⚠ capture truncated — the stream to the agent was complete; the stored copy is not");
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
export async function cmdStop(stateDir: string, force = false): Promise<string> {
  const daemon = await pingDaemon(stateDir);
  if (!daemon) return "no beagle daemon is running.";
  const status = await controlRequest(daemon.socketPath, { cmd: "status" });
  const leases = (status.data as { leases?: number } | undefined)?.leases ?? 0;
  if (leases > 0 && !force) {
    return (
      `the daemon is capturing for ${leases} live agent session${leases === 1 ? "" : "s"} — ` +
      `stopping now would drop that capture.\nFinish those sessions first, or force with: beagle stop --force`
    );
  }
  await controlRequest(daemon.socketPath, { cmd: "shutdown" });
  // confirm it actually went down (the shutdown is async on the daemon side)
  for (let i = 0; i < 20; i++) {
    await Bun.sleep(100);
    if (!(await pingDaemon(stateDir))) return `daemon stopped (pid ${daemon.pid}).`;
  }
  return `asked the daemon (pid ${daemon.pid}) to stop, but it is still responding — check \`beagle status\`.`;
}

/** One detect line per agent: what login Beagle sees and what capture mode a
 *  plain `beagle run <agent>` would therefore pick. Exported for tests. */
export function detectLine(agent: string, auth: "api-key" | "subscription" | "unknown"): string {
  const login =
    auth === "subscription" ? "subscription login" : auth === "api-key" ? "API-key login" : "login not detected";
  const mode =
    auth === "subscription"
      ? "telemetry capture"
      : auth === "api-key"
        ? "wire capture"
        : "asks on first run";
  return `  ${agent.padEnd(9)} ${login.padEnd(19)} beagle run ${agent}   (${mode})`;
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
    // opencode wire-captures both logins, pi is API-key only — for those the
    // login detail doesn't change the command or the mode.
    if (f.agent === "claude" || f.agent === "codex") return detectLine(f.agent, detectAuthForRun(f.agent));
    return `  ${f.agent.padEnd(9)} ${"".padEnd(19)} beagle run ${f.agent}   (wire capture)`;
  });
  return `Found ${found.length} agent${found.length === 1 ? "" : "s"}:\n${lines.join("\n")}\nAlways-on instead: beagle watch <agent>`;
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
    resolveReal: (agent) => resolveRealBinary(stateDir, agent),
    runType: (agent) => {
      try {
        const shell = process.env.SHELL ?? "/bin/sh";
        const r = Bun.spawnSync([shell, "-ic", `type ${agent}`]);
        return r.stdout.toString().trim() || r.stderr.toString().trim();
      } catch {
        return "";
      }
    },
    confirm: (diff) => {
      process.stdout.write(diff + "\n");
      if (yes) return true;
      process.stdout.write("Proceed? [y/N] ");
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
): { ok: boolean; message: string } {
  const env = buildWatchEnv(stateDir, yes);
  const r = watchAgent(agent, env, mode);
  if (r.applied) new GraduationTracker(stateDir).markWatched(agent);
  return { ok: r.applied, message: r.message };
}

export async function cmdUnwatch(stateDir: string, agent: string): Promise<string> {
  const r = unwatchAgent(agent, buildWatchEnv(stateDir, true));
  // Leave no trace: when the LAST watched agent goes, the service is removed —
  // also stop a still-running daemon (launchd kills its own; this catches
  // ephemeral/manually-started ones). Graceful: an active capture (lease)
  // keeps it alive; those daemons idle-exit on their own afterwards.
  if (r.serviceRemoved) {
    const daemon = await pingDaemon(stateDir);
    if (daemon) {
      const status = await controlRequest(daemon.socketPath, { cmd: "status" });
      const leases = (status.data as { leases?: number } | undefined)?.leases ?? 0;
      if (leases === 0) {
        await controlRequest(daemon.socketPath, { cmd: "shutdown" });
        return r.message + " Daemon stopped.";
      }
      return r.message + ` Daemon left running (${leases} live capture session${leases === 1 ? "" : "s"}) — it stops when they end, or run: beagle stop`;
    }
  }
  return r.message;
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

export async function cmdUi(stateDir: string): Promise<string> {
  const daemon = await ensureDaemon(stateDir); // R1: the dashboard is always one command away
  if (!daemon) return "could not start the beagle daemon — check `beagle status`.";
  const r = await controlRequest(daemon.socketPath, { cmd: "ui" });
  if (!r.ok) return `could not start the viewer: ${r.error}`;
  const url = (r.data as { url: string }).url;
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
      // Claude takes ONE --settings value (last wins), so if the user passed
      // their own, blindly prepending ours would either lose theirs or (their
      // flag coming later) silently drop the hook — and with it tool-output
      // scanning. Merge instead: their settings verbatim, our hook appended.
      const si = agentArgs.indexOf("--settings");
      let settings = buildHookSettings(beagleHookCommand());
      let restArgs = agentArgs;
      if (si !== -1 && agentArgs[si + 1] !== undefined) {
        settings = mergeHookIntoSettings(agentArgs[si + 1]!, beagleHookCommand());
        restArgs = [...agentArgs.slice(0, si), ...agentArgs.slice(si + 2)];
      }
      cleanupFile = writeRedirectConfig(stateDir, `claude-hook-${runId}`, settings);
      finalArgs = ["--settings", cleanupFile, ...restArgs];
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
      // per-run flag. No config or auth files are touched, ever.
      const baseUrl = runBaseUrl(daemon.proxyPort, runId);
      const source = buildExtensionRedirect(spec.extension.baseUrlProvider, baseUrl);
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
  const exitCode = await execAgent(daemon.socketPath, realBinary, finalArgs, modeEnv, cleanupFile);
  // Both modes have silent zero-capture failure modes the agent itself never
  // surfaces — say so loudly rather than let the user believe the run was
  // watched. Gated the same way for both: near-instant runs (--help, version
  // checks) are skipped — a real model turn can finish in ~5s, so the bar
  // must sit well under that — and so is an agent the user deliberately
  // excluded from capture (zero rows there is configured behavior, not a
  // failure). A rare false positive remains (e.g. `codex login`, which sends
  // no model traffic) — the right trade against silently unwatched runs.
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

// PostToolUse hook forwarder (Mode B tool-output capture). Reads Claude Code's
// hook JSON from stdin and POSTs it to the daemon's loopback receiver. Silent
// and ALWAYS exits 0 — a hook must never disrupt the agent or feed output back
// into its context.
export async function cmdHookForward(): Promise<number> {
  try {
    const endpoint = process.env.BEAGLE_HOOK_ENDPOINT;
    const token = process.env.BEAGLE_HOOK_TOKEN;
    if (endpoint && token) {
      // Bounded read (size AND time): a runaway or never-closing tool output
      // can't balloon or hang this short-lived process. The read cap matches
      // the receiver's body cap — anything larger wouldn't be accepted anyway.
      const body = await readStdinCapped(32 << 20, 1500);
      if (body) {
        // Hard timeout: PostToolUse runs synchronously inside the agent's loop,
        // so a hung/slow receiver must NEVER stall the agent. Best-effort.
        await fetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json", "x-beagle-run": token },
          body,
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
