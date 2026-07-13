// CLI command surface (design §6.9): the whole product headless. Reads open
// the store read-only (work daemon-down); live actions ride the socket.
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { Store, StoreVersionError } from "../core/store/store";
import { loadConfig, saveConfig } from "../core/config/config";
import { controlRequest, openLease } from "../daemon/control";
import { Notifier, stripControlChars } from "../notifier/notifier";
import { GraduationTracker } from "../install/graduation";
import { detectAgents, knownExtraLocations, pathDirsFromEnv } from "../install/detect";
import { watchAgent, unwatchAgent, type WatchEnv } from "../install/watch";
import { ChangeManifest } from "../install/manifest";
import { listLeakEvents } from "../viewer/feed-query";
import { buildCodexOtelArgs, buildCodexOtelEnv, buildHookSettings, buildOtelEnv } from "../parsers/otlp-map";
import { buildExtensionRedirect, buildRedirectConfig, readFirstConfig, writeRedirectConfig, writeRedirectExtension } from "../install/config-redirect";
import { AGENTS, buildRunEnv, runBaseUrl } from "./agents";

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
    return r.ok ? info : null;
  } catch {
    return null;
  }
}

// Ensure a daemon is up, spawning one if needed. Shared by run and ui.
async function ensureDaemon(stateDir: string): Promise<DaemonInfo | null> {
  let daemon = await pingDaemon(stateDir);
  if (daemon) return daemon;
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
  const names = found.map((f) => f.agent).join(" and ");
  const first = found[0]!;
  return `Found ${names}. Try: ${first.runCommand}`;
}

function buildWatchEnv(stateDir: string, yes: boolean): WatchEnv {
  return {
    stateDir,
    shimDir: join(stateDir, "shims"),
    // For the compiled binary, argv0 is the beagle executable — exactly what
    // the shim and the service unit should invoke.
    beagleBinary: process.execPath,
    shell: process.env.SHELL ?? "/bin/sh",
    platform: process.platform,
    home: homedir(),
    resolveReal: (agent) => {
      const found = detectAgents({
        pathDirs: pathDirsFromEnv(process.env.PATH),
        extraLocations: knownExtraLocations(homedir()),
      });
      return found.find((f) => f.agent === agent)?.path ?? null;
    },
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
  };
}

export function cmdWatch(stateDir: string, agent: string, yes: boolean): string {
  const env = buildWatchEnv(stateDir, yes);
  const r = watchAgent(agent, env);
  if (r.applied) new GraduationTracker(stateDir).markWatched(agent);
  return r.message;
}

export function cmdUnwatch(stateDir: string, agent: string): string {
  return unwatchAgent(agent, buildWatchEnv(stateDir, true)).message;
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
    return (
      `redact-on-capture: ${cfg.redactOnCapture}\n` +
      `excluded agents: ${cfg.excludedAgents.join(", ") || "(none)"}\n` +
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
  } else {
    return "usage: beagle config [redact-on-capture on|off | exclude <agent> | unexclude <agent>]";
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
// to the agent verbatim. The shim invokes: beagle run <agent> --real <path> -- <args...>
export function parseRunArgs(rawArgs: string[]): {
  telemetry: boolean;
  realBinary: string | null;
  agentArgs: string[];
} {
  const sepIdx = rawArgs.indexOf("--");
  const beagleArgs = sepIdx === -1 ? rawArgs : rawArgs.slice(0, sepIdx);
  const realIdx = beagleArgs.indexOf("--real");
  return {
    telemetry: beagleArgs.includes("--telemetry"),
    realBinary: realIdx !== -1 ? (beagleArgs[realIdx + 1] ?? null) : null,
    agentArgs:
      sepIdx !== -1
        ? rawArgs.slice(sepIdx + 1)
        : rawArgs.filter(
            (a, i) => a !== "--telemetry" && a !== "--real" && rawArgs[i - 1] !== "--real",
          ),
  };
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
  const { telemetry, realBinary: realOverride, agentArgs } = parseRunArgs(rawArgs);
  if (telemetry && !spec.telemetry) {
    const supported = Object.entries(AGENTS)
      .filter(([, s]) => s.telemetry)
      .map(([n]) => n)
      .join(", ");
    console.error(`--telemetry (agent self-report capture) is supported for ${supported}.`);
    return 2;
  }
  if (!telemetry && !spec.baseUrlEnv && !spec.config && !spec.extension) {
    console.error(
      `${agentName} is config-driven and its config-override mechanism isn't confirmed yet — ` +
        `point it at Beagle manually for now (see the README).`,
    );
    return 2;
  }
  const realBinary = realOverride ?? spec.command;

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
      const settings = buildHookSettings(beagleHookCommand());
      cleanupFile = writeRedirectConfig(stateDir, `claude-hook-${runId}`, settings);
      finalArgs = ["--settings", cleanupFile, ...agentArgs];
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
        upstream: spec.upstream,
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
    } else {
      modeEnv = buildRunEnv(agentName, daemon.proxyPort, runId);
    }
  }
  const otelBefore = telemetry ? countOtelCalls(stateDir) : -1;
  const exitCode = await execAgent(daemon.socketPath, realBinary, finalArgs, modeEnv, stateDir, agentName, cleanupFile, telemetry);
  // Telemetry capture has real silent-failure modes the wire path doesn't: an
  // agent version without OTel export, a user env/config that displaces the
  // exporter. The agent runs fine either way — so if nothing arrived, say so
  // loudly rather than let the user believe the run was watched.
  if (telemetry && !(await otelCallsArrived(stateDir, otelBefore))) {
    process.stderr.write(
      `beagle ▲ nothing arrived from ${agentName}'s telemetry this run — it was likely NOT captured.\n` +
        `  Check \`beagle status\`, and that your ${agentName} version supports telemetry export.\n`,
    );
  }
  return exitCode;
}

// COUNT of agent-reported calls in the store; -1 when unreadable (never block
// or false-alarm the run over a store hiccup).
function countOtelCalls(stateDir: string): number {
  const store = openStore(stateDir);
  if (store === null || isStoreError(store)) return -1;
  try {
    return store.queryAll<{ n: number }>("SELECT COUNT(*) AS n FROM exchanges WHERE source='otel'")[0]?.n ?? 0;
  } catch {
    return -1;
  } finally {
    store.close();
  }
}

// Did any agent-reported call land since `before`? Exports are batched, so the
// last batch can trail the agent's exit — poll briefly before concluding zero.
// (Another concurrent Mode B run can also bump the count — that's fine, the
// warning is a best-effort tripwire, not an accounting.)
async function otelCallsArrived(stateDir: string, before: number, deadlineMs = 4000): Promise<boolean> {
  if (before < 0) return true; // store unreadable → don't cry wolf
  const t0 = Date.now();
  for (;;) {
    const n = countOtelCalls(stateDir);
    if (n < 0 || n > before) return true;
    if (Date.now() - t0 >= deadlineMs) return false;
    await Bun.sleep(250);
  }
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
  stateDir: string,
  agentName: string,
  redirectCfg: string | null,
  telemetry: boolean,
): Promise<number> {
  // Graduation nudges the user toward `beagle watch`, which installs a
  // WIRE-mode PATH shim. That shim can't do --telemetry, so for a subscription
  // login (the only reason to use --telemetry) it would capture nothing while
  // status reports coverage. Telemetry runs are therefore excluded from the
  // graduation flow entirely — neither counted nor nudged.
  const grad = new GraduationTracker(stateDir);
  const shouldNudge = !telemetry && grad.recordRunAndCheck(agentName);

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
    const exitCode = await child.exited;

    // Graduation nudge AFTER the agent exits (R2): full-screen TUIs wipe
    // anything printed before they start; after exit the terminal is ours.
    if (shouldNudge) {
      process.stderr.write(
        `\nbeagle: you've run ${agentName} under Beagle a few times.\n` +
          `  Watch it automatically so you never have to prefix again? Run: beagle watch ${agentName}\n` +
          `  (one-time nudge; it won't ask again)\n\n`,
      );
    }
    return exitCode;
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
