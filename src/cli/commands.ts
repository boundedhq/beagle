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
import { buildOtelEnv } from "../parsers/otlp-map";
import { buildRedirectConfig, readFirstConfig, writeRedirectConfig } from "../install/config-redirect";
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
  const exchanges = store?.countExchanges() ?? 0;
  const leaks = store?.countLeakEvents() ?? 0;
  store?.close();
  const dbPath = join(stateDir, "beagle.db");
  const sizeMb = existsSync(dbPath) ? (statSync(dbPath).size / (1 << 20)).toFixed(1) : "0.0";
  const cfg = loadConfig(stateDir);
  lines.push(`exchanges: ${exchanges} · leaks: ${leaks} · store: ${sizeMb} MB`);
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
    `found in ${hits.length} exchange${hits.length === 1 ? "" : "s"} across ${sessions.size} session${sessions.size === 1 ? "" : "s"}:`,
  ];
  for (const h of hits) {
    lines.push(`  ${h.exchangeId.slice(0, 8)}  ${new Date(h.tsRequest).toISOString()}  session ${clean(h.sessionId).slice(0, 8)}`);
  }
  return lines.join("\n");
}

export function cmdLeaks(stateDir: string): string {
  const store = openStore(stateDir);
  if (isStoreError(store)) return store.error;
  if (!store) return "no leaks recorded.";
  const events = store.listLeakEvents();
  store.close();
  if (events.length === 0) return "no leaks recorded.";
  const lines = [`${events.length} leak event${events.length === 1 ? "" : "s"}:`];
  for (const e of events) {
    const tier = e.confidenceTier === "structured" ? "" : " (possible)";
    lines.push(
      `  ${new Date(e.firstTs).toISOString()}  ${clean(e.secretType)}${tier} → ${clean(e.destination)}` +
        `  ×${e.occurrences}${e.firstExchange ? `  first: ${e.firstExchange.slice(0, 8)}` : ""}`,
    );
  }
  return lines.join("\n");
}

export function cmdShow(stateDir: string, idPrefix: string): string {
  const store = openStore(stateDir);
  if (isStoreError(store)) return store.error;
  const ex = store?.getExchange(idPrefix) ?? null;
  store?.close();
  if (!ex) return `no exchange matches '${idPrefix}' (prefix may be ambiguous or unknown).`;
  const lines = [
    `exchange ${ex.id}`,
    `  ${clean(ex.agent ?? "?")} → ${clean(ex.provider ?? "?")}${ex.model ? `/${clean(ex.model)}` : ""}  ${clean(ex.endpoint ?? "")}`,
    `  at ${new Date(ex.tsRequest).toISOString()}  status ${ex.status ?? "?"}  tokens ${ex.tokensIn ?? "?"}→${ex.tokensOut ?? "?"}`,
    `  session ${ex.sessionId.slice(0, 8)} (keyed by ${ex.sessionTier})  run ${clean(ex.runId)}`,
    `  summary: ${clean(ex.summary ?? "—")}`,
  ];
  if (ex.scanState !== "ok") {
    lines.push("  ⚠ scan timed out — treated as unverified, not clean");
  }
  if (ex.captureState !== "ok") {
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

function readLineSync(): string {
  try {
    const buf = new Uint8Array(256);
    const n = require("node:fs").readSync(0, buf, 0, 256, null) as number;
    return new TextDecoder().decode(buf.subarray(0, n));
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
  // of the wire — for Claude Code on a Claude.ai subscription, where putting
  // a proxy on the wire is off-limits. Capture is labeled agent-reported.
  const { telemetry, realBinary: realOverride, agentArgs } = parseRunArgs(rawArgs);
  if (telemetry && agentName !== "claude") {
    console.error("--telemetry (agent self-report capture) is supported for claude only in v1.");
    return 2;
  }
  if (!telemetry && !spec.baseUrlEnv && !spec.config) {
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

  let modeEnv: Record<string, string>;
  if (telemetry) {
    // Nothing goes on the wire: point the agent's own OTel exporter at the
    // daemon's loopback receiver, authed by the per-session run token.
    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort?: number; otlpToken?: string } | undefined;
    if (!status.ok || !data?.otlpPort || !data.otlpToken) {
      console.error("could not read the telemetry receiver from the daemon — try `beagle status`.");
      return 1;
    }
    modeEnv = buildOtelEnv(`http://127.0.0.1:${data.otlpPort}`, data.otlpToken);
  } else {
    const runId = randomUUID();
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
    let redirectCfg: string | null = null;
    if (spec.config) {
      // Config-driven agent (opencode): write a Beagle-owned config that
      // merges the user's real settings with the proxy baseURL, and point the
      // agent at it — the user's real config is never touched.
      const baseUrl = runBaseUrl(daemon.proxyPort, runId);
      const userCfg = readFirstConfig(spec.config.realConfigCandidates(homedir()));
      const merged = buildRedirectConfig(userCfg, spec.config.baseUrlPath, baseUrl);
      redirectCfg = writeRedirectConfig(stateDir, agentName, merged);
      modeEnv = { [spec.config.configEnv]: redirectCfg };
    } else {
      modeEnv = buildRunEnv(agentName, daemon.proxyPort, runId);
    }
    return await execAgent(daemon.socketPath, realBinary, agentArgs, modeEnv, stateDir, agentName, redirectCfg);
  }

  return await execAgent(daemon.socketPath, realBinary, agentArgs, modeEnv, stateDir, agentName, null);
}

async function execAgent(
  socketPath: string,
  realBinary: string,
  agentArgs: string[],
  modeEnv: Record<string, string>,
  stateDir: string,
  agentName: string,
  redirectCfg: string | null,
): Promise<number> {
  const grad = new GraduationTracker(stateDir);
  const shouldNudge = grad.recordRunAndCheck(agentName);

  // Hold a lease for the agent's lifetime so an auto-started ephemeral daemon
  // stays up while we're watching, then winds down after we exit (§6.7). Both
  // wire and telemetry modes need this — Mode B registers no run.
  const lease = await openLease(socketPath).catch(() => null);

  try {
    const child = Bun.spawn([realBinary, ...agentArgs], {
      env: { ...process.env, ...modeEnv },
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
