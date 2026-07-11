// CLI command surface (design §6.9): the whole product headless. Reads open
// the store read-only (work daemon-down); live actions ride the socket.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { Store, StoreVersionError } from "../core/store/store";
import { loadConfig } from "../core/config/config";
import { controlRequest } from "../daemon/control";
import { Notifier, stripControlChars } from "../notifier/notifier";
import { GraduationTracker } from "../install/graduation";
import { detectAgents, knownExtraLocations, pathDirsFromEnv } from "../install/detect";
import { watchAgent, unwatchAgent, type WatchEnv } from "../install/watch";
import { ChangeManifest } from "../install/manifest";
import { AGENTS, buildRunEnv } from "./agents";

// Everything printed by these commands can embed traffic-derived text
// (summaries, session ids from parsed content) — sanitize at the boundary,
// the terminal-escape-injection rule from design §6.10.
const clean = stripControlChars;

export function defaultStateDir(): string {
  if (process.env.BEAGLE_STATE_DIR) return process.env.BEAGLE_STATE_DIR;
  const base = process.env.XDG_STATE_HOME ?? join(homedir(), ".local", "state");
  return join(base, "beagle");
}

function openStore(stateDir: string): Store | null {
  if (!existsSync(join(stateDir, "beagle.db"))) return null;
  return Store.openReadOnly(stateDir);
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

export function cmdStatus(stateDir: string, daemonUp: DaemonInfo | null = null): string {
  const lines: string[] = [];
  if (daemonUp) {
    lines.push(`daemon: running (pid ${daemonUp.pid}, proxy 127.0.0.1:${daemonUp.proxyPort})`);
  } else {
    lines.push("daemon: not running — agents launched now go DIRECT (unmonitored)");
  }
  let store: Store | null = null;
  try {
    store = openStore(stateDir);
  } catch (e) {
    if (e instanceof StoreVersionError) return lines.concat(e.message).join("\n");
    throw e;
  }
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
    beagleBinary: process.execPath,
    shell: process.env.SHELL ?? "/bin/sh",
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

export async function cmdUi(stateDir: string): Promise<string> {
  const daemon = await pingDaemon(stateDir);
  if (!daemon) return "the beagle daemon isn't running — start an agent with `beagle run <agent>` first.";
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

export async function cmdRun(stateDir: string, agentName: string, rawArgs: string[]): Promise<number> {
  const spec = AGENTS[agentName];
  if (!spec) {
    console.error(`unknown agent '${agentName}' — supported: ${Object.keys(AGENTS).join(", ")}`);
    return 2;
  }
  if (!spec.baseUrlEnv) {
    console.error(
      `${agentName} is config-driven; wrapper support arrives with 'beagle watch' — coming in a following release.`,
    );
    return 2;
  }
  // The shim invokes: beagle run <agent> --real <path> -- <args...>
  let realBinary = spec.command;
  let agentArgs = rawArgs;
  const realIdx = rawArgs.indexOf("--real");
  if (realIdx !== -1 && rawArgs[realIdx + 1]) {
    realBinary = rawArgs[realIdx + 1]!;
    const sep = rawArgs.indexOf("--", realIdx);
    agentArgs = sep !== -1 ? rawArgs.slice(sep + 1) : rawArgs.slice(realIdx + 2);
  }

  let daemon = await pingDaemon(stateDir);
  if (!daemon) {
    const script = process.argv[1];
    const argv =
      script && /\.(ts|js|mjs)$/.test(script)
        ? [process.execPath, script, "daemon"]
        : [process.execPath, "daemon"];
    const child = Bun.spawn(argv, {
      env: { ...process.env, BEAGLE_STATE_DIR: stateDir },
      stdio: ["ignore", "ignore", "ignore"],
    });
    child.unref();
    for (let i = 0; i < 40 && !daemon; i++) {
      await Bun.sleep(100);
      daemon = await pingDaemon(stateDir);
    }
  }

  if (!daemon) {
    // Proxy-down: v1 fails OPEN (observe-only, nothing to protect) but says so
    // unmissably via an OS notification — a printed line dies with the first
    // alternate-screen redraw of a TUI (R2, §8 failure table).
    notifyProxyDown(agentName);
    const direct = Bun.spawn([realBinary, ...agentArgs], { stdio: ["inherit", "inherit", "inherit"] });
    return await direct.exited;
  }

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

  // Graduation nudge after the 3rd wrapper run (R2) — never applies anything.
  const grad = new GraduationTracker(stateDir);
  if (grad.recordRunAndCheck(agentName)) {
    process.stderr.write(
      `\nbeagle: you've run ${agentName} under Beagle a few times.\n` +
        `  Watch it automatically so you never have to prefix again? Run: beagle watch ${agentName}\n` +
        `  (one-time nudge; it won't ask again)\n\n`,
    );
  }

  const env = { ...process.env, ...buildRunEnv(agentName, daemon.proxyPort, runId) };
  const child = Bun.spawn([realBinary, ...agentArgs], { env, stdio: ["inherit", "inherit", "inherit"] });
  return await child.exited;
}

function notifyProxyDown(agent: string): void {
  const notifier = new Notifier();
  notifier.notify({
    title: "Beagle isn't running",
    body: `${agent} is NOT being monitored — its traffic is going direct to the provider.`,
  });
  process.stderr.write(`beagle ▲ not running — ${agent} is NOT being monitored (traffic goes direct).\n`);
}
