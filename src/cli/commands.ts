// CLI command surface (design §6.9): the whole product headless. Reads open
// the store read-only (work daemon-down); live actions ride the socket.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { Store, StoreVersionError } from "../core/store/store";
import { loadConfig } from "../core/config/config";
import { controlRequest } from "../daemon/control";
import { stripControlChars } from "../notifier/notifier";
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

export async function cmdRun(stateDir: string, agentName: string, agentArgs: string[]): Promise<number> {
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
  let daemon = await pingDaemon(stateDir);
  if (!daemon) {
    // Compiled binary: argv[1] is not a script path — invoke ourselves
    // directly. Dev (bun run): re-run the entry script.
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
    if (!daemon) {
      console.error("could not start the beagle daemon");
      return 1;
    }
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
  const env = { ...process.env, ...buildRunEnv(agentName, daemon.proxyPort, runId) };
  const child = Bun.spawn([spec.command, ...agentArgs], { env, stdio: ["inherit", "inherit", "inherit"] });
  return await child.exited;
}
