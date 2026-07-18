// CLI entry point (non-core). Headless loop per R12: run, status, search,
// leaks, show, purge — the whole product without the viewer.
import {
  cmdConfig, cmdDetect, cmdHookForward, cmdLeaks, cmdPurge, cmdRun, cmdSearch, cmdShow,
  cmdStatus, cmdStop, cmdUninstall, cmdUnwatch, cmdUnwatchAll, cmdUnwatchSelect, cmdWatch,
  defaultStateDir, offerRefreshedShell, parseWatchArgs, readLineSync,
} from "./commands";
import { BEAGLE_VERSION } from "../core/version";

export const VERSION = BEAGLE_VERSION;

const HELP = `beagle ${VERSION} — a local transparency proxy for AI agents

usage:
  beagle run <agent> [args...]   watch one agent run (claude, codex, opencode, pi)
  beagle run <agent> [--telemetry|--wire]
                                 subscription logins (claude, codex) capture
                                 via the agent's own telemetry — detected
                                 automatically; Beagle asks once if it can't
                                 tell. Flags force a mode.
  beagle watch <agent> [--yes]   watch an agent automatically (PATH shim);
                                 subscription logins auto-detected (claude,
                                 codex); --telemetry/--wire to force a mode
  beagle unwatch [<agent>|--all] [--force]
                                 stop watching, restore your setup (no agent:
                                 pick from what's watched; --all: every agent;
                                 removes the shell-rc PATH block and stops the
                                 daemon once nothing is left watched; refuses
                                 mid-capture unless --force)
  beagle stop [--force]          stop the background daemon and pause the
                                 always-on service until the next watch
                                 (refuses while a session is being captured)
  beagle detect                  find supported agents on this machine
  beagle status                  trust strip: coverage, store, retention
  beagle search [string]         was this ever sent? definitive answer
                                 (no argument: reads the term from stdin, so
                                 secrets stay out of your shell history)
  beagle leaks                   the leak log, grouped by session
  beagle show <id-prefix>        one call: leaks, provenance, what was sent
                                 and received (--full: every message; --raw:
                                 exact bytes)
  beagle purge [all|panic]       erase captured data
  beagle uninstall [--yes]       remove everything Beagle installed (unwatch
                                 all, stop the daemon, erase data, remove the
                                 state dir) — the binary you remove yourself
  beagle config [...]            view/set redact-on-capture, exclusions,
                                 run-mode <agent> <wire|telemetry|auto>
  beagle ui [--session <id>]     open the dashboard (fresh one-time link);
                                 --session lands on that session's transcript
  beagle daemon                  run the daemon in the foreground
  beagle help                    this text
`;

export async function run(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const stateDir = defaultStateDir();
  switch (cmd) {
    case "--version":
    case "-v":
      console.log(`beagle ${VERSION}`);
      return 0;
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      return 0;
    case "run": {
      const [agent, ...agentArgs] = rest;
      if (!agent) { console.error("usage: beagle run <agent> [args...]"); return 2; }
      return cmdRun(stateDir, agent, agentArgs);
    }
    case "watch": {
      const parsed = parseWatchArgs(rest);
      if ("error" in parsed) { console.error(parsed.error); return 2; }
      const r = cmdWatch(stateDir, parsed.agent, parsed.yes, parsed.mode);
      console.log(r.message);
      if (r.ok && r.shellReloadHint) {
        const launched = parsed.yes ? false : await offerRefreshedShell();
        if (!launched)
          console.log("  (open a new terminal, or run `exec $SHELL -l` here, to pick up the change)");
      }
      return r.ok ? 0 : 1;
    }
    case "unwatch": {
      // Reject unknown flags like `watch` does — unwatch is the destructive
      // sibling, so a typo (`--al`, `--froce`) must fail loudly, not silently
      // fall into the picker or run unforced.
      const bad = rest.find((a) => a.startsWith("--") && a !== "--force" && a !== "--all");
      if (bad) { console.error(`beagle unwatch: unknown flag ${bad}\nusage: beagle unwatch [<agent>|--all] [--force]`); return 2; }
      const agent = rest.find((a) => !a.startsWith("--"));
      const force = rest.includes("--force");
      if (rest.includes("--all")) {
        if (agent) { console.error("beagle unwatch --all takes no agent (it unwatches everything)."); return 2; }
        console.log(await cmdUnwatchAll(stateDir, force));
        return 0;
      }
      if (!agent) { console.log(await cmdUnwatchSelect(stateDir, force)); return 0; }
      console.log(await cmdUnwatch(stateDir, agent, force));
      return 0;
    }
    case "stop":
      console.log(await cmdStop(stateDir, rest.includes("--force")));
      return 0;
    case "detect":
      console.log(cmdDetect());
      return 0;
    case "status": {
      const { controlRequest } = await import("../daemon/control");
      const { readFileSync } = await import("node:fs");
      const { join } = await import("node:path");
      let info = null;
      try {
        const raw = JSON.parse(readFileSync(join(stateDir, "daemon.json"), "utf8"));
        const r = await controlRequest(raw.socketPath, { cmd: "ping" }, 800);
        if (r.ok) {
          // Ping proved the daemon is up — record that first and never retract
          // it: controlRequest REJECTS on timeout/socket error, so enriching
          // inside this same try would report "not running" for a daemon that
          // is running and capturing.
          info = raw;
          try {
            // The daemon knows why it is up (live sessions, open dashboard,
            // never-idle-exits) — surface that instead of a bare "running".
            const st = await controlRequest(raw.socketPath, { cmd: "status" }, 800);
            if (st.ok) {
              const d = st.data as Record<string, unknown>;
              info = { ...raw, leases: d.leases, viewerOpen: d.viewerOpen, persistent: d.persistent };
            }
          } catch { /* reason unknown; the plain "running" line still holds */ }
        }
      } catch { /* not running */ }
      console.log(cmdStatus(stateDir, info));
      return 0;
    }
    case "search": {
      // No argument → read the term from stdin (`pbpaste | beagle search`),
      // so a real secret never has to appear in argv / shell history.
      let term = rest.join(" ");
      if (!term) {
        if (process.stdin.isTTY) console.error("beagle: paste the term to search, then press Enter:");
        term = readLineSync().trim();
      }
      if (!term) { console.error("usage: beagle search [string]  (or pipe the term via stdin)"); return 2; }
      console.log(cmdSearch(stateDir, term));
      return 0;
    }
    case "leaks":
      console.log(cmdLeaks(stateDir));
      return 0;
    case "show": {
      const id = rest.find((a) => !a.startsWith("-"));
      if (!id) { console.error("usage: beagle show <call-id-prefix> [--full] [--raw]"); return 2; }
      console.log(cmdShow(stateDir, id, { full: rest.includes("--full"), raw: rest.includes("--raw") }));
      return 0;
    }
    case "purge": {
      console.log(await cmdPurge(stateDir, rest[0] ?? "all"));
      return 0;
    }
    case "uninstall":
      console.log(await cmdUninstall(stateDir, rest.includes("--yes") || rest.includes("-y")));
      return 0;
    case "ui": {
      const { cmdUi } = await import("./commands");
      const si = rest.indexOf("--session");
      if (si !== -1 && !rest[si + 1]) {
        console.error("usage: beagle ui [--session <id>]");
        return 2;
      }
      console.log(await cmdUi(stateDir, si !== -1 ? rest[si + 1] : undefined));
      return 0;
    }
    case "config":
      console.log(await cmdConfig(stateDir, rest));
      return 0;
    case "daemon": {
      const { Daemon } = await import("../daemon/daemon");
      // An explicitly-launched `beagle daemon` (foreground or service unit)
      // stays up; only the one auto-started by `beagle run` is ephemeral and
      // idle-exits (BEAGLE_EPHEMERAL, set by that spawn). BEAGLE_IDLE_MS tunes
      // the grace period.
      const idleEnv = Number(process.env.BEAGLE_IDLE_MS);
      const daemon = await Daemon.start({
        stateDir,
        persistent: process.env.BEAGLE_EPHEMERAL !== "1",
        idleTimeoutMs: Number.isFinite(idleEnv) && idleEnv > 0 ? idleEnv : undefined,
      });
      console.log(`beagled: proxy on 127.0.0.1:${daemon.proxyPort}, control at ${daemon.socketPath}`);
      const shutdown = () => void daemon.stop().then(() => process.exit(0));
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
      await new Promise(() => {}); // run until signaled
      return 0;
    }
    case "__hook":
      // Hidden: Claude Code's PostToolUse hook (Mode B tool-output capture)
      // invokes this to forward the tool result to the loopback receiver.
      return await cmdHookForward();
    default:
      console.log(HELP);
      if (!cmd) console.log(cmdDetect()); // R1: bare `beagle` tells you the next command
      return cmd ? 2 : 0;
  }
}

if (import.meta.main) {
  process.exit(await run(process.argv.slice(2)));
}
