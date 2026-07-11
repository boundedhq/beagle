// CLI entry point (non-core). Headless loop per R12: run, status, search,
// leaks, show, purge — the whole product without the viewer.
import {
  cmdConfig, cmdDetect, cmdLeaks, cmdPurge, cmdRun, cmdSearch, cmdShow, cmdStatus,
  cmdUnwatch, cmdWatch, defaultStateDir,
} from "./commands";

export const VERSION = "0.1.0";

const HELP = `beagle ${VERSION} — a local transparency proxy for AI agents

usage:
  beagle run <agent> [args...]   watch one agent run (claude, codex)
  beagle run claude --telemetry  watch via Claude Code's own telemetry
                                 (for Claude.ai subscription logins — nothing
                                 sits on the wire; capture is agent-reported)
  beagle watch <agent> [--yes]   watch an agent automatically (PATH shim)
  beagle unwatch <agent>         stop watching, restore your setup
  beagle detect                  find supported agents on this machine
  beagle status                  trust strip: coverage, store, retention
  beagle search <string>         was this ever sent? definitive answer
  beagle leaks                   the leak log
  beagle show <id-prefix>        one exchange, summarized
  beagle purge [all|panic]       erase captured data
  beagle config [...]            view/set redact-on-capture, exclusions
  beagle ui                      open the dashboard (fresh one-time link)
  beagle daemon                  run the daemon in the foreground
`;

export async function run(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const stateDir = defaultStateDir();
  switch (cmd) {
    case "--version":
    case "-v":
      console.log(`beagle ${VERSION}`);
      return 0;
    case "run": {
      const [agent, ...agentArgs] = rest;
      if (!agent) { console.error("usage: beagle run <agent> [args...]"); return 2; }
      return cmdRun(stateDir, agent, agentArgs);
    }
    case "watch": {
      const agent = rest.find((a) => !a.startsWith("--"));
      if (!agent) { console.error("usage: beagle watch <agent> [--yes]"); return 2; }
      console.log(cmdWatch(stateDir, agent, rest.includes("--yes")));
      return 0;
    }
    case "unwatch": {
      if (!rest[0]) { console.error("usage: beagle unwatch <agent>"); return 2; }
      console.log(cmdUnwatch(stateDir, rest[0]));
      return 0;
    }
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
        if (r.ok) info = raw;
      } catch { /* not running */ }
      console.log(cmdStatus(stateDir, info));
      return 0;
    }
    case "search": {
      const term = rest.join(" ");
      if (!term) { console.error("usage: beagle search <string>"); return 2; }
      console.log(cmdSearch(stateDir, term));
      return 0;
    }
    case "leaks":
      console.log(cmdLeaks(stateDir));
      return 0;
    case "show": {
      if (!rest[0]) { console.error("usage: beagle show <exchange-id-prefix>"); return 2; }
      console.log(cmdShow(stateDir, rest[0]));
      return 0;
    }
    case "purge": {
      console.log(await cmdPurge(stateDir, rest[0] ?? "all"));
      return 0;
    }
    case "ui": {
      const { cmdUi } = await import("./commands");
      console.log(await cmdUi(stateDir));
      return 0;
    }
    case "config":
      console.log(await cmdConfig(stateDir, rest));
      return 0;
    case "daemon": {
      const { Daemon } = await import("../daemon/daemon");
      const daemon = await Daemon.start({ stateDir });
      console.log(`beagled: proxy on 127.0.0.1:${daemon.proxyPort}, control at ${daemon.socketPath}`);
      const shutdown = () => void daemon.stop().then(() => process.exit(0));
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
      await new Promise(() => {}); // run until signaled
      return 0;
    }
    default:
      console.log(HELP);
      if (!cmd) console.log(cmdDetect()); // R1: bare `beagle` tells you the next command
      return cmd ? 2 : 0;
  }
}

if (import.meta.main) {
  process.exit(await run(process.argv.slice(2)));
}
