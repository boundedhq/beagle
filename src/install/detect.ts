// Agent detection (design §6.12): resolve each supported agent the way the
// user's shell would (PATH walk) plus known install locations (e.g.
// ~/.claude/local). R1's negative case is a specified experience.
import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { AGENTS } from "../cli/agents";

export interface DetectedAgent {
  agent: string;
  path: string;
  runCommand: string;
}

export interface DetectOptions {
  pathDirs: string[];
  extraLocations: Array<{ agent: string; path: string }>;
}

function isExecutable(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

export function detectAgents(opts: DetectOptions): DetectedAgent[] {
  const found = new Map<string, string>();
  for (const name of Object.keys(AGENTS)) {
    for (const dir of opts.pathDirs) {
      const p = join(dir, name);
      if (isExecutable(p)) {
        found.set(name, p);
        break;
      }
    }
  }
  for (const loc of opts.extraLocations) {
    if (!found.has(loc.agent) && existsSync(loc.path)) found.set(loc.agent, loc.path);
  }
  return [...found.entries()].map(([agent, path]) => ({
    agent,
    path,
    runCommand: `beagle run ${agent}`,
  }));
}

export function pathDirsFromEnv(pathEnv: string | undefined): string[] {
  return (pathEnv ?? "").split(":").filter(Boolean);
}

export function knownExtraLocations(home: string): Array<{ agent: string; path: string }> {
  return [{ agent: "claude", path: join(home, ".claude", "local", "claude") }];
}
