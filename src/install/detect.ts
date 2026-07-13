// Agent detection (design §6.12): resolve each supported agent the way the
// user's shell would (PATH walk) plus known install locations (e.g.
// ~/.claude/local). R1's negative case is a specified experience.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { AGENTS } from "../cli/agents";

// How codex is signed in — the input to `watch`'s wire-vs-telemetry choice: a
// "Sign in with ChatGPT" login can't be wire-proxied, so watching it in wire
// mode would capture nothing. Reads ~/.codex/auth.json but ONLY the auth_mode
// label and key PRESENCE — token values never leave the parse.
export function codexAuthMode(home: string): "chatgpt" | "api-key" | "unknown" {
  try {
    const raw = JSON.parse(readFileSync(join(home, ".codex", "auth.json"), "utf8")) as {
      auth_mode?: unknown;
      OPENAI_API_KEY?: unknown;
      tokens?: unknown;
    };
    // codex ≥0.4x writes an explicit label; trust it first.
    const label = typeof raw?.auth_mode === "string" ? raw.auth_mode.toLowerCase() : "";
    if (label.includes("chatgpt")) return "chatgpt";
    if (label.includes("api")) return "api-key";
    // Older files: infer from which credential is present.
    if (raw?.OPENAI_API_KEY) return "api-key";
    if (raw?.tokens && typeof raw.tokens === "object") return "chatgpt";
    return "unknown";
  } catch {
    return "unknown"; // no auth.json / unreadable → never block, just don't auto-pick
  }
}

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
