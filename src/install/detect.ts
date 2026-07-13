// Agent detection (design §6.12): resolve each supported agent the way the
// user's shell would (PATH walk) plus known install locations (e.g.
// ~/.claude/local). R1's negative case is a specified experience.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { AGENTS } from "../cli/agents";
import { isBeagleShim } from "./shim";

// How codex is signed in — the input to `watch`'s wire-vs-telemetry choice: a
// "Sign in with ChatGPT" login can't be wire-proxied, so watching it in wire
// mode would capture nothing. Reads auth.json (honoring $CODEX_HOME, codex's
// own config-dir override) but ONLY the auth_mode label and key PRESENCE —
// token values never leave the parse.
// How opencode's openai provider is signed in. Its ChatGPT-plan OAuth login
// speaks to OpenAI's Codex backend (https://chatgpt.com/backend-api/codex),
// NOT api.openai.com — the wire redirect must forward to the right upstream
// or every request 404s. Reads ~/.local/share/opencode/auth.json but ONLY the
// per-provider `type` label — credential values never leave the parse.
export function opencodeAuthMode(home: string): "oauth" | "api-key" | "unknown" {
  try {
    const raw = JSON.parse(
      readFileSync(join(home, ".local", "share", "opencode", "auth.json"), "utf8"),
    ) as Record<string, { type?: unknown } | undefined>;
    const t = raw?.openai && typeof raw.openai === "object" ? raw.openai.type : undefined;
    if (t === "oauth") return "oauth";
    if (t === "api" || t === "apikey" || t === "api-key") return "api-key";
    return "unknown";
  } catch {
    return "unknown";
  }
}

export function codexAuthMode(home: string, codexHome?: string): "chatgpt" | "api-key" | "unknown" {
  try {
    const dir = codexHome || join(home, ".codex");
    const raw = JSON.parse(readFileSync(join(dir, "auth.json"), "utf8")) as {
      auth_mode?: unknown;
      OPENAI_API_KEY?: unknown;
      tokens?: unknown;
    };
    // codex ≥0.4x writes an explicit label; trust it first.
    const label = typeof raw?.auth_mode === "string" ? raw.auth_mode.toLowerCase() : "";
    if (label.includes("chatgpt")) return "chatgpt";
    if (label.includes("api")) return "api-key";
    // Older files: infer from which credential is present. ChatGPT tokens win
    // when both exist — codex's own default (preferred_auth_method=chatgpt)
    // uses the login, and the error is asymmetric anyway: telemetry still
    // captures an API-key run, while wire captures nothing of a ChatGPT run.
    if (raw?.tokens && typeof raw.tokens === "object") return "chatgpt";
    if (raw?.OPENAI_API_KEY) return "api-key";
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

// A candidate that is Beagle's OWN shim is never "the agent": listing it in
// `beagle detect` misreports, and resolving it as the real binary writes a
// self-exec'ing shim (fork bomb) or double-wraps `beagle run`. Content-based,
// so symlinked shim dirs and shims from other state dirs are caught too.
function isRealAgentBinary(path: string): boolean {
  return isExecutable(path) && !isBeagleShim(path);
}

export function detectAgents(opts: DetectOptions): DetectedAgent[] {
  const found = new Map<string, string>();
  for (const name of Object.keys(AGENTS)) {
    for (const dir of opts.pathDirs) {
      const p = join(dir, name);
      if (isRealAgentBinary(p)) {
        found.set(name, p);
        break;
      }
    }
  }
  for (const loc of opts.extraLocations) {
    if (!found.has(loc.agent) && existsSync(loc.path) && isRealAgentBinary(loc.path)) found.set(loc.agent, loc.path);
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
