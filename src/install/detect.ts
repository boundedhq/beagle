// Agent detection (design §6.12): resolve each supported agent the way the
// user's shell would (PATH walk) plus known install locations (e.g.
// ~/.claude/local). R1's negative case is a specified experience.
import {
  accessSync, constants as fsConstants, existsSync, readFileSync, statSync,
} from "node:fs";
import { join } from "node:path";
import { AGENTS, UNSUPPORTED_AGENTS } from "../cli/agents";
import { isBeagleShim } from "./shim";

// How opencode's openai provider is signed in. Its ChatGPT-plan OAuth login
// speaks to OpenAI's Codex backend (https://chatgpt.com/backend-api/codex),
// NOT api.openai.com — the wire redirect must forward to the right upstream
// or every request 404s. Reads opencode's auth.json (honoring $XDG_DATA_HOME,
// which opencode itself resolves its data dir through, else ~/.local/share)
// but ONLY the per-provider `type` label — credential values never leave the
// parse. `xdgDataHome` is injectable for tests.
export function opencodeAuthMode(home: string, xdgDataHome?: string): "oauth" | "api-key" | "unknown" {
  try {
    const dataDir = xdgDataHome || join(home, ".local", "share");
    const raw = JSON.parse(
      readFileSync(join(dataDir, "opencode", "auth.json"), "utf8"),
    ) as Record<string, { type?: unknown } | undefined>;
    const t = raw?.openai && typeof raw.openai === "object" ? raw.openai.type : undefined;
    if (t === "oauth") return "oauth";
    if (t === "api" || t === "apikey" || t === "api-key") return "api-key";
    return "unknown";
  } catch {
    return "unknown";
  }
}

// Which provider pi is signed in with — and where that provider's traffic
// goes. Unlike the other agents, pi bakes each provider's base URL into its
// models and authenticates from its OWN store (~/.pi/agent/auth.json), so the
// wire redirect must re-point whichever provider pi is ACTUALLY using; a fixed
// one captures nothing. Reads the default-provider label from settings.json
// (falling back to the sole logged-in provider when none is set) and maps it to
// its upstream — labels/PRESENCE only, the OAuth tokens never leave the parse.
// Beagle wire-captures pi's OpenAI-family logins: `openai` (API key →
// api.openai.com) and `openai-codex` (ChatGPT Plus/Pro OAuth → the same Codex
// backend as codex/opencode subscriptions). `piAgentDir` is injectable for tests.
export interface PiProvider {
  provider: string;
  upstream: string;
}
const PI_UPSTREAMS: Record<string, string> = {
  // pi's openai provider appends /responses to this base.
  openai: "https://api.openai.com/v1",
  // pi's openai-codex provider appends /codex/responses to this base; its
  // OAuth login speaks to the ChatGPT backend, never api.openai.com.
  "openai-codex": "https://chatgpt.com/backend-api",
};
export function piProvider(home: string, piAgentDir?: string): PiProvider | undefined {
  const dir = piAgentDir || join(home, ".pi", "agent");
  let provider = "";
  try {
    const settings = JSON.parse(readFileSync(join(dir, "settings.json"), "utf8")) as { defaultProvider?: unknown };
    if (typeof settings?.defaultProvider === "string") provider = settings.defaultProvider;
  } catch {
    /* no settings.json / unreadable → fall through to the login list */
  }
  if (!provider) {
    // No default recorded: the redirect is unambiguous only if exactly one
    // Beagle-supported provider is logged in — otherwise we can't know which pi
    // would pick. Filter to known providers so a future non-provider metadata
    // key in auth.json (a "version"/"$schema" field) can't miscount the logins.
    try {
      const auth = JSON.parse(readFileSync(join(dir, "auth.json"), "utf8")) as Record<string, unknown>;
      const logins = Object.keys(auth ?? {}).filter((k) => Object.hasOwn(PI_UPSTREAMS, k));
      if (logins.length === 1) provider = logins[0]!;
    } catch {
      /* no auth.json / unreadable */
    }
  }
  // Object.hasOwn, not `provider in PI_UPSTREAMS` / a bare index: a config value
  // that happens to be a prototype key (`constructor`, `toString`, `__proto__`)
  // must resolve to "unknown → undefined", never to an inherited function.
  const upstream = Object.hasOwn(PI_UPSTREAMS, provider) ? PI_UPSTREAMS[provider] : undefined;
  return upstream ? { provider, upstream } : undefined;
}

// How Claude Code is signed in. An ANTHROPIC_API_KEY in the environment means
// API-key traffic (wire-proxyable); a Claude.ai OAuth login leaves an
// `oauthAccount` record in ~/.claude.json (honoring $CLAUDE_CONFIG_DIR). Only
// key PRESENCE is read — account values (email, org) never leave the parse.
// The env var wins when both exist: wire capture is higher fidelity, and the
// zero-capture warning catches a wrong guess.
export function claudeAuthMode(
  home: string,
  hasApiKeyEnv: boolean,
  claudeConfigDir?: string,
): "api-key" | "subscription" | "unknown" {
  if (hasApiKeyEnv) return "api-key";
  // apiKeyHelper in settings.json is Claude Code's env-var-free API-key auth —
  // without this check, such a user with a STALE oauthAccount record from an
  // old Claude.ai login would be misread as subscription and silently
  // downgraded to agent-reported capture.
  try {
    const settingsPath = join(claudeConfigDir ?? join(home, ".claude"), "settings.json");
    const settings = JSON.parse(readFileSync(settingsPath, "utf8")) as { apiKeyHelper?: unknown };
    if (typeof settings?.apiKeyHelper === "string" && settings.apiKeyHelper.length > 0) return "api-key";
  } catch {
    /* no settings.json / unreadable → keep looking */
  }
  try {
    const path = claudeConfigDir ? join(claudeConfigDir, ".claude.json") : join(home, ".claude.json");
    const raw = JSON.parse(readFileSync(path, "utf8")) as { oauthAccount?: unknown };
    if (raw?.oauthAccount && typeof raw.oauthAccount === "object" && Object.keys(raw.oauthAccount).length > 0) {
      return "subscription";
    }
    return "unknown";
  } catch {
    return "unknown";
  }
}

// How codex is signed in — the input to `watch`'s wire-vs-telemetry choice: a
// "Sign in with ChatGPT" login can't be wire-proxied, so watching it in wire
// mode would capture nothing. Reads auth.json (honoring $CODEX_HOME, codex's
// own config-dir override) but ONLY the auth_mode label and key PRESENCE —
// token values never leave the parse.
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

export interface DetectedUnsupportedAgent {
  agent: string;
  displayName: string;
  evidence: "executable" | "configuration";
  note?: string;
}

function isExecutable(path: string): boolean {
  try {
    if (!statSync(path).isFile()) return false;
    accessSync(path, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
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

/** Recognize agents Beagle does not support yet. Like supported detection,
 *  this only inspects local PATH entries/filesystem state and never executes a
 *  candidate or makes a network request. */
export function detectUnsupportedAgents(opts: { pathDirs: string[]; home: string }): DetectedUnsupportedAgent[] {
  const found: DetectedUnsupportedAgent[] = [];
  for (const [agent, spec] of Object.entries(UNSUPPORTED_AGENTS)) {
    const executable = spec.commands.some((name) =>
      opts.pathDirs.some((dir) => isRealAgentBinary(join(dir, name))));
    const configured = !executable && spec.configDirs?.(opts.home).some(isDirectory);
    if (!executable && !configured) continue;
    found.push({
      agent,
      displayName: spec.displayName,
      evidence: executable ? "executable" : "configuration",
      note: spec.note,
    });
  }
  return found;
}

export function pathDirsFromEnv(pathEnv: string | undefined): string[] {
  return (pathEnv ?? "").split(":").filter(Boolean);
}

export function knownExtraLocations(home: string): Array<{ agent: string; path: string }> {
  return [{ agent: "claude", path: join(home, ".claude", "local", "claude") }];
}
