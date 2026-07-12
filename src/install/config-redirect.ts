// Beagle-owned config redirect (design R2) for config-driven agents that read
// their model base URL from a config file rather than an env var (opencode:
// `provider.<id>.options.baseURL`). Beagle writes a merged copy of the user's
// real config with the baseURL pointed at the proxy, and points the agent at
// it via its config-path override env — the user's real config stays untouched.
// Non-core.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export function deepSet(obj: Record<string, any>, path: string[], value: unknown): void {
  let cur = obj;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i]!;
    if (typeof cur[key] !== "object" || cur[key] === null) cur[key] = {};
    cur = cur[key];
  }
  cur[path[path.length - 1]!] = value;
}

/** Deep-clone the user's config (or start empty) and set the proxy baseURL. */
export function buildRedirectConfig(
  userConfig: Record<string, unknown> | null,
  baseUrlPath: string[],
  baseUrl: string,
): Record<string, unknown> {
  const merged = userConfig ? structuredClone(userConfig) : {};
  deepSet(merged, baseUrlPath, baseUrl);
  return merged;
}

/** First existing config file among candidates, parsed; null if none/malformed. */
export function readFirstConfig(candidates: string[]): Record<string, unknown> | null {
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    try {
      return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    } catch {
      return null; // malformed user config: fall back to a bare override
    }
  }
  return null;
}

/** Write the Beagle-owned config into the state dir (0600); return its path. */
export function writeRedirectConfig(
  stateDir: string,
  agent: string,
  config: Record<string, unknown>,
): string {
  const dir = join(stateDir, "agent-config");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, `${agent}.json`);
  writeFileSync(path, JSON.stringify(config, null, 2), { mode: 0o600 });
  return path;
}
