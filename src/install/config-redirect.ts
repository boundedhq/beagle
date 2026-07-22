// Beagle-owned config redirect (design R2) for config-driven agents that read
// their model base URL from a config file rather than an env var (opencode:
// `provider.<id>.options.baseURL`). Beagle writes a merged copy of the user's
// real config with the baseURL pointed at the proxy, and points the agent at
// it via its config-path override env — the user's real config stays untouched.
// Non-core.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { writeFileAtomic } from "../core/fs/durable";

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
  const path = join(stateDir, "agent-config", `${agent}.json`);
  writeFileAtomic(path, JSON.stringify(config, null, 2));
  return path;
}

/** Source of a Beagle-owned pi extension that re-points one provider at the
 *  proxy for this run. pi loads it via `-e <file>`; overriding only `baseUrl`
 *  keeps every existing model on the provider (per pi's custom-provider docs).
 *  Deliberately import-free (`pi: any`) — the file runs inside pi's own
 *  loader, and a bare function can never fail module resolution there. */
export function buildExtensionRedirect(provider: string, baseUrl: string): string {
  return (
    "// Beagle-owned redirect (generated per run; deleted when the run ends).\n" +
    "// Points pi's provider at the local Beagle proxy — nothing else changes.\n" +
    "export default function (pi: any) {\n" +
    `  pi.registerProvider(${JSON.stringify(provider)}, { baseUrl: ${JSON.stringify(baseUrl)} });\n` +
    "}\n"
  );
}

/** Write the Beagle-owned extension into the state dir (0600); return its path. */
export function writeRedirectExtension(stateDir: string, agent: string, source: string): string {
  const path = join(stateDir, "agent-config", `${agent}.ts`);
  writeFileAtomic(path, source);
  return path;
}
