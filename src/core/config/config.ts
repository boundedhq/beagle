// Config + install key (design §6.11). One 0600 file in the state dir;
// defaults are the R11 retention posture.
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

export interface BeagleConfig {
  payloadWindowDays: number;
  sizeCapMB: number;
  eventWindowDays: number;
  redactOnCapture: boolean;
  excludedAgents: string[];
  /** Remembered answer to "API key or subscription?" per agent — how
   *  `beagle run <agent>` captures when no flag is passed. Set by the one-time
   *  prompt or `beagle config run-mode`. Absent = auto-detect each run. */
  agentRunMode: Record<string, "wire" | "telemetry">;
}

export const DEFAULT_CONFIG: BeagleConfig = {
  payloadWindowDays: 7,
  sizeCapMB: 1024,
  eventWindowDays: 90,
  // Secure default: a secret-detection tool must not itself keep detected
  // secrets in cleartext at rest. Only the matched secret spans are masked
  // (`[REDACTED:type:hash]`) — surrounding content stays intact and searchable.
  // Opt out (`beagle config redact-on-capture off`) for the raw-fidelity view.
  redactOnCapture: true,
  excludedAgents: [],
  agentRunMode: {},
};

export function loadConfig(stateDir: string): BeagleConfig {
  const path = join(stateDir, "config.json");
  if (!existsSync(path)) {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    writeFileSync(path, JSON.stringify(DEFAULT_CONFIG, null, 2), { mode: 0o600 });
    return { ...DEFAULT_CONFIG };
  }
  try {
    return sanitizeConfig(JSON.parse(readFileSync(path, "utf8")) as Partial<BeagleConfig>);
  } catch {
    return { ...DEFAULT_CONFIG }; // corrupt config: defaults, never crash the daemon
  }
}

/** Merge a parsed config over the defaults, taking each field ONLY when it is
 *  the right type and range — a hand-edited `payloadWindowDays: "bad"` must not
 *  become NaN and silently disable retention, and `agentRunMode: null` must not
 *  crash command paths that enumerate it. Anything off falls back per field to
 *  the secure default; unknown keys are dropped. */
export function sanitizeConfig(raw: Partial<BeagleConfig>): BeagleConfig {
  const c: BeagleConfig = { ...DEFAULT_CONFIG };
  const posNum = (v: unknown, min: number): number | undefined =>
    typeof v === "number" && Number.isFinite(v) && v >= min ? v : undefined;
  c.payloadWindowDays = posNum(raw.payloadWindowDays, 0) ?? c.payloadWindowDays;
  c.sizeCapMB = posNum(raw.sizeCapMB, 1) ?? c.sizeCapMB;
  c.eventWindowDays = posNum(raw.eventWindowDays, 0) ?? c.eventWindowDays;
  if (typeof raw.redactOnCapture === "boolean") c.redactOnCapture = raw.redactOnCapture;
  if (Array.isArray(raw.excludedAgents)) {
    c.excludedAgents = raw.excludedAgents.filter((a): a is string => typeof a === "string");
  }
  if (raw.agentRunMode && typeof raw.agentRunMode === "object" && !Array.isArray(raw.agentRunMode)) {
    const modes: Record<string, "wire" | "telemetry"> = {};
    for (const [k, v] of Object.entries(raw.agentRunMode)) {
      if (v === "wire" || v === "telemetry") modes[k] = v;
    }
    c.agentRunMode = modes;
  }
  return c;
}

export function saveConfig(stateDir: string, config: BeagleConfig): void {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const path = join(stateDir, "config.json");
  writeFileSync(path, JSON.stringify(config, null, 2), { mode: 0o600 });
  // mode on writeFileSync only applies at creation; enforce on existing files.
  chmodSync(path, 0o600);
}

export function loadOrCreateInstallKey(stateDir: string): Uint8Array {
  const path = join(stateDir, "install.key");
  if (existsSync(path)) {
    const raw = readFileSync(path);
    if (raw.length === 32) return new Uint8Array(raw);
  }
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const key = randomBytes(32);
  writeFileSync(path, key, { mode: 0o600 });
  chmodSync(path, 0o600);
  return new Uint8Array(key);
}
