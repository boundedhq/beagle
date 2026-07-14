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
    return { ...DEFAULT_CONFIG, ...(JSON.parse(readFileSync(path, "utf8")) as Partial<BeagleConfig>) };
  } catch {
    return { ...DEFAULT_CONFIG }; // corrupt config: defaults, never crash the daemon
  }
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
