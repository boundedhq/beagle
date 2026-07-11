// Config + install key (design §6.11). One 0600 file in the state dir;
// defaults are the R11 retention posture.
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

export interface BeagleConfig {
  payloadWindowDays: number;
  sizeCapMB: number;
  eventWindowDays: number;
  redactOnCapture: boolean;
  excludedAgents: string[];
}

export const DEFAULT_CONFIG: BeagleConfig = {
  payloadWindowDays: 7,
  sizeCapMB: 1024,
  eventWindowDays: 90,
  redactOnCapture: false,
  excludedAgents: [],
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
  writeFileSync(join(stateDir, "config.json"), JSON.stringify(config, null, 2), { mode: 0o600 });
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
