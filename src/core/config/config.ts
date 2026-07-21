// Config + install key (design §6.11). One 0600 file in the state dir;
// defaults are the R11 retention posture.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { loadJsonFile, writeFileAtomic } from "../fs/durable";

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
  const r = loadJsonFile(path);
  if (r.status === "ok") return sanitizeConfig(r.value as Partial<BeagleConfig>);
  if (r.status === "missing") {
    writeFileAtomic(path, JSON.stringify(DEFAULT_CONFIG, null, 2));
    return { ...DEFAULT_CONFIG };
  }
  // Corrupt: run on safe defaults so the daemon never crashes, but LEAVE the bad
  // file in place. `beagle status` reads it and surfaces the corruption; a silent
  // rewrite here would erase the only signal that the user's saved retention /
  // redaction / run-mode settings were lost. An explicit `beagle config …` write
  // replaces it atomically when the user chooses to.
  return { ...DEFAULT_CONFIG };
}

/** Read config WITHOUT creating or repairing anything. For read-only callers
 *  like `beagle status` — loadConfig writes DEFAULT_CONFIG on first run, which
 *  would make the trust strip's "beagle has modified nothing on this system" a
 *  lie by the act of checking. Missing/corrupt → in-memory defaults, no file.
 *  Corruption is surfaced by `beagle status` via loadJsonFile, not swallowed. */
export function readConfig(stateDir: string): BeagleConfig {
  const r = loadJsonFile(join(stateDir, "config.json"));
  return r.status === "ok" ? sanitizeConfig(r.value as Partial<BeagleConfig>) : { ...DEFAULT_CONFIG };
}

/** Merge a parsed config over the defaults, taking each field ONLY when it is
 *  the right type and range — a hand-edited `payloadWindowDays: "bad"` must not
 *  become NaN and silently disable retention, and `agentRunMode: null` must not
 *  crash command paths that enumerate it. Anything off falls back per field to
 *  the secure default; unknown keys are dropped. */
export function sanitizeConfig(raw: Partial<BeagleConfig>): BeagleConfig {
  const c: BeagleConfig = { ...DEFAULT_CONFIG };
  // A file that parses to null / a scalar / an array is not a config object —
  // every field falls back. (Also makes this total: without the guard a `null`
  // raw crashes at `raw.redactOnCapture`, previously masked only by a try/catch.)
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return c;
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
  // Atomic: a crash or full disk mid-write must never leave a truncated
  // config.json that silently loads as defaults on the next start.
  writeFileAtomic(join(stateDir, "config.json"), JSON.stringify(config, null, 2));
}

export function loadOrCreateInstallKey(stateDir: string): Uint8Array {
  const path = join(stateDir, "install.key");
  if (existsSync(path)) {
    const raw = readFileSync(path);
    if (raw.length === 32) return new Uint8Array(raw);
  }
  // Atomic: a torn write would fail the length check next start and silently
  // regenerate the key, breaking every stored leak fingerprint's continuity.
  const key = randomBytes(32);
  writeFileAtomic(path, key);
  return new Uint8Array(key);
}
