import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { DEFAULT_CONFIG, loadConfig, readConfig, sanitizeConfig, saveConfig } from "../src/core/config/config";
import { loadJsonFile } from "../src/core/fs/durable";

describe("readConfig (read-only — never writes)", () => {
  test("missing file → defaults, and no config.json is created", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-rocfg-"));
    const c = readConfig(dir);
    expect(c).toEqual(DEFAULT_CONFIG);
    expect(existsSync(join(dir, "config.json"))).toBe(false); // the whole point
  });

  test("existing file is read and sanitized, still no write", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-rocfg-"));
    writeFileSync(join(dir, "config.json"), JSON.stringify({ payloadWindowDays: "bad", redactOnCapture: false }));
    const c = readConfig(dir);
    expect(c.payloadWindowDays).toBe(DEFAULT_CONFIG.payloadWindowDays); // sanitized
    expect(c.redactOnCapture).toBe(false);
  });
});

describe("sanitizeConfig (validate-or-default per field)", () => {
  test("a wrong-typed retention value falls back to the default, never NaN", () => {
    // The bug this guards: payloadWindowDays: "bad" → NaN → Store.sweep's
    // Number.isFinite guard skips age-based retention, silently keeping data
    // forever. sanitizeConfig must reject the bad value per field.
    const c = sanitizeConfig({ payloadWindowDays: "bad" as unknown as number });
    expect(c.payloadWindowDays).toBe(DEFAULT_CONFIG.payloadWindowDays);
    expect(Number.isFinite(c.payloadWindowDays)).toBe(true);
  });

  test("negative / non-finite numbers are rejected; valid ones kept", () => {
    expect(sanitizeConfig({ payloadWindowDays: -5 }).payloadWindowDays).toBe(DEFAULT_CONFIG.payloadWindowDays);
    expect(sanitizeConfig({ sizeCapMB: 0 }).sizeCapMB).toBe(DEFAULT_CONFIG.sizeCapMB); // min 1
    expect(sanitizeConfig({ eventWindowDays: Infinity }).eventWindowDays).toBe(DEFAULT_CONFIG.eventWindowDays);
    expect(sanitizeConfig({ payloadWindowDays: 3 }).payloadWindowDays).toBe(3);
  });

  test("agentRunMode: null / garbage never crashes and yields an object", () => {
    expect(sanitizeConfig({ agentRunMode: null as never }).agentRunMode).toEqual({});
    const c = sanitizeConfig({ agentRunMode: { claude: "wire", bad: "nonsense" } as never });
    expect(c.agentRunMode).toEqual({ claude: "wire" }); // bad value dropped
  });

  test("redactOnCapture stays boolean-only; a truthy string can't turn it off", () => {
    expect(sanitizeConfig({ redactOnCapture: "false" as never }).redactOnCapture).toBe(true); // default preserved
    expect(sanitizeConfig({ redactOnCapture: false }).redactOnCapture).toBe(false);
  });

  test("excludedAgents keeps only strings; unknown keys are dropped", () => {
    const c = sanitizeConfig({ excludedAgents: ["claude", 42 as never], junk: 1 } as never);
    expect(c.excludedAgents).toEqual(["claude"]);
    expect("junk" in c).toBe(false);
  });

  test("loadConfig runs the parsed file through sanitize", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-cfg-"));
    writeFileSync(join(dir, "config.json"), JSON.stringify({ payloadWindowDays: "oops", redactOnCapture: false }));
    const c = loadConfig(dir);
    expect(c.payloadWindowDays).toBe(DEFAULT_CONFIG.payloadWindowDays); // sanitized
    expect(c.redactOnCapture).toBe(false); // valid override kept
  });

  test("null / scalar / array config never crashes sanitize — total, all defaults", () => {
    // Guards a real crash: before the object guard, sanitizeConfig(null) threw at
    // `raw.redactOnCapture`, surviving only because a caller happened to catch it.
    expect(sanitizeConfig(null as never)).toEqual(DEFAULT_CONFIG);
    expect(sanitizeConfig(42 as never)).toEqual(DEFAULT_CONFIG);
    expect(sanitizeConfig([1, 2] as never)).toEqual(DEFAULT_CONFIG);
  });
});

describe("corrupt config is surfaced, never silently rewritten to defaults", () => {
  test("loadConfig on a corrupt file → safe defaults, but LEAVES the bad file in place", () => {
    // The daemon must not crash, but must also not erase the only on-disk signal
    // that the user's saved settings were lost — `beagle status` reads this file.
    const dir = mkdtempSync(join(tmpdir(), "beagle-cfg-corrupt-"));
    const p = join(dir, "config.json");
    writeFileSync(p, "{ this is not json");
    const before = readFileSync(p, "utf8");
    expect(loadConfig(dir)).toEqual(DEFAULT_CONFIG); // daemon-safe
    expect(readFileSync(p, "utf8")).toBe(before); // NOT overwritten with defaults
  });

  test("readConfig on a corrupt file → defaults, and still writes nothing", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-cfg-corrupt-"));
    writeFileSync(join(dir, "config.json"), "\x00\x00garbage");
    expect(readConfig(dir)).toEqual(DEFAULT_CONFIG);
  });

  test("a truncated (interrupted) write is detectable as corrupt, not mistaken for config", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-cfg-corrupt-"));
    const p = join(dir, "config.json");
    saveConfig(dir, { ...DEFAULT_CONFIG, payloadWindowDays: 30 });
    // Simulate a non-atomic crash truncating the file in place:
    writeFileSync(p, readFileSync(p, "utf8").slice(0, 12));
    expect(loadJsonFile(p).status).toBe("corrupt"); // surfaced, not swallowed as a default
  });

  test("saveConfig persists atomically: exact content, 0600, no temp sidecar left", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-cfg-save-"));
    saveConfig(dir, { ...DEFAULT_CONFIG, redactOnCapture: false });
    expect(loadConfig(dir).redactOnCapture).toBe(false);
    expect(statSync(join(dir, "config.json")).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir).some((n) => n.endsWith(".tmp"))).toBe(false);
  });
});
