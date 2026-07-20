import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { DEFAULT_CONFIG, loadConfig, readConfig, sanitizeConfig } from "../src/core/config/config";

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
});
