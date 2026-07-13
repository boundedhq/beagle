import { describe, expect, test } from "bun:test";
import { mkdtempSync, existsSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  deepSet,
  buildRedirectConfig,
  buildExtensionRedirect,
  writeRedirectConfig,
  writeRedirectExtension,
  readFirstConfig,
} from "../src/install/config-redirect";

function tmp() {
  return mkdtempSync(join(tmpdir(), "beagle-cfg-"));
}

describe("deepSet", () => {
  test("sets a nested path, creating intermediate objects", () => {
    const o: Record<string, unknown> = {};
    deepSet(o, ["provider", "openai", "options", "baseURL"], "http://x");
    expect(o).toEqual({ provider: { openai: { options: { baseURL: "http://x" } } } });
  });

  test("preserves sibling keys when overriding", () => {
    const o: Record<string, any> = { provider: { openai: { options: { apiKey: "k" }, models: ["gpt"] } }, theme: "dark" };
    deepSet(o, ["provider", "openai", "options", "baseURL"], "http://x");
    expect(o.provider.openai.options).toEqual({ apiKey: "k", baseURL: "http://x" });
    expect(o.provider.openai.models).toEqual(["gpt"]);
    expect(o.theme).toBe("dark");
  });
});

describe("buildRedirectConfig", () => {
  test("merges the user's real config and sets the proxy baseURL", () => {
    const user = { provider: { openai: { options: { apiKey: "sk-user" } } }, model: "gpt-5" };
    const merged = buildRedirectConfig(user, ["provider", "openai", "options", "baseURL"], "http://127.0.0.1:9/run/x");
    expect(merged).toEqual({
      provider: { openai: { options: { apiKey: "sk-user", baseURL: "http://127.0.0.1:9/run/x" } } },
      model: "gpt-5",
    });
    // does not mutate the input
    expect(user.provider.openai.options).not.toHaveProperty("baseURL");
  });

  test("works with no user config (null)", () => {
    const merged = buildRedirectConfig(null, ["provider", "openai", "options", "baseURL"], "http://x");
    expect(merged).toEqual({ provider: { openai: { options: { baseURL: "http://x" } } } });
  });
});

describe("readFirstConfig", () => {
  test("returns the first existing config, parsed", () => {
    const dir = tmp();
    const a = join(dir, "a.json");
    writeFileSync(a, JSON.stringify({ model: "x" }));
    expect(readFirstConfig([join(dir, "missing.json"), a])).toEqual({ model: "x" });
  });

  test("null when none exist", () => {
    expect(readFirstConfig([join(tmp(), "nope.json")])).toBeNull();
  });

  test("null on malformed config (never throws)", () => {
    const dir = tmp();
    const bad = join(dir, "bad.json");
    writeFileSync(bad, "{not json");
    expect(readFirstConfig([bad])).toBeNull();
  });
});

describe("writeRedirectConfig", () => {
  test("writes a Beagle-owned config (0600) and returns its path", () => {
    const dir = tmp();
    const path = writeRedirectConfig(dir, "opencode", { provider: { openai: {} } });
    expect(existsSync(path)).toBe(true);
    expect(path).toContain("opencode");
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ provider: { openai: {} } });
  });
});

describe("buildExtensionRedirect (pi: -e extension override)", () => {
  test("generates a default-export extension that re-points the provider", () => {
    const src = buildExtensionRedirect("openai", "http://127.0.0.1:9/run/abc");
    expect(src).toContain("export default function");
    expect(src).toContain('registerProvider("openai"');
    expect(src).toContain('"http://127.0.0.1:9/run/abc"');
  });

  test("has no imports — nothing for pi's loader to resolve", () => {
    // The file is injected into a foreign process; a bare `pi: any` signature
    // keeps it dependency-free so it can never fail to load on resolution.
    const src = buildExtensionRedirect("openai", "http://x");
    expect(src).not.toMatch(/^\s*import /m);
    expect(src).not.toContain("require(");
  });

  test("provider id and URL are JSON-escaped into the source", () => {
    const src = buildExtensionRedirect('we"ird', 'http://h/"q');
    expect(src).toContain(JSON.stringify('we"ird'));
    expect(src).toContain(JSON.stringify('http://h/"q'));
  });
});

describe("writeRedirectExtension", () => {
  test("writes a Beagle-owned .ts extension (0600) and returns its path", () => {
    const dir = tmp();
    const path = writeRedirectExtension(dir, "pi", "export default function (pi) {}");
    expect(existsSync(path)).toBe(true);
    expect(path).toContain("pi");
    expect(path.endsWith(".ts")).toBe(true);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(readFileSync(path, "utf8")).toContain("export default");
  });
});
