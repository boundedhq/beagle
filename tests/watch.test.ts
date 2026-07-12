import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, existsSync, readFileSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { watchAgent, unwatchAgent, type WatchEnv } from "../src/install/watch";
import { ChangeManifest } from "../src/install/manifest";

function makeEnv(overrides: Partial<WatchEnv> = {}): WatchEnv {
  const stateDir = mkdtempSync(join(tmpdir(), "beagle-watch-"));
  const shimDir = join(stateDir, "shims");
  return {
    stateDir,
    shimDir,
    beagleBinary: "/usr/local/bin/beagle",
    shell: "/bin/zsh",
    resolveReal: () => "/opt/homebrew/bin/claude",
    runType: (agent) => `${agent} is ${join(shimDir, agent)}`, // resolves to shim → covered
    confirm: () => true,
    ...overrides,
  };
}

describe("watchAgent", () => {
  test("places the shim, records the manifest, and verifies coverage", () => {
    const env = makeEnv();
    const r = watchAgent("claude", env);
    expect(r.applied).toBe(true);
    expect(r.verdict?.covered).toBe(true);
    expect(existsSync(join(env.shimDir, "claude"))).toBe(true);
    const shim = readFileSync(join(env.shimDir, "claude"), "utf8");
    expect(shim).toContain("beagle");
    expect(shim).toContain("run claude");
    const entries = new ChangeManifest(env.stateDir).list();
    expect(entries.length).toBe(1);
    expect(entries[0]?.kind).toBe("shim");
  });

  test("declining the diff changes nothing", () => {
    const env = makeEnv({ confirm: () => false });
    const r = watchAgent("claude", env);
    expect(r.applied).toBe(false);
    expect(existsSync(join(env.shimDir, "claude"))).toBe(false);
    expect(new ChangeManifest(env.stateDir).list().length).toBe(0);
  });

  test("reports non-coverage when an alias bypasses the shim", () => {
    const env = makeEnv({
      runType: () => "claude is aliased to `/Users/u/.claude/local/claude`",
    });
    const r = watchAgent("claude", env);
    expect(r.applied).toBe(true); // shim placed
    expect(r.verdict?.covered).toBe(false);
    expect(r.message.toLowerCase()).toContain("alias");
  });

  test("non-coverage message includes the exact PATH fix", () => {
    const env = makeEnv({ runType: () => "claude is /opt/homebrew/bin/claude" });
    const r = watchAgent("claude", env);
    expect(r.verdict?.covered).toBe(false);
    expect(r.message).toContain(`export PATH="${env.shimDir}:$PATH"`);
    expect(r.message).toContain("beagle status");
  });

  test("unsupported or missing agent is refused", () => {
    expect(watchAgent("nonesuch", makeEnv()).applied).toBe(false);
    expect(watchAgent("claude", makeEnv({ resolveReal: () => null })).applied).toBe(false);
  });

  test("config-driven opencode is now shimmable (shim execs `beagle run opencode`)", () => {
    const env = makeEnv({ resolveReal: () => "/opt/homebrew/bin/opencode" });
    const r = watchAgent("opencode", env);
    expect(r.applied).toBe(true);
    const shim = readFileSync(join(env.shimDir, "opencode"), "utf8");
    expect(shim).toContain("run opencode");
  });

  test("pi (no confirmed config knob) is still refused", () => {
    const env = makeEnv({ resolveReal: () => "/opt/homebrew/bin/pi" });
    const r = watchAgent("pi", env);
    expect(r.applied).toBe(false);
    expect(existsSync(join(env.shimDir, "pi"))).toBe(false);
  });
});

describe("unwatchAgent", () => {
  test("removes the shim and clears the manifest entry", () => {
    const env = makeEnv();
    watchAgent("claude", env);
    expect(existsSync(join(env.shimDir, "claude"))).toBe(true);
    const r = unwatchAgent("claude", env);
    expect(r.applied).toBe(true);
    expect(existsSync(join(env.shimDir, "claude"))).toBe(false);
    expect(new ChangeManifest(env.stateDir).list().length).toBe(0);
  });

  test("unwatching an unwatched agent is a clean no-op", () => {
    const env = makeEnv();
    const r = unwatchAgent("codex", env);
    expect(r.applied).toBe(false);
  });

  test("only the named agent is unwatched", () => {
    const env = makeEnv();
    watchAgent("claude", env);
    watchAgent("codex", env);
    unwatchAgent("claude", env);
    expect(existsSync(join(env.shimDir, "claude"))).toBe(false);
    expect(existsSync(join(env.shimDir, "codex"))).toBe(true);
    expect(new ChangeManifest(env.stateDir).list().length).toBe(1);
  });
});
