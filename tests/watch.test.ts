import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, existsSync, readFileSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { watchAgent, unwatchAgent, type WatchEnv } from "../src/install/watch";
import { ChangeManifest } from "../src/install/manifest";

const activations: string[] = [];
const deactivations: string[] = [];

function makeEnv(overrides: Partial<WatchEnv> = {}): WatchEnv {
  const stateDir = mkdtempSync(join(tmpdir(), "beagle-watch-"));
  const shimDir = join(stateDir, "shims");
  return {
    stateDir,
    shimDir,
    beagleBinary: "/usr/local/bin/beagle",
    shell: "/bin/zsh",
    platform: "linux",
    home: stateDir, // keep the service file inside the temp dir
    resolveReal: () => "/opt/homebrew/bin/claude",
    runType: (agent) => `${agent} is ${join(shimDir, agent)}`, // resolves to shim → covered
    confirm: () => true,
    serviceRunner: {
      activate: (p) => activations.push(p.path),
      deactivate: (p) => deactivations.push(p.path),
    },
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
    // shim + the always-on service (first graduation)
    expect(entries.map((e) => e.kind).sort()).toEqual(["service", "shim"]);
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

  test("config-driven agent (opencode) is refused rather than getting a broken shim", () => {
    const env = makeEnv({ resolveReal: () => "/opt/homebrew/bin/opencode" });
    const r = watchAgent("opencode", env);
    expect(r.applied).toBe(false);
    expect(r.message.toLowerCase()).toContain("config-driven");
    expect(existsSync(join(env.shimDir, "opencode"))).toBe(false);
  });
});

describe("service unit at graduation", () => {
  beforeEach(() => {
    activations.length = 0;
    deactivations.length = 0;
  });

  test("first watch installs + activates the service; second watch does not reinstall", () => {
    const diffs: string[] = [];
    const env = makeEnv({ confirm: (d) => { diffs.push(d); return true; } });
    watchAgent("claude", env);
    expect(diffs[0]).toContain("background service"); // disclosed in the diff
    const svcPath = join(env.stateDir, ".config/systemd/user/beagle.service");
    expect(existsSync(svcPath)).toBe(true);
    expect(activations).toEqual([svcPath]);

    watchAgent("codex", env);
    expect(diffs[1]).not.toContain("background service"); // already installed
    expect(activations.length).toBe(1); // not reinstalled
    const services = new ChangeManifest(env.stateDir).list().filter((e) => e.kind === "service");
    expect(services.length).toBe(1);
  });
});

describe("unwatchAgent", () => {
  beforeEach(() => {
    activations.length = 0;
    deactivations.length = 0;
  });

  test("removes the shim and clears the manifest; last agent also removes the service", () => {
    const env = makeEnv();
    watchAgent("claude", env);
    const svcPath = join(env.stateDir, ".config/systemd/user/beagle.service");
    expect(existsSync(svcPath)).toBe(true);
    const r = unwatchAgent("claude", env);
    expect(r.applied).toBe(true);
    expect(r.message).toContain("Background service removed");
    expect(existsSync(join(env.shimDir, "claude"))).toBe(false);
    expect(existsSync(svcPath)).toBe(false);
    expect(deactivations).toEqual([svcPath]);
    expect(new ChangeManifest(env.stateDir).list().length).toBe(0);
  });

  test("unwatching an unwatched agent is a clean no-op", () => {
    const env = makeEnv();
    const r = unwatchAgent("codex", env);
    expect(r.applied).toBe(false);
  });

  test("service survives until the LAST watched agent is unwatched", () => {
    const env = makeEnv();
    watchAgent("claude", env);
    watchAgent("codex", env);
    const svcPath = join(env.stateDir, ".config/systemd/user/beagle.service");

    unwatchAgent("claude", env);
    expect(existsSync(join(env.shimDir, "codex"))).toBe(true);
    expect(existsSync(svcPath)).toBe(true); // codex still watched
    // manifest: shim:codex + service
    expect(new ChangeManifest(env.stateDir).list().length).toBe(2);

    unwatchAgent("codex", env);
    expect(existsSync(svcPath)).toBe(false); // last agent gone → service removed
    expect(new ChangeManifest(env.stateDir).list().length).toBe(0);
  });
});
