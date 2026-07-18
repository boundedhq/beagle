import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, existsSync, readFileSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
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
    expect(r.shellReloadHint).toBe(false); // already covered → no reload offer
    expect(existsSync(join(env.shimDir, "claude"))).toBe(true);
    const shim = readFileSync(join(env.shimDir, "claude"), "utf8");
    expect(shim).toContain("beagle");
    expect(shim).toContain('run "claude"');
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

  test("PATH-order non-coverage: with consent, the rc gets the guarded block and the manifest records it", () => {
    const env = makeEnv({ runType: () => "claude is /opt/homebrew/bin/claude" });
    const r = watchAgent("claude", env);
    expect(r.verdict?.covered).toBe(false);
    // consent (confirm → true) → the fix is APPLIED, not dictated
    const rcPath = join(env.home, ".zshrc");
    expect(r.message).toContain(`PATH updated in ${rcPath}`);
    // this fake env's runType never reflects the rc edit, so the re-probe still
    // reads not-covered → the honest "new login shells" wording, not "covered"
    expect(r.message).toContain("New login shells pick it up");
    // the CLI offers a refreshed shell for THIS terminal — signalled via the hint
    expect(r.shellReloadHint).toBe(true);
    const rc = readFileSync(rcPath, "utf8");
    expect(rc).toContain("# >>> beagle shims >>>");
    expect(rc).toContain(`export PATH="${env.shimDir}:$PATH"`);
    expect(rc).toContain("# <<< beagle shims <<<");
    const kinds = new ChangeManifest(env.stateDir).list().map((e) => e.kind).sort();
    expect(kinds).toEqual(["service", "shellrc", "shim"]);
  });

  test("PATH-order fix, re-probe now covered → the message EARNS its 'verified' claim", () => {
    // The realistic zsh case: the `-ic` probe can't see the shim until the rc
    // block is written, then it can. Key the fake probe on the rc file existing
    // — not-covered on the first (pre-install) call, covered on the re-probe.
    const env = makeEnv({});
    const rcPath = join(env.home, ".zshrc");
    env.runType = (agent) =>
      existsSync(rcPath) ? `${agent} is ${join(env.shimDir, agent)}` : `${agent} is /opt/homebrew/bin/${agent}`;
    const r = watchAgent("claude", env);
    expect(r.message).toContain("new terminals covered");
    expect(r.shellReloadHint).toBe(true);
  });

  test("the rc-fix prompt is a distinct 'Add it to <rc>?' question, not a repeat 'Proceed?'", () => {
    const prompts: (string | undefined)[] = [];
    const env = makeEnv({
      runType: () => "claude is /opt/homebrew/bin/claude",
      confirm: (_diff, prompt) => { prompts.push(prompt); return true; },
    });
    watchAgent("claude", env);
    // first confirm = the plan (default prompt); second = the rc edit (custom)
    expect(prompts[0]).toBeUndefined(); // uses the default "Proceed? [y/N]"
    expect(prompts[1]).toContain(`Add it to ${join(env.home, ".zshrc")}?`);
  });

  test("PATH-order non-coverage: declining the rc offer keeps the manual instructions", () => {
    let calls = 0;
    const env = makeEnv({
      runType: () => "claude is /opt/homebrew/bin/claude",
      confirm: () => ++calls === 1, // yes to the shim diff, no to the rc edit
    });
    const r = watchAgent("claude", env);
    expect(r.message).toContain(`export PATH="${env.shimDir}:$PATH"`);
    expect(r.shellReloadHint).toBe(false); // no rc change → nothing to reload
    expect(existsSync(join(env.home, ".zshrc"))).toBe(false);
    expect(new ChangeManifest(env.stateDir).list().some((e) => e.kind === "shellrc")).toBe(false);
  });

  test("an alias bypass never offers the rc edit (a PATH change can't fix it)", () => {
    const env = makeEnv({
      runType: () => "claude is aliased to `/Users/u/.claude/local/claude`",
    });
    watchAgent("claude", env);
    expect(existsSync(join(env.home, ".zshrc"))).toBe(false);
  });

  test("an unknown shell falls back to the manual instructions", () => {
    const env = makeEnv({
      shell: "/usr/bin/nushell",
      runType: () => "claude is /opt/homebrew/bin/claude",
    });
    const r = watchAgent("claude", env);
    expect(r.message).toContain(`export PATH="${env.shimDir}:$PATH"`);
    expect(existsSync(join(env.home, ".zshrc"))).toBe(false);
  });

  test("a malformed pre-existing beagle block is refused, never overwritten", () => {
    const env = makeEnv({ runType: () => "claude is /opt/homebrew/bin/claude" });
    const rcPath = join(env.home, ".zshrc");
    writeFileSync(rcPath, "# my stuff\n# >>> beagle shims >>>\nexport PATH=oops\n"); // no end marker
    const r = watchAgent("claude", env);
    expect(r.message).toContain("malformed");
    expect(r.shellReloadHint).toBe(false); // nothing changed → no reload offer
    expect(readFileSync(rcPath, "utf8")).toContain("export PATH=oops"); // untouched
  });

  test("unwatching the last agent removes the rc block along with the service", () => {
    const env = makeEnv({ runType: () => "claude is /opt/homebrew/bin/claude" });
    const rcPath = join(env.home, ".zshrc");
    writeFileSync(rcPath, "# mine before\n");
    watchAgent("claude", env);
    expect(readFileSync(rcPath, "utf8")).toContain("# >>> beagle shims >>>");
    const r = unwatchAgent("claude", env);
    expect(r.applied).toBe(true);
    expect(r.message).toContain(`PATH block removed from ${rcPath}`);
    // one action per line: unwatched / service removed / PATH block removed
    expect(r.message.split("\n")).toHaveLength(3);
    const after = readFileSync(rcPath, "utf8");
    expect(after).not.toContain("beagle shims");
    expect(after).toContain("# mine before"); // the user's content survives
    expect(new ChangeManifest(env.stateDir).list().length).toBe(0);
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
    expect(shim).toContain('run "opencode"');
  });

  test("pi is shimmable via its extension redirect (the shim just execs `beagle run pi`)", () => {
    const env = makeEnv({ resolveReal: () => "/opt/homebrew/bin/pi" });
    const r = watchAgent("pi", env);
    expect(r.applied).toBe(true);
    const shim = readFileSync(join(env.shimDir, "pi"), "utf8");
    expect(shim).toContain('run "pi"');
    expect(shim).not.toContain("--telemetry"); // pi has no telemetry mode
  });
});

describe("watchAgent — self-exec guard (fork-bomb prevention)", () => {
  test("refuses when the resolved 'real' binary IS the shim (shim dir on PATH + re-watch)", () => {
    const env = makeEnv();
    // Simulate the confirmed-live failure: the resolver found Beagle's own
    // shim because the shim dir sits at the front of the user's PATH.
    env.resolveReal = () => join(env.shimDir, "claude");
    const r = watchAgent("claude", env);
    expect(r.applied).toBe(false);
    expect(r.message).toContain("shim");
    expect(existsSync(join(env.shimDir, "claude"))).toBe(false); // nothing written
  });
});

describe("watchAgent — telemetry mode (subscription logins)", () => {
  test("--telemetry writes a shim that runs the agent in Mode B", () => {
    const env = makeEnv();
    const r = watchAgent("claude", env, "telemetry");
    expect(r.applied).toBe(true);
    expect(r.message).toContain("agent telemetry");
    const shim = readFileSync(join(env.shimDir, "claude"), "utf8");
    expect(shim).toContain('run "claude" --telemetry --real');
    expect(shim.endsWith('-- "$@"\n')).toBe(true); // user args still forwarded
    // manifest records the mode so status/unwatch stay honest
    const entry = new ChangeManifest(env.stateDir).list().find((e) => e.kind === "shim")!;
    expect(entry.mode).toBe("telemetry");
  });

  test("--telemetry is refused for agents without a telemetry mode", () => {
    for (const agent of ["opencode", "pi"]) {
      const env = makeEnv({ resolveReal: () => `/opt/homebrew/bin/${agent}` });
      const r = watchAgent(agent, env, "telemetry");
      expect(r.applied).toBe(false);
      expect(r.message).toContain("no telemetry");
      expect(existsSync(join(env.shimDir, agent))).toBe(false);
    }
  });

  test("auto mode picks telemetry when a subscription login is detected", () => {
    const env = makeEnv({
      resolveReal: () => "/opt/homebrew/bin/codex",
      detectSubscription: (agent) => agent === "codex",
    });
    const r = watchAgent("codex", env); // no explicit mode
    expect(r.applied).toBe(true);
    expect(readFileSync(join(env.shimDir, "codex"), "utf8")).toContain("--telemetry");
    expect(r.message).toContain("agent telemetry");
  });

  test("auto mode stays wire when no subscription is detected — with the subscription hint in the plan", () => {
    let plan = "";
    const env = makeEnv({
      resolveReal: () => "/opt/homebrew/bin/codex",
      detectSubscription: () => false,
      confirm: (diff) => ((plan = diff), true),
    });
    const r = watchAgent("codex", env);
    expect(r.applied).toBe(true);
    expect(readFileSync(join(env.shimDir, "codex"), "utf8")).not.toContain("--telemetry");
    expect(plan).toContain("--telemetry"); // the hint names the escape hatch
  });

  test("--wire overrides auto-detection AND pins wire in the shim", () => {
    const env = makeEnv({
      resolveReal: () => "/opt/homebrew/bin/codex",
      detectSubscription: () => true, // would auto-pick telemetry
    });
    const r = watchAgent("codex", env, "wire");
    expect(r.applied).toBe(true);
    const shim = readFileSync(join(env.shimDir, "codex"), "utf8");
    expect(shim).not.toContain("--telemetry");
    // the user's explicit choice must survive run-time login detection
    expect(shim).toContain('run "codex" --wire --real');
  });

  test("auto-resolved wire is NOT pinned — run-time detection can self-heal a login change", () => {
    const env = makeEnv({
      resolveReal: () => "/opt/homebrew/bin/codex",
      detectSubscription: () => false, // auto says wire today
    });
    watchAgent("codex", env); // auto mode
    const shim = readFileSync(join(env.shimDir, "codex"), "utf8");
    expect(shim).not.toContain("--wire");
    expect(shim).not.toContain("--telemetry");
  });

  test("re-watching to switch modes rewrites the shim and updates (not duplicates) the manifest", () => {
    const env = makeEnv();
    watchAgent("claude", env, "wire");
    watchAgent("claude", env, "telemetry");
    const shim = readFileSync(join(env.shimDir, "claude"), "utf8");
    expect(shim).toContain("--telemetry");
    const shims = new ChangeManifest(env.stateDir).list().filter((e) => e.kind === "shim");
    expect(shims.length).toBe(1); // replaced, not stacked
    expect(shims[0]!.mode).toBe("telemetry");
    // and unwatch still fully cleans up
    const u = unwatchAgent("claude", env);
    expect(u.applied).toBe(true);
    expect(existsSync(join(env.shimDir, "claude"))).toBe(false);
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

  test("last unwatch reports serviceRemoved so the CLI can stop the daemon too", () => {
    const env = makeEnv();
    watchAgent("claude", env);
    const r = unwatchAgent("claude", env);
    expect(r.applied).toBe(true);
    expect(r.serviceRemoved).toBe(true); // last agent → service torn down
    // and a non-last unwatch must NOT claim it
    const env2 = makeEnv();
    watchAgent("claude", env2);
    watchAgent("codex", { ...env2, resolveReal: () => "/opt/homebrew/bin/codex" });
    const r2 = unwatchAgent("claude", env2);
    expect(r2.serviceRemoved ?? false).toBe(false);
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

// The rc-block primitives themselves: idempotence, replacement, safe removal,
// per-shell targets.
import { installPathBlock, pathBlockMalformed, removePathBlock, rcTargetFor } from "../src/install/shellrc";

describe("shellrc PATH block", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "beagle-rc-")); });

  test("creates the rc file when missing", () => {
    const rc = join(dir, ".zshrc");
    const r = installPathBlock(rc, 'export PATH="/x/shims":$PATH');
    expect(r).toEqual({ ok: true, changed: true });
    expect(readFileSync(rc, "utf8")).toContain("beagle shims >>>");
  });

  test("re-install replaces the block in place — never duplicates", () => {
    const rc = join(dir, ".zshrc");
    writeFileSync(rc, "alias ll='ls -l'\n");
    installPathBlock(rc, 'export PATH="/old":$PATH');
    installPathBlock(rc, 'export PATH="/new":$PATH');
    const s = readFileSync(rc, "utf8");
    expect(s.match(/>>> beagle shims >>>/g)?.length).toBe(1);
    expect(s).toContain("/new");
    expect(s).not.toContain("/old");
    expect(s).toContain("alias ll"); // user content intact
  });

  test("identical re-install reports changed: false", () => {
    const rc = join(dir, ".zshrc");
    installPathBlock(rc, 'export PATH="/x":$PATH');
    expect(installPathBlock(rc, 'export PATH="/x":$PATH')).toEqual({ ok: true, changed: false });
  });

  test("removal strips exactly the block and its separator", () => {
    const rc = join(dir, ".zshrc");
    writeFileSync(rc, "# before\n");
    installPathBlock(rc, 'export PATH="/x":$PATH');
    expect(removePathBlock(rc)).toBe(true);
    expect(readFileSync(rc, "utf8")).toBe("# before\n");
  });

  test("removal is a safe no-op on a missing file or absent markers", () => {
    expect(removePathBlock(join(dir, "nope"))).toBe(false);
    const rc = join(dir, ".zshrc");
    writeFileSync(rc, "just mine\n");
    expect(removePathBlock(rc)).toBe(false);
    expect(readFileSync(rc, "utf8")).toBe("just mine\n");
  });

  test("per-shell targets: zsh honors ZDOTDIR, darwin bash uses .bash_profile, fish gets fish syntax", () => {
    expect(rcTargetFor("/bin/zsh", "/h", "linux", "/s")).toEqual({
      path: "/h/.zshrc", line: 'export PATH="/s:$PATH"',
    });
    expect(rcTargetFor("/bin/zsh", "/h", "linux", "/s", "/zdot")?.path).toBe("/zdot/.zshrc");
    // ZDOTDIR set-but-empty means unset — an empty string must never produce
    // a CWD-relative "./.zshrc" (found live: block written into the repo root)
    expect(rcTargetFor("/bin/zsh", "/h", "linux", "/s", "")?.path).toBe("/h/.zshrc");
    expect(rcTargetFor("/bin/bash", "/h", "darwin", "/s")?.path).toBe("/h/.bash_profile");
    expect(rcTargetFor("/bin/bash", "/h", "linux", "/s")?.path).toBe("/h/.bashrc");
    const fish = rcTargetFor("/usr/bin/fish", "/h", "linux", "/s");
    expect(fish?.path).toBe("/h/.config/fish/config.fish");
    expect(fish?.line).toBe('set -gx PATH "/s" $PATH');
    expect(rcTargetFor("/usr/bin/nushell", "/h", "linux", "/s")).toBeNull();
  });

  test("a `$(…)` in the shim path is escaped — no command substitution on shell start", () => {
    // A dir literally named with a command substitution must be inert in the
    // rc line, not executed on every login (the reported injection).
    const evil = rcTargetFor("/bin/zsh", "/h", "linux", "/tmp/x$(touch /tmp/pwned)");
    expect(evil?.line).toBe('export PATH="/tmp/x\\$(touch /tmp/pwned):$PATH"');
    // and the value is written escaped, so `$(` never reaches the shell live
    const rc = join(dir, ".zshrc");
    installPathBlock(rc, evil!.line);
    expect(readFileSync(rc, "utf8")).toContain('\\$(touch /tmp/pwned)');
    // fish gets the same treatment
    const evilFish = rcTargetFor("/usr/bin/fish", "/h", "linux", "/tmp/x$(evil)");
    expect(evilFish?.line).toBe('set -gx PATH "/tmp/x\\$(evil)" $PATH');
  });

  test("markers are line-anchored: a commented-out block is NOT a false boundary", () => {
    const rc = join(dir, ".zshrc");
    // user disabled Beagle's block by commenting every line
    writeFileSync(rc, "## >>> beagle shims >>> managed by beagle\n## export PATH=x\n## <<< beagle shims <<<\nmine\n");
    // install must treat this as "no block present" → append a fresh one, not
    // splice mid-line into the commented text
    const r = installPathBlock(rc, 'export PATH="/s":$PATH');
    expect(r.ok).toBe(true);
    const s = readFileSync(rc, "utf8");
    expect(s).toContain("## >>> beagle shims >>> managed by beagle"); // commented line untouched
    expect(s.match(/^# >>> beagle shims >>>/gm)?.length).toBe(1); // exactly one real block
    // removal likewise ignores the commented markers and strips only the real block
    expect(removePathBlock(rc)).toBe(true);
    expect(readFileSync(rc, "utf8")).toContain("## >>> beagle shims >>>");
  });

  test("pathBlockMalformed detects a begin marker with no end", () => {
    const rc = join(dir, ".zshrc");
    expect(pathBlockMalformed(rc)).toBe(false); // missing file
    writeFileSync(rc, "# >>> beagle shims >>>\nexport PATH=oops\n");
    expect(pathBlockMalformed(rc)).toBe(true);
    writeFileSync(rc, "# >>> beagle shims >>>\nx\n# <<< beagle shims <<<\n");
    expect(pathBlockMalformed(rc)).toBe(false);
  });

  test("scoped removal leaves another install's block alone", () => {
    const rc = join(dir, ".zshrc");
    installPathBlock(rc, 'export PATH="/other/shims:$PATH"'); // written by state dir B
    // state dir A tries to remove, scoped to ITS shim dir — must not touch B's
    expect(removePathBlock(rc, "/mine/shims")).toBe(false);
    expect(readFileSync(rc, "utf8")).toContain("/other/shims");
    // scoped to the block's OWN dir → removes
    expect(removePathBlock(rc, "/other/shims")).toBe(true);
    expect(readFileSync(rc, "utf8")).not.toContain("beagle shims");
  });
});

// Service verify/repair: an installed unit pointing at the wrong state dir is
// the "always-on daemon for the wrong store" failure — caught live when a
// stale test unit pinned the real launchd agent to /tmp/beagle-lease.*.
import { launchdPlist, servicePlan, serviceStateDir, systemdUnit } from "../src/install/service";

describe("watchAgent — service verify/repair", () => {
  test("a unit baked with a different state dir is repaired (rewritten + reactivated)", () => {
    const env = makeEnv();
    const plan = servicePlan(env.platform, env.home, env.beagleBinary, env.stateDir)!;
    mkdirSync(join(env.home, ".config", "systemd", "user"), { recursive: true });
    writeFileSync(plan.path, systemdUnit({ beagleBinary: env.beagleBinary, stateDir: "/tmp/beagle-lease.STALE" }));
    const before = deactivations.length;
    const r = watchAgent("claude", env);
    expect(r.applied).toBe(true);
    const after = readFileSync(plan.path, "utf8");
    expect(after).toContain(env.stateDir);
    expect(after).not.toContain("beagle-lease.STALE");
    expect(deactivations.length).toBe(before + 1); // deactivate → rewrite → activate
    // the shared entry exists exactly once
    const svcEntries = new ChangeManifest(env.stateDir).list().filter((e) => e.kind === "service");
    expect(svcEntries.length).toBe(1);
  });

  test("a hand-edited unit Beagle can't parse is left alone", () => {
    const env = makeEnv();
    const plan = servicePlan(env.platform, env.home, env.beagleBinary, env.stateDir)!;
    mkdirSync(join(env.home, ".config", "systemd", "user"), { recursive: true });
    writeFileSync(plan.path, "# my custom unit\n[Service]\nExecStart=/somewhere/else\n");
    watchAgent("claude", env);
    expect(readFileSync(plan.path, "utf8")).toContain("my custom unit"); // untouched
  });

  test("poison combo: tmp state dir + REAL home skips the service entirely", () => {
    const env = makeEnv({ home: "/Users/nonexistent-real-home" }); // never written to
    const r = watchAgent("claude", env);
    expect(r.applied).toBe(true);
    expect(r.message).toContain("background service NOT installed");
    const kinds = new ChangeManifest(env.stateDir).list().map((e) => e.kind);
    expect(kinds).not.toContain("service");
  });

  test("poison combo ALSO skips the shell-rc edit — no /tmp path in a real rc", () => {
    const env = makeEnv({
      home: "/Users/nonexistent-real-home",
      runType: () => "claude is /opt/homebrew/bin/claude", // not covered
    });
    const r = watchAgent("claude", env);
    expect(r.verdict?.covered).toBe(false);
    // no rc mutation — falls back to the printed manual instructions
    expect(new ChangeManifest(env.stateDir).list().some((e) => e.kind === "shellrc")).toBe(false);
    expect(r.message).toContain('export PATH="');
    expect(existsSync(join("/Users/nonexistent-real-home", ".zshrc"))).toBe(false);
  });

  test("a hand-edited unit is never adopted, so unwatch-of-last-agent never deletes it", () => {
    const env = makeEnv();
    const plan = servicePlan(env.platform, env.home, env.beagleBinary, env.stateDir)!;
    mkdirSync(join(env.home, ".config", "systemd", "user"), { recursive: true });
    writeFileSync(plan.path, "# my custom unit\n[Service]\nExecStart=/somewhere/else\n");
    watchAgent("claude", env);
    // not adopted — an unparseable unit is the user's
    expect(new ChangeManifest(env.stateDir).list().some((e) => e.kind === "service")).toBe(false);
    unwatchAgent("claude", env); // last agent gone
    expect(existsSync(plan.path)).toBe(true); // the hand-edited unit survives
    expect(readFileSync(plan.path, "utf8")).toContain("my custom unit");
  });

  test("re-watch after the unit file was deleted doesn't duplicate the manifest entry", () => {
    const env = makeEnv();
    const plan = servicePlan(env.platform, env.home, env.beagleBinary, env.stateDir)!;
    watchAgent("claude", env); // installs + records the service
    rmSync(plan.path, { force: true }); // file deleted out from under the manifest
    watchAgent("claude", env); // svcInstall path again — must recordReplacing, not stack
    const svcEntries = new ChangeManifest(env.stateDir).list().filter((e) => e.kind === "service");
    expect(svcEntries.length).toBe(1);
  });
});

describe("serviceStateDir", () => {
  test("reads back both unit formats, including escaped characters", () => {
    const odd = '/tmp/we"ird &dir';
    expect(serviceStateDir(launchdPlist({ beagleBinary: "/b", stateDir: odd }))).toBe(odd);
    expect(serviceStateDir(systemdUnit({ beagleBinary: "/b", stateDir: odd }))).toBe(odd);
  });
  test("hand-edited/unknown content → null", () => {
    expect(serviceStateDir("[Service]\nExecStart=/x daemon\n")).toBeNull();
    expect(serviceStateDir("")).toBeNull();
  });
});

describe("watchAgent — re-enable a paused service", () => {
  test("watch re-activates an installed, healthy, but inactive service", () => {
    const env = makeEnv();
    watchAgent("claude", env); // installs + activates
    const before = activations.length;
    // Same install, now reported inactive (e.g. after `beagle stop`).
    const env2 = { ...env, serviceRunner: {
      activate: (p: { path: string }) => activations.push(p.path),
      deactivate: () => {},
      isActive: () => false,
    } };
    const r = watchAgent("claude", env2);
    expect(r.applied).toBe(true);
    expect(activations.length).toBe(before + 1); // re-activated
  });

  test("an active service is left alone (no spurious re-activation)", () => {
    const env = makeEnv();
    watchAgent("claude", env);
    const before = activations.length;
    const env2 = { ...env, serviceRunner: {
      activate: (p: { path: string }) => activations.push(p.path),
      deactivate: () => {},
      isActive: () => true,
    } };
    watchAgent("claude", env2);
    expect(activations.length).toBe(before); // untouched
  });
});

describe("watchAgent — orphaned service adoption", () => {
  test("a healthy on-disk unit missing from the manifest is adopted (bookkeeping only)", () => {
    const env = makeEnv();
    const plan = servicePlan(env.platform, env.home, env.beagleBinary, env.stateDir)!;
    mkdirSync(join(env.home, ".config", "systemd", "user"), { recursive: true });
    writeFileSync(plan.path, systemdUnit({ beagleBinary: env.beagleBinary, stateDir: env.stateDir }));
    const before = activations.length;
    watchAgent("claude", env); // manifest had no service entry
    const svcEntries = new ChangeManifest(env.stateDir).list().filter((e) => e.kind === "service");
    expect(svcEntries.length).toBe(1); // adopted
    expect(activations.length).toBe(before); // no OS action — it was healthy
  });
});
