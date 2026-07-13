import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, chmodSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChangeManifest } from "../src/install/manifest";
import { isBeagleShim, shimScript, parseCoverageVerdict } from "../src/install/shim";
import { codexAuthMode, detectAgents } from "../src/install/detect";
import { GraduationTracker } from "../src/install/graduation";
import { detectSubscriptionFor, graduationNudge, parseWatchArgs } from "../src/cli/commands";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "beagle-install-"));
}

describe("ChangeManifest", () => {
  let dir: string;
  beforeEach(() => (dir = tmp()));

  test("records mutations before applying and reverts in reverse order", () => {
    const m = new ChangeManifest(dir);
    m.record({ kind: "shim", agent: "claude", path: "/usr/local/bin/claude", backup: null });
    m.record({ kind: "config-backup", agent: "opencode", path: "/home/u/.config/opencode/config.json", backup: join(dir, "bak-1") });
    const entries = m.list();
    expect(entries.length).toBe(2);
    expect(entries[0]?.kind).toBe("shim");
    // persisted 0600
    expect(existsSync(join(dir, "changes.json"))).toBe(true);
    expect(statSync(join(dir, "changes.json")).mode & 0o777).toBe(0o600);

    const reverts: string[] = [];
    m.revert((e) => reverts.push(`${e.kind}:${e.agent}`));
    expect(reverts).toEqual(["config-backup:opencode", "shim:claude"]); // reverse
    expect(m.list().length).toBe(0);
  });

  test("survives reload from disk", () => {
    const m = new ChangeManifest(dir);
    m.record({ kind: "service", agent: null, path: "/x/beagle.plist", backup: null });
    const m2 = new ChangeManifest(dir);
    expect(m2.list().length).toBe(1);
    expect(m2.list()[0]?.kind).toBe("service");
  });

  test("summary text lists what changed for the trust strip", () => {
    const m = new ChangeManifest(dir);
    m.record({ kind: "shim", agent: "claude", path: "/usr/local/bin/claude", backup: null });
    expect(m.summary()).toContain("claude");
    expect(m.summary()).toContain("1");
  });

  test("summary labels telemetry shims so the trust strip shows the capture mode", () => {
    const m = new ChangeManifest(dir);
    m.record({ kind: "shim", agent: "codex", path: "/s/codex", backup: null, mode: "telemetry" });
    m.record({ kind: "shim", agent: "claude", path: "/s/claude", backup: null, mode: "wire" });
    expect(m.summary()).toContain("codex (telemetry)");
    expect(m.summary()).toContain("claude");
    expect(m.summary()).not.toContain("claude (telemetry)");
  });

  test("recordReplacing updates a re-watched agent's entry instead of stacking duplicates", () => {
    const m = new ChangeManifest(dir);
    m.recordReplacing({ kind: "shim", agent: "codex", path: "/s/codex", backup: null, mode: "wire" });
    m.recordReplacing({ kind: "shim", agent: "codex", path: "/s/codex", backup: null, mode: "telemetry" });
    const shims = m.list().filter((e) => e.kind === "shim");
    expect(shims.length).toBe(1);
    expect(shims[0]!.mode).toBe("telemetry");
    // different path or agent is NOT replaced
    m.recordReplacing({ kind: "shim", agent: "claude", path: "/s/claude", backup: null, mode: "wire" });
    expect(m.list().length).toBe(2);
  });
});

describe("shim script", () => {
  test("generated shim redirects then execs the real binary", () => {
    const s = shimScript({
      agent: "claude",
      realBinary: "/opt/homebrew/bin/claude",
      beagleBinary: "/usr/local/bin/beagle",
    });
    expect(s.startsWith("#!/bin/sh")).toBe(true);
    expect(s).toContain("/usr/local/bin/beagle");
    expect(s).toContain("exec");
    expect(s).toContain("/opt/homebrew/bin/claude");
    // must pass through args
    expect(s).toContain('"$@"');
  });

  test("shim quotes paths with spaces safely", () => {
    const s = shimScript({
      agent: "claude",
      realBinary: "/Applications/My Tools/claude",
      beagleBinary: "/usr/local/bin/beagle",
    });
    expect(s).toContain('"/Applications/My Tools/claude"');
  });

  test("telemetry shim runs the agent in Mode B, keeping --real and arg passthrough", () => {
    const s = shimScript({
      agent: "codex",
      realBinary: "/opt/homebrew/bin/codex",
      beagleBinary: "/usr/local/bin/beagle",
      telemetry: true,
    });
    expect(s).toContain('run codex --telemetry --real "/opt/homebrew/bin/codex" -- "$@"');
    // and the default stays wire
    const wire = shimScript({ agent: "codex", realBinary: "/o/codex", beagleBinary: "/b" });
    expect(wire).not.toContain("--telemetry");
  });
});

describe("isBeagleShim + shim-aware detection (fork-bomb & double-wrap defense)", () => {
  test("recognizes a generated shim by content; never misclassifies other files", () => {
    const dir = mkdtempSync(join(tmpdir(), "beagle-shimid-"));
    const shimPath = join(dir, "codex");
    writeFileSync(shimPath, shimScript({ agent: "codex", realBinary: "/r/codex", beagleBinary: "/b" }), { mode: 0o755 });
    expect(isBeagleShim(shimPath)).toBe(true);
    const real = join(dir, "real-binary");
    writeFileSync(real, "#!/bin/sh\necho hi\n", { mode: 0o755 });
    expect(isBeagleShim(real)).toBe(false);
    expect(isBeagleShim(join(dir, "missing"))).toBe(false); // error → false, never blocks
  });

  test("detectAgents skips Beagle shims even when the shim dir is first on PATH", () => {
    // Content-based: catches shims from a symlinked dir or an OLD state dir,
    // where a path comparison can't. Mistaking a shim for the agent is how
    // the self-exec fork bomb happened.
    const shimDir = mkdtempSync(join(tmpdir(), "beagle-shimdir-"));
    const realDir = mkdtempSync(join(tmpdir(), "beagle-realdir-"));
    writeFileSync(join(shimDir, "codex"), shimScript({ agent: "codex", realBinary: join(realDir, "codex"), beagleBinary: "/b" }), { mode: 0o755 });
    writeFileSync(join(realDir, "codex"), "#!/bin/sh\necho codex\n", { mode: 0o755 });
    const found = detectAgents({ pathDirs: [shimDir, realDir], extraLocations: [] });
    expect(found.find((f) => f.agent === "codex")?.path).toBe(join(realDir, "codex"));
  });

  test("dev-mode shim carries the runtime AND the entry script", () => {
    const s = shimScript({
      agent: "claude",
      realBinary: "/opt/homebrew/bin/claude",
      beagleBinary: "/usr/local/bin/bun",
      beagleScript: "/repo/src/cli/main.ts",
      telemetry: true,
    });
    expect(s).toContain('"/usr/local/bin/bun" "/repo/src/cli/main.ts" run claude --telemetry');
  });
});

describe("codexAuthMode (subscription detection for watch auto-mode)", () => {
  const authHome = (content: string | null) => {
    const home = mkdtempSync(join(tmpdir(), "beagle-auth-"));
    if (content !== null) {
      mkdirSync(join(home, ".codex"), { recursive: true });
      writeFileSync(join(home, ".codex", "auth.json"), content);
    }
    return home;
  };

  test("explicit auth_mode label wins even over contradicting credential presence", () => {
    // Label says chatgpt while an API key sits in the file — the label rules.
    expect(codexAuthMode(authHome('{"auth_mode":"chatgpt","OPENAI_API_KEY":"sk-x","tokens":null}'))).toBe("chatgpt");
    // Label says apikey while ChatGPT tokens sit in the file — the label rules.
    expect(codexAuthMode(authHome('{"auth_mode":"apikey","OPENAI_API_KEY":null,"tokens":{"access_token":"t"}}'))).toBe("api-key");
    // The real live shape (codex 0.144.x).
    expect(codexAuthMode(authHome('{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"id_token":"a","access_token":"b","refresh_token":"c","account_id":"d"},"last_refresh":"2026-07-13"}'))).toBe("chatgpt");
  });

  test("older files fall back to credential presence — tokens win when both exist", () => {
    expect(codexAuthMode(authHome('{"OPENAI_API_KEY":"sk-x"}'))).toBe("api-key");
    expect(codexAuthMode(authHome('{"OPENAI_API_KEY":null,"tokens":{"access_token":"t"}}'))).toBe("chatgpt");
    // Both present, no label: codex's own default prefers the ChatGPT login,
    // and telemetry is the safe direction either way.
    expect(codexAuthMode(authHome('{"OPENAI_API_KEY":"sk-x","tokens":{"access_token":"t"}}'))).toBe("chatgpt");
  });

  test("honors a CODEX_HOME-style override dir", () => {
    const home = mkdtempSync(join(tmpdir(), "beagle-auth-"));
    const codexHome = join(home, "relocated-codex");
    mkdirSync(codexHome, { recursive: true });
    writeFileSync(join(codexHome, "auth.json"), '{"auth_mode":"chatgpt"}');
    expect(codexAuthMode(home, codexHome)).toBe("chatgpt"); // reads the override
    expect(codexAuthMode(home)).toBe("unknown"); // default location is empty
  });

  test("missing or malformed auth.json is unknown — never blocks, never auto-picks", () => {
    expect(codexAuthMode(authHome(null))).toBe("unknown");
    expect(codexAuthMode(authHome("not json"))).toBe("unknown");
    expect(codexAuthMode(authHome("{}"))).toBe("unknown");
  });
});

describe("parseWatchArgs (strict watch flag parsing)", () => {
  test("modes parse and default to auto", () => {
    expect(parseWatchArgs(["codex"])).toEqual({ agent: "codex", yes: false, mode: "auto" });
    expect(parseWatchArgs(["codex", "--telemetry", "--yes"])).toEqual({ agent: "codex", yes: true, mode: "telemetry" });
    expect(parseWatchArgs(["--wire", "codex"])).toEqual({ agent: "codex", yes: false, mode: "wire" });
  });

  test("--telemetry and --wire together are rejected", () => {
    const r = parseWatchArgs(["codex", "--telemetry", "--wire"]);
    expect("error" in r && r.error).toContain("mutually exclusive");
  });

  test("an unknown flag is an error, never a silent fallback to auto", () => {
    // A typo'd --telemetry silently degrading to auto could install a WIRE
    // shim for a subscription user — the exact failure this feature removes.
    const r = parseWatchArgs(["codex", "--telemetr"]);
    expect("error" in r && r.error).toContain("--telemetr");
    expect("error" in parseWatchArgs([])).toBe(true); // missing agent
  });
});

describe("detectSubscriptionFor (the real auto-mode wiring)", () => {
  test("codex with a ChatGPT auth.json is a subscription; claude never auto-detects", () => {
    const home = mkdtempSync(join(tmpdir(), "beagle-sub-"));
    mkdirSync(join(home, ".codex"), { recursive: true });
    writeFileSync(join(home, ".codex", "auth.json"), '{"auth_mode":"chatgpt"}');
    expect(detectSubscriptionFor("codex", home)).toBe(true);
    expect(detectSubscriptionFor("claude", home)).toBe(false); // not statically detectable
    writeFileSync(join(home, ".codex", "auth.json"), '{"auth_mode":"apikey","OPENAI_API_KEY":"sk-x"}');
    expect(detectSubscriptionFor("codex", home)).toBe(false);
  });
});

describe("graduationNudge (mode-aware watch suggestion)", () => {
  test("wire runs point at plain watch; telemetry runs carry --telemetry", () => {
    expect(graduationNudge("codex", false)).toContain("beagle watch codex\n");
    expect(graduationNudge("codex", true)).toContain("beagle watch codex --telemetry");
    // a telemetry user must never be pointed at a wire-only watch command
    expect(graduationNudge("claude", true)).not.toContain("watch claude\n");
  });
});

describe("coverage verdict (the shim honesty clause, R2)", () => {
  test("resolution landing on the shim is covered", () => {
    const v = parseCoverageVerdict("claude", "/usr/local/bin/claude", "/usr/local/bin/claude is /usr/local/bin/claude");
    expect(v.covered).toBe(true);
  });

  test("an alias bypassing the shim is reported with the cause", () => {
    const v = parseCoverageVerdict("claude", "/usr/local/bin/claude", "claude is aliased to `/Users/u/.claude/local/claude`");
    expect(v.covered).toBe(false);
    expect(v.reason.toLowerCase()).toContain("alias");
  });

  test("zsh 'is an alias for' phrasing is detected too", () => {
    const v = parseCoverageVerdict("claude", "/usr/local/bin/claude", "claude is an alias for /Users/u/.claude/local/claude");
    expect(v.covered).toBe(false);
    expect(v.reason.toLowerCase()).toContain("alias");
  });

  test("a shim path that merely contains 'alias' is not a false alias hit", () => {
    const shim = "/Users/alias/bin/claude";
    const v = parseCoverageVerdict("claude", shim, `claude is ${shim}`);
    expect(v.covered).toBe(true);
  });

  test("resolution to a different absolute path is a bypass", () => {
    const v = parseCoverageVerdict("claude", "/usr/local/bin/claude", "claude is /Users/u/.claude/local/claude");
    expect(v.covered).toBe(false);
    expect(v.reason.toLowerCase()).toContain("bypass");
  });
});

describe("agent detection", () => {
  test("finds agents on a simulated PATH and reports the run command", () => {
    const dir = tmp();
    const bin = join(dir, "bin");
    mkdirSync(bin, { recursive: true });
    for (const name of ["claude", "codex"]) {
      const p = join(bin, name);
      writeFileSync(p, "#!/bin/sh\n");
      chmodSync(p, 0o755);
    }
    const found = detectAgents({ pathDirs: [bin], extraLocations: [] });
    expect(found.map((f) => f.agent).sort()).toEqual(["claude", "codex"]);
    expect(found.find((f) => f.agent === "claude")?.runCommand).toBe("beagle run claude");
  });

  test("finds Claude Code's known install location outside PATH", () => {
    const dir = tmp();
    const local = join(dir, ".claude", "local");
    mkdirSync(local, { recursive: true });
    const p = join(local, "claude");
    writeFileSync(p, "#!/bin/sh\n");
    chmodSync(p, 0o755);
    const found = detectAgents({ pathDirs: [], extraLocations: [{ agent: "claude", path: p }] });
    expect(found.find((f) => f.agent === "claude")).toBeDefined();
  });

  test("reports nothing found cleanly", () => {
    const found = detectAgents({ pathDirs: [tmp()], extraLocations: [] });
    expect(found).toEqual([]);
  });
});

describe("graduation nudge (R2)", () => {
  let dir: string;
  beforeEach(() => (dir = tmp()));

  test("nudges once on the 3rd run, never again if dismissed", () => {
    const g = new GraduationTracker(dir);
    expect(g.recordRunAndCheck("claude")).toBe(false); // 1
    expect(g.recordRunAndCheck("claude")).toBe(false); // 2
    expect(g.recordRunAndCheck("claude")).toBe(true); // 3 → nudge
    expect(g.recordRunAndCheck("claude")).toBe(false); // 4, already nudged
    g.dismiss("claude");
    expect(g.recordRunAndCheck("claude")).toBe(false); // stays dismissed
  });

  test("per-agent counters are independent", () => {
    const g = new GraduationTracker(dir);
    g.recordRunAndCheck("claude");
    g.recordRunAndCheck("claude");
    expect(g.recordRunAndCheck("codex")).toBe(false); // codex only at 1
    expect(g.recordRunAndCheck("claude")).toBe(true); // claude at 3
  });

  test("persists across instances", () => {
    new GraduationTracker(dir).recordRunAndCheck("claude");
    new GraduationTracker(dir).recordRunAndCheck("claude");
    expect(new GraduationTracker(dir).recordRunAndCheck("claude")).toBe(true);
  });

  test("watch marks graduated so no further nudges", () => {
    const g = new GraduationTracker(dir);
    g.markWatched("claude");
    g.recordRunAndCheck("claude");
    g.recordRunAndCheck("claude");
    expect(g.recordRunAndCheck("claude")).toBe(false);
  });
});
