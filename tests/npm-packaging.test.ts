import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BEAGLE_VERSION } from "../src/core/version";

// Drives scripts/build-npm.ts with stub binaries (env-overridden dirs) and
// checks the tree it produces. The load-bearing invariant: the launcher
// package's optionalDependencies must EXACTLY match the platform package
// names+versions, and the launcher's own `@boundedhq/beagle-<os>-<cpu>` naming
// (in launcher.cjs) must match those names — any drift breaks every install.
describe("npm packaging", () => {
  const TARGETS = ["darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64"];

  function build(): string {
    const root = mkdtempSync(join(tmpdir(), "beagle-npm-"));
    const releaseDir = join(root, "release");
    const npmOut = join(root, "npm");
    mkdirSync(releaseDir, { recursive: true });
    for (const t of TARGETS) writeFileSync(join(releaseDir, `beagle-${t}`), `#!stub ${t}\n`);
    const r = Bun.spawnSync(["bun", "scripts/build-npm.ts"], {
      env: { ...process.env, BEAGLE_RELEASE_DIR: releaseDir, BEAGLE_NPM_OUT: npmOut },
    });
    if (r.exitCode !== 0) throw new Error(`build-npm failed: ${r.stderr.toString()}`);
    return npmOut;
  }

  test("launcher optionalDependencies match the platform packages exactly (name + version)", () => {
    const npmOut = build();
    const main = JSON.parse(readFileSync(join(npmOut, "beagle", "package.json"), "utf8"));
    expect(main.name).toBe("@boundedhq/beagle");
    expect(main.version).toBe(BEAGLE_VERSION);
    expect(main.bin).toEqual({ beagle: "bin/beagle.cjs" });
    // provenance needs a canonical git URL to match the package against
    expect(main.repository?.url).toContain("github.com/boundedhq/beagle");
    // README ships so the primary channel's npm page isn't blank
    expect(existsSync(join(npmOut, "beagle", "README.md"))).toBe(true);

    const expected = Object.fromEntries(TARGETS.map((t) => [`@boundedhq/beagle-${t}`, BEAGLE_VERSION]));
    expect(main.optionalDependencies).toEqual(expected);

    for (const t of TARGETS) {
      const [os, cpu] = t.split("-");
      const p = JSON.parse(readFileSync(join(npmOut, `beagle-${t}`, "package.json"), "utf8"));
      expect(p.name).toBe(`@boundedhq/beagle-${t}`);
      expect(p.version).toBe(BEAGLE_VERSION);
      expect(p.os).toEqual([os]);
      expect(p.cpu).toEqual([cpu]);
      expect(p.files).toEqual(["beagle"]);
      // the binary rides the tarball — no post-install fetch
      expect(existsSync(join(npmOut, `beagle-${t}`, "beagle"))).toBe(true);
    }
    expect(existsSync(join(npmOut, "beagle", "bin", "beagle.cjs"))).toBe(true);
  });

  test("every platform the launcher resolves to has a matching published package", () => {
    // launcher.cjs computes `@boundedhq/beagle-${process.platform}-${cpu}` where
    // cpu maps x64→x64, arm64→arm64. Reproduce that mapping for each supported
    // (platform, arch) and assert the launcher would land on a real optionalDep
    // — this is the drift guard between launcher.cjs and build-npm.ts.
    const main = JSON.parse(readFileSync(join(build(), "beagle", "package.json"), "utf8"));
    const supported: Array<[string, string]> = [
      ["darwin", "arm64"], ["darwin", "x64"], ["linux", "x64"], ["linux", "arm64"],
    ];
    for (const [platform, arch] of supported) {
      const cpu = arch === "x64" ? "x64" : arch === "arm64" ? "arm64" : arch;
      const name = `@boundedhq/beagle-${platform}-${cpu}`;
      expect(main.optionalDependencies[name]).toBe(BEAGLE_VERSION);
    }
    // and the launcher source still uses that exact naming scheme
    const src = readFileSync(join(import.meta.dir, "..", "packaging", "npm", "launcher.cjs"), "utf8");
    expect(src).toContain("@boundedhq/beagle-${process.platform}-${cpu}");
  });
});
