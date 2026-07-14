// Assemble the npm publish tree from the per-platform binaries in
// dist/release/ (produced by build-release.ts). Layout:
//   dist/npm/beagle/                  → the launcher package (@boundedhq/beagle)
//   dist/npm/beagle-<os>-<cpu>/       → one binary package per platform
// The launcher package carries the binaries as optionalDependencies pinned to
// this exact version; npm installs only the one whose os/cpu match. No
// post-install scripts, no network — the binary is already in the tarball.
import { copyFileSync, cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { BEAGLE_VERSION as VERSION } from "../src/core/version";

const SCOPE = "@boundedhq";
const PKG = `${SCOPE}/beagle`;
const TARGETS = [
  { os: "darwin", cpu: "arm64" },
  { os: "darwin", cpu: "x64" },
  { os: "linux", cpu: "x64" },
  { os: "linux", cpu: "arm64" },
];

const repo = "github:boundedhq/beagle";
const license = "MIT";
// Dirs are overridable so the packaging test can drive this with stub binaries.
const releaseDir = process.env.BEAGLE_RELEASE_DIR ?? join(process.cwd(), "dist", "release");
const npmDir = process.env.BEAGLE_NPM_OUT ?? join(process.cwd(), "dist", "npm");
rmSync(npmDir, { recursive: true, force: true });

// One package per platform, each with its single binary + os/cpu guard.
const optionalDependencies: Record<string, string> = {};
for (const { os, cpu } of TARGETS) {
  const name = `${PKG}-${os}-${cpu}`;
  optionalDependencies[name] = VERSION;
  const dir = join(npmDir, `beagle-${os}-${cpu}`);
  mkdirSync(dir, { recursive: true });
  const binSrc = join(releaseDir, `beagle-${os}-${cpu}`);
  copyFileSync(binSrc, join(dir, "beagle")); // throws if build-release didn't run
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify(
      {
        name,
        version: VERSION,
        description: `Beagle prebuilt binary for ${os}-${cpu}.`,
        license,
        repository: repo,
        os: [os],
        cpu: [cpu],
        files: ["beagle"],
      },
      null,
      2,
    ) + "\n",
  );
}

// The launcher package users actually install.
const mainDir = join(npmDir, "beagle");
mkdirSync(join(mainDir, "bin"), { recursive: true });
cpSync(join(process.cwd(), "packaging", "npm", "launcher.cjs"), join(mainDir, "bin", "beagle.cjs"));
writeFileSync(
  join(mainDir, "package.json"),
  JSON.stringify(
    {
      name: PKG,
      version: VERSION,
      description: "Local transparency proxy for AI agents — see what they send, catch leaked secrets.",
      license,
      repository: repo,
      homepage: "https://github.com/boundedhq/beagle",
      bin: { beagle: "bin/beagle.cjs" },
      files: ["bin/beagle.cjs"],
      // The binary rides these; npm installs only the matching os/cpu.
      optionalDependencies,
      engines: { node: ">=18" },
    },
    null,
    2,
  ) + "\n",
);

console.log(`npm packages assembled in ${npmDir} at v${VERSION}:`);
console.log(`  ${PKG} + ${TARGETS.length} platform packages`);
