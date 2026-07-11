// Cross-compile the single binary for each supported target (R1/R9). Bun's
// --compile --target produces a self-contained executable per platform; the
// rules/ and viewer static assets are embedded via imports at build time.
// No post-install fetch, ever (supply-chain rule).
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const TARGETS = [
  { target: "bun-darwin-arm64", out: "beagle-darwin-arm64" },
  { target: "bun-darwin-x64", out: "beagle-darwin-x64" },
  { target: "bun-linux-x64", out: "beagle-linux-x64" },
  { target: "bun-linux-arm64", out: "beagle-linux-arm64" },
];

const distDir = join(process.cwd(), "dist", "release");
mkdirSync(distDir, { recursive: true });

let failed = false;
for (const t of TARGETS) {
  const outfile = join(distDir, t.out);
  console.log(`building ${t.out}…`);
  const r = Bun.spawnSync([
    "bun", "build", "--compile", `--target=${t.target}`,
    "src/cli/main.ts", "--outfile", outfile,
  ]);
  if (r.exitCode !== 0) {
    console.error(`  FAILED: ${r.stderr.toString()}`);
    failed = true;
  } else {
    console.log(`  → ${outfile}`);
  }
}
process.exit(failed ? 1 : 0);
