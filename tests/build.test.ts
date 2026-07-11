import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("compiled binary", () => {
  test(
    "bun build --compile produces a runnable binary that prints version",
    async () => {
      const out = join(mkdtempSync(join(tmpdir(), "beagle-build-")), "beagle");
      const build = Bun.spawnSync([
        "bun", "build", "--compile", "src/cli/main.ts", "--outfile", out,
      ], { cwd: join(import.meta.dir, "..") });
      expect(build.exitCode).toBe(0);

      const run = Bun.spawnSync([out, "--version"]);
      expect(run.exitCode).toBe(0);
      expect(run.stdout.toString()).toMatch(/^beagle \d+\.\d+\.\d+/);
    },
    120_000,
  );
});
