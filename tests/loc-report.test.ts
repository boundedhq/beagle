import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { countLoc, locReport, CORE_BUDGET, TRUST_PATH_BUDGET } from "../scripts/loc-report";

function scratch(): string {
  return mkdtempSync(join(tmpdir(), "beagle-loc-"));
}

describe("countLoc", () => {
  test("counts non-blank, non-comment lines", () => {
    const src = [
      "// a comment",
      "",
      "const x = 1;",
      "  ",
      "/* block",
      "   comment */",
      "const y = 2; // trailing comment still counts",
      "",
    ].join("\n");
    expect(countLoc(src)).toBe(2);
  });

  test("empty file counts zero", () => {
    expect(countLoc("")).toBe(0);
    expect(countLoc("\n\n// only comments\n")).toBe(0);
  });
});

describe("locReport", () => {
  test("separates the dependency-free core, wider trust path, and other code", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core/store"), { recursive: true });
    mkdirSync(join(root, "src/daemon"), { recursive: true });
    mkdirSync(join(root, "src/parsers"), { recursive: true });
    mkdirSync(join(root, "src/cli"), { recursive: true });
    writeFileSync(join(root, "src/core/store/store.ts"), "const a = 1;\nconst b = 2;\n");
    writeFileSync(join(root, "src/daemon/daemon.ts"), "const c = 3;\nconst d = 4;\n");
    writeFileSync(join(root, "src/parsers/parsers.ts"), "const e = 5;\n");
    writeFileSync(join(root, "src/cli/main.ts"), "const f = 6;\n");
    const r = locReport(root);
    expect(r.core).toBe(2);
    // trustPath INCLUDES core (2) plus daemon (2) + parsers (1): a regression
    // that excluded or double-counted core would break this exact total.
    expect(r.trustPath).toBe(5);
    expect(r.total).toBe(6);
    expect(r.perFile.find((f) => f.file.endsWith("daemon.ts"))?.trustPath).toBe(true);
    expect(r.perFile.find((f) => f.file.endsWith("main.ts"))?.trustPath).toBe(false);
  });

  test("the complex capture/redaction/demo modules are actually attributed to the trust path", () => {
    // Exercise the real isTrustPath logic (not just the manifest constant): a
    // directory-covered module and the explicit daemon file must both count.
    const root = scratch();
    for (const rel of [
      "src/adapters/scan-host.ts", // directory-covered (src/adapters/)
      "src/parsers/otlp-map.ts", // directory-covered (src/parsers/)
      "src/transform/redact.ts", // directory-covered (src/transform/)
      "src/notifier/notifier.ts", // directory-covered (src/notifier/)
      "src/daemon/daemon.ts", // explicit file entry
      "src/cli/demo.ts", // explicit file entry (loopback/fail-closed drill)
    ]) {
      mkdirSync(join(root, rel, ".."), { recursive: true });
      writeFileSync(join(root, rel), "const a = 1;\n");
    }
    // src/daemon/control.ts is deliberately OUT of scope (control-plane).
    mkdirSync(join(root, "src/daemon"), { recursive: true });
    writeFileSync(join(root, "src/daemon/control.ts"), "const c = 1;\n");
    const r = locReport(root);
    const byName = (name: string) => r.perFile.find((f) => f.file.replaceAll("\\", "/") === name);
    for (const rel of [
      "src/adapters/scan-host.ts",
      "src/parsers/otlp-map.ts",
      "src/transform/redact.ts",
      "src/notifier/notifier.ts",
      "src/daemon/daemon.ts",
      "src/cli/demo.ts",
    ]) {
      expect(byName(rel)?.trustPath).toBe(true);
    }
    expect(byName("src/daemon/control.ts")?.trustPath).toBe(false);
  });

  test("a missing explicit manifest file is flagged; a fully-present tree flags nothing", () => {
    // Explicit files absent → surfaced (never silently shrinks scope).
    const missing = scratch();
    mkdirSync(join(missing, "src/core"), { recursive: true });
    writeFileSync(join(missing, "src/core/x.ts"), "const x = 1;\n");
    expect(locReport(missing).missingTrustPathFiles).toContain("src/daemon/daemon.ts");
    expect(locReport(missing).missingTrustPathFiles).toContain("src/cli/demo.ts");
    // Both present → missing list is EMPTY (the case CI actually runs; a
    // guard that flagged present files would fail the build forever).
    const present = scratch();
    mkdirSync(join(present, "src/daemon"), { recursive: true });
    mkdirSync(join(present, "src/cli"), { recursive: true });
    writeFileSync(join(present, "src/daemon/daemon.ts"), "const d = 1;\n");
    writeFileSync(join(present, "src/cli/demo.ts"), "const e = 1;\n");
    expect(locReport(present).missingTrustPathFiles).toEqual([]);
  });

  test("a trust-path directory entry matches by prefix, not by adjacent name", () => {
    // The trailing slash on "src/core/" / "src/adapters/" is load-bearing: a
    // sibling dir sharing the prefix must NOT be pulled into either budget.
    const root = scratch();
    mkdirSync(join(root, "src/core-experimental"), { recursive: true });
    mkdirSync(join(root, "src/adapters-legacy"), { recursive: true });
    mkdirSync(join(root, "src/daemon"), { recursive: true });
    writeFileSync(join(root, "src/core-experimental/x.ts"), "const a = 1;\n");
    writeFileSync(join(root, "src/adapters-legacy/y.ts"), "const b = 2;\n");
    writeFileSync(join(root, "src/daemon/daemon.ts"), "const d = 3;\n"); // keep missing list empty
    const r = locReport(root);
    const byName = (name: string) => r.perFile.find((f) => f.file.replaceAll("\\", "/") === name);
    expect(byName("src/core-experimental/x.ts")?.core).toBe(false);
    expect(byName("src/core-experimental/x.ts")?.trustPath).toBe(false);
    expect(byName("src/adapters-legacy/y.ts")?.trustPath).toBe(false);
    expect(r.core).toBe(0);
  });

  test("ignores test files and non-ts files", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core"), { recursive: true });
    writeFileSync(join(root, "src/core/x.ts"), "const a = 1;\n");
    writeFileSync(join(root, "src/core/x.test.ts"), "const t = 1;\nconst u = 2;\n");
    writeFileSync(join(root, "src/core/notes.md"), "hello\nworld\n");
    const r = locReport(root);
    expect(r.core).toBe(1);
    expect(r.total).toBe(1);
  });

  test("publishes separate portability-core and trust-path ceilings", () => {
    expect(CORE_BUDGET).toBe(2000);
    expect(TRUST_PATH_BUDGET).toBe(5000);
  });

  test("core over-budget flag is set independently", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core"), { recursive: true });
    const lines = Array.from({ length: CORE_BUDGET + 1 }, (_, i) => `const v${i} = ${i};`).join("\n");
    writeFileSync(join(root, "src/core/big.ts"), lines + "\n");
    const r = locReport(root);
    expect(r.overCoreBudget).toBe(true);
    expect(r.overTrustPathBudget).toBe(false);
  });

  test("trust-path over-budget flag includes non-core security logic", () => {
    const root = scratch();
    mkdirSync(join(root, "src/daemon"), { recursive: true });
    const lines = Array.from({ length: TRUST_PATH_BUDGET + 1 }, (_, i) => `const v${i} = ${i};`).join("\n");
    writeFileSync(join(root, "src/daemon/daemon.ts"), lines + "\n");
    const r = locReport(root);
    expect(r.overCoreBudget).toBe(false);
    expect(r.overTrustPathBudget).toBe(true);
  });

  // The CLI gate (import.meta.main) is what CI actually depends on: its exit
  // code, not the LocResult booleans, is what blocks a merge. Spawn it so a
  // regression in the FAIL wiring / --check requirement can't ship green.
  test("--check gates the exit code; plain report never fails", () => {
    const script = join(import.meta.dir, "..", "scripts", "loc-report.ts");
    const run = (root: string, check: boolean) =>
      Bun.spawnSync(check ? ["bun", script, root, "--check"] : ["bun", script, root]);

    const clean = scratch();
    mkdirSync(join(clean, "src/core"), { recursive: true });
    mkdirSync(join(clean, "src/daemon"), { recursive: true });
    mkdirSync(join(clean, "src/cli"), { recursive: true });
    writeFileSync(join(clean, "src/core/x.ts"), "const a = 1;\n");
    writeFileSync(join(clean, "src/daemon/daemon.ts"), "const b = 2;\n");
    writeFileSync(join(clean, "src/cli/demo.ts"), "const c = 3;\n");
    expect(run(clean, true).exitCode).toBe(0);

    const overCore = scratch();
    mkdirSync(join(overCore, "src/core"), { recursive: true });
    mkdirSync(join(overCore, "src/daemon"), { recursive: true });
    mkdirSync(join(overCore, "src/cli"), { recursive: true });
    writeFileSync(join(overCore, "src/daemon/daemon.ts"), "const b = 2;\n");
    writeFileSync(join(overCore, "src/cli/demo.ts"), "const c = 3;\n");
    writeFileSync(
      join(overCore, "src/core/big.ts"),
      Array.from({ length: CORE_BUDGET + 1 }, (_, i) => `const v${i} = ${i};`).join("\n") + "\n",
    );
    const overRun = run(overCore, true);
    expect(overRun.exitCode).toBe(1);
    expect(overRun.stderr.toString()).toContain("FAIL");

    // daemon.ts absent → missing-manifest gate fails under --check,
    const miss = scratch();
    mkdirSync(join(miss, "src/core"), { recursive: true });
    writeFileSync(join(miss, "src/core/x.ts"), "const a = 1;\n");
    const missRun = run(miss, true);
    expect(missRun.exitCode).toBe(1);
    expect(missRun.stderr.toString()).toContain("missing");
    // …but the same failing tree exits 0 as a plain report (informational only).
    expect(run(miss, false).exitCode).toBe(0);
  });
});
