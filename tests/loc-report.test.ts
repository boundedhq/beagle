import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  countLoc,
  locReport,
  CORE_BUDGET,
  TRUST_PATH_BUDGET,
  TRUST_PATH_SCOPE,
} from "../scripts/loc-report";

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
    expect(r.trustPath).toBe(5);
    expect(r.total).toBe(6);
    expect(r.perFile.find((f) => f.file.endsWith("daemon.ts"))?.trustPath).toBe(true);
    expect(r.perFile.find((f) => f.file.endsWith("main.ts"))?.trustPath).toBe(false);
  });

  test("trust-path manifest names the complex capture and redaction modules", () => {
    expect(TRUST_PATH_SCOPE.files).toContain("src/daemon/daemon.ts");
    expect(TRUST_PATH_SCOPE.files).toContain("src/parsers/otlp-map.ts");
    expect(TRUST_PATH_SCOPE.files).toContain("src/parsers/parsers.ts");
    expect(TRUST_PATH_SCOPE.files).toContain("src/transform/redact.ts");
    expect(TRUST_PATH_SCOPE.files).toContain("src/adapters/scan-host.ts");
  });

  test("missing manifest entries are visible instead of silently shrinking scope", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core"), { recursive: true });
    writeFileSync(join(root, "src/core/x.ts"), "const x = 1;\n");
    const r = locReport(root);
    expect(r.missingTrustPathFiles).toContain("src/daemon/daemon.ts");
    expect(r.missingTrustPathFiles).toContain("src/transform/redact.ts");
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
});
