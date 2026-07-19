import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { countLoc, locReport, CORE_BUDGET } from "../scripts/loc-report";

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
  test("splits core vs non-core by directory", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core/store"), { recursive: true });
    mkdirSync(join(root, "src/cli"), { recursive: true });
    writeFileSync(join(root, "src/core/store/store.ts"), "const a = 1;\nconst b = 2;\n");
    writeFileSync(join(root, "src/cli/main.ts"), "const c = 3;\n");
    const r = locReport(root);
    expect(r.core).toBe(2);
    expect(r.total).toBe(3);
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

  test("core budget is the R9 ceiling", () => {
    expect(CORE_BUDGET).toBe(2000);
  });

  test("overBudget flag set when core exceeds budget", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core"), { recursive: true });
    const lines = Array.from({ length: CORE_BUDGET + 1 }, (_, i) => `const v${i} = ${i};`).join("\n");
    writeFileSync(join(root, "src/core/big.ts"), lines + "\n");
    const r = locReport(root);
    expect(r.overBudget).toBe(true);
  });
});
