import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findBunImportViolations } from "../scripts/lint-bun-imports";

function scratch(): string {
  return mkdtempSync(join(tmpdir(), "beagle-lint-"));
}

describe("findBunImportViolations", () => {
  test("flags bun: imports outside src/adapters", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core/store"), { recursive: true });
    writeFileSync(
      join(root, "src/core/store/store.ts"),
      'import { Database } from "bun:sqlite";\n',
    );
    const v = findBunImportViolations(root);
    expect(v.length).toBe(1);
    expect(v[0]?.file).toContain("src/core/store/store.ts");
    expect(v[0]?.specifier).toBe("bun:sqlite");
  });

  test("allows bun: imports inside src/adapters", () => {
    const root = scratch();
    mkdirSync(join(root, "src/adapters"), { recursive: true });
    writeFileSync(join(root, "src/adapters/sqlite.ts"), 'import { Database } from "bun:sqlite";\n');
    expect(findBunImportViolations(root)).toEqual([]);
  });

  test("allows bun:test in test files anywhere", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core"), { recursive: true });
    writeFileSync(join(root, "src/core/x.test.ts"), 'import { test } from "bun:test";\n');
    expect(findBunImportViolations(root)).toEqual([]);
  });

  test("catches dynamic and require-style imports", () => {
    const root = scratch();
    mkdirSync(join(root, "src/cli"), { recursive: true });
    writeFileSync(join(root, "src/cli/a.ts"), 'const m = await import("bun:sqlite");\n');
    writeFileSync(join(root, "src/cli/b.ts"), 'const m = require("bun:ffi");\n');
    const v = findBunImportViolations(root);
    expect(v.map((x) => x.specifier).sort()).toEqual(["bun:ffi", "bun:sqlite"]);
  });

  test("node: stdlib imports are fine anywhere", () => {
    const root = scratch();
    mkdirSync(join(root, "src/core"), { recursive: true });
    writeFileSync(join(root, "src/core/x.ts"), 'import net from "node:net";\n');
    expect(findBunImportViolations(root)).toEqual([]);
  });
});
