import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findDocsClaimViolations } from "../scripts/lint-docs-claims";

function scratch(): string {
  return mkdtempSync(join(tmpdir(), "beagle-docs-lint-"));
}

describe("findDocsClaimViolations", () => {
  test("flags a false-positive percentage claim, in either order and across spacings", () => {
    for (const claim of [
      "Structured-alert false positives | < 5% of 22 curated negatives", // the exact removed claim
      "holds the loud tier to fewer than 5% false positives", // percent-first
      "the false-positive rate is under 5 percent", // hyphen + spelled-out
      "false  positives stay below 5%", // multi-space (the old regex's blind spot)
      "false_positives: 5%", // underscore
    ]) {
      const root = scratch();
      writeFileSync(join(root, "README.md"), `# Docs\n\n${claim}\n`);
      const v = findDocsClaimViolations(root);
      expect(v.length).toBeGreaterThanOrEqual(1);
      expect(v[0]?.file).toBe("README.md");
    }
  });

  test("finds the claim in ANY markdown file, not just README/CONTRIBUTING", () => {
    const root = scratch();
    mkdirSync(join(root, "docs"), { recursive: true });
    writeFileSync(join(root, "SECURITY.md"), "we keep false positives under 5%\n");
    writeFileSync(join(root, "docs", "faq.md"), "clean\n");
    const v = findDocsClaimViolations(root);
    expect(v.some((x) => x.file === "SECURITY.md")).toBe(true);
  });

  test("allows honest prose that mentions false positives without a rate", () => {
    const root = scratch();
    writeFileSync(
      join(root, "README.md"),
      "The gate keeps curated negatives free of false positives; it is not a measured false-positive rate.\n",
    );
    writeFileSync(join(root, "CONTRIBUTING.md"), "The curated detector regression gate is a ship gate.\n");
    expect(findDocsClaimViolations(root)).toEqual([]);
  });

  test("an unrelated percentage far from any false-positive mention does not trip", () => {
    const root = scratch();
    writeFileSync(
      join(root, "README.md"),
      "Install size ≤ 100 MB; the vendored ruleset covers 95% of documented key formats.\n\n" +
        "Separately, on example keys in code this tool avoids false positives at the loud tier.\n",
    );
    expect(findDocsClaimViolations(root)).toEqual([]);
  });

  test("ignores non-markdown files and node_modules", () => {
    const root = scratch();
    mkdirSync(join(root, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(root, "node_modules", "dep", "README.md"), "false positives under 5%\n");
    writeFileSync(join(root, "notes.txt"), "false positives under 5%\n");
    expect(findDocsClaimViolations(root)).toEqual([]);
  });

  test("ignores Claude worktree copies while still checking active docs", () => {
    const root = scratch();
    mkdirSync(join(root, ".claude", "worktrees", "old-checkout"), { recursive: true });
    writeFileSync(
      join(root, ".claude", "worktrees", "old-checkout", "README.md"),
      "false positives under 5%\n",
    );
    writeFileSync(join(root, "README.md"), "active docs are clean\n");
    expect(findDocsClaimViolations(root)).toEqual([]);

    writeFileSync(join(root, "SECURITY.md"), "false positives under 5%\n");
    expect(findDocsClaimViolations(root).map((x) => x.file)).toEqual(["SECURITY.md"]);
  });

  test("the repo's own docs are clean (the published claim is gone)", () => {
    expect(findDocsClaimViolations(join(import.meta.dir, ".."))).toEqual([]);
  });
});
