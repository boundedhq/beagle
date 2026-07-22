// Docs-claims guard: Beagle does not publish a false-positive RATE. The
// curated fixtures in tests/precision.test.ts pin known detector behavior;
// they are not a sample from which to estimate a real-world rate, so no public
// doc may restate them as a percentage. This lints all Markdown in the active
// checkout for that overclaim reappearing (not nested worktree copies).
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

const FORBIDDEN = [
  {
    // "false positive(s)" within ~30 chars of a numeric percentage, in either
    // order. Symmetric and hyphen/space/underscore-tolerant so a reworded
    // reintroduction ("false-positive … 5%", "5 percent false positives",
    // "false  positives … 5%") can't slip through; the window is bounded so an
    // unrelated percentage elsewhere in a paragraph doesn't trip it. This is a
    // heuristic guard on our OWN docs — a rare false alarm is a one-line reword,
    // never a shipped bug.
    pattern:
      /false[-\s_]*positives?[\s\S]{0,30}\d\s?(?:%|percent)|\d\s?(?:%|percent)[\s\S]{0,30}false[-\s_]*positives?/i,
    why: "a false-positive rate stated as a percentage (unsupported without a large, representative corpus)",
  },
];

export interface DocsClaimViolation {
  file: string;
  line: number;
  why: string;
}

export function findDocsClaimViolations(root: string): DocsClaimViolation[] {
  const violations: DocsClaimViolation[] = [];
  let entries: string[];
  try {
    entries = readdirSync(root, { recursive: true } as { recursive: true }) as string[];
  } catch {
    return [];
  }
  for (const rel of entries) {
    const norm = rel.replaceAll("\\", "/");
    if (!norm.endsWith(".md")) continue;
    if (norm.startsWith("node_modules/") || norm.includes("/node_modules/")) continue;
    if (norm.startsWith(".git/")) continue;
    if (norm.startsWith(".claude/worktrees/")) continue;
    let text: string;
    try {
      text = readFileSync(join(root, rel), "utf8");
    } catch {
      continue; // a directory named *.md, or an unreadable entry — skip
    }
    // Scan each file on its own: a proximity match must not straddle a file
    // boundary (two individually-clean docs read together could otherwise trip).
    for (const f of FORBIDDEN) {
      const m = f.pattern.exec(text);
      if (m) {
        const line = text.slice(0, m.index).split("\n").length;
        violations.push({ file: norm, line, why: f.why });
      }
    }
  }
  return violations;
}

if (import.meta.main) {
  const root = process.argv.slice(2).find((a) => !a.startsWith("--")) ?? process.cwd();
  const v = findDocsClaimViolations(root);
  if (v.length > 0) {
    for (const x of v) console.error(`docs-claims: ${x.why} — ${x.file}:${x.line}`);
    process.exit(1);
  }
  console.log("docs-claims lint: clean");
}
