// LOC accounting for the R9 legibility budget: the security-path core
// (src/core) must stay ≤ CORE_BUDGET readable lines; everything else is
// disclosed in the same report but not budgeted.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export const CORE_BUDGET = 1500;

export interface LocResult {
  core: number;
  total: number;
  overBudget: boolean;
  perFile: Array<{ file: string; lines: number; core: boolean }>;
}

export function countLoc(source: string): number {
  let count = 0;
  let inBlockComment = false;
  for (const rawLine of source.split("\n")) {
    let line = rawLine.trim();
    if (inBlockComment) {
      const end = line.indexOf("*/");
      if (end === -1) continue;
      line = line.slice(end + 2).trim();
      inBlockComment = false;
    }
    // Strip block comments that open (and possibly close) on this line.
    while (true) {
      const start = line.indexOf("/*");
      if (start === -1) break;
      const end = line.indexOf("*/", start + 2);
      if (end === -1) {
        line = line.slice(0, start).trim();
        inBlockComment = true;
        break;
      }
      line = (line.slice(0, start) + " " + line.slice(end + 2)).trim();
    }
    if (line === "" || line.startsWith("//")) continue;
    count++;
  }
  return count;
}

function* walk(dir: string): Generator<string> {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      if (entry === "node_modules" || entry === ".git") continue;
      yield* walk(p);
    } else {
      yield p;
    }
  }
}

export function locReport(root: string): LocResult {
  const srcDir = join(root, "src");
  const perFile: LocResult["perFile"] = [];
  let core = 0;
  let total = 0;
  let files: string[] = [];
  try {
    files = [...walk(srcDir)];
  } catch {
    // no src dir yet
  }
  for (const file of files) {
    const rel = relative(root, file);
    if (!rel.endsWith(".ts")) continue;
    if (rel.endsWith(".test.ts")) continue;
    const lines = countLoc(readFileSync(file, "utf8"));
    const isCore = rel.startsWith(join("src", "core") + "/") || rel === join("src", "core");
    perFile.push({ file: rel, lines, core: isCore });
    total += lines;
    if (isCore) core += lines;
  }
  return { core, total, overBudget: core > CORE_BUDGET, perFile };
}

if (import.meta.main) {
  const root = process.argv[2] ?? process.cwd();
  const check = process.argv.includes("--check");
  const r = locReport(root);
  for (const f of r.perFile.sort((a, b) => b.lines - a.lines)) {
    console.log(`${f.core ? "CORE " : "     "} ${String(f.lines).padStart(6)}  ${f.file}`);
  }
  console.log(`\ncore: ${r.core} / ${CORE_BUDGET} budget · total: ${r.total}`);
  if (check && r.overBudget) {
    console.error(`FAIL: core LOC ${r.core} exceeds the ${CORE_BUDGET} budget (R9)`);
    process.exit(1);
  }
}
