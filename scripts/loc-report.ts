// LOC accounting for two distinct R9 legibility boundaries: the dependency-
// free runtime core and the wider capture-to-alert trust path.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

export const CORE_BUDGET = 2000;
export const TRUST_PATH_BUDGET = 5000;

/** Explicit audit scope for capture, parsing, scanning, redaction, persistence,
 * and alert delivery. src/core remains a separate portability boundary. */
export const TRUST_PATH_SCOPE = {
  directories: ["src/core/"],
  files: [
    "src/adapters/codex-rollout-tailer.ts",
    "src/adapters/scan-host.ts",
    "src/adapters/scan-worker-entry.ts",
    "src/adapters/sqlite.ts",
    "src/daemon/daemon.ts",
    "src/notifier/alert-copy.ts",
    "src/notifier/notifier.ts",
    "src/parsers/codex-rollout.ts",
    "src/parsers/otlp-map.ts",
    "src/parsers/parsers.ts",
    "src/transform/redact.ts",
  ],
} as const;

export interface LocResult {
  core: number;
  trustPath: number;
  total: number;
  overCoreBudget: boolean;
  overTrustPathBudget: boolean;
  missingTrustPathFiles: string[];
  perFile: Array<{ file: string; lines: number; core: boolean; trustPath: boolean }>;
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
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      yield* walk(p);
    } else if (entry.isFile()) {
      yield p;
    }
  }
}

export function locReport(root: string): LocResult {
  const srcDir = join(root, "src");
  const perFile: LocResult["perFile"] = [];
  let core = 0;
  let trustPath = 0;
  let total = 0;
  const seenFiles = new Set<string>();
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
    const normalized = rel.replaceAll("\\", "/");
    seenFiles.add(normalized);
    const isCore = normalized.startsWith("src/core/");
    const isTrustPath =
      TRUST_PATH_SCOPE.directories.some((dir) => normalized.startsWith(dir)) ||
      (TRUST_PATH_SCOPE.files as readonly string[]).includes(normalized);
    perFile.push({ file: rel, lines, core: isCore, trustPath: isTrustPath });
    total += lines;
    if (isCore) core += lines;
    if (isTrustPath) trustPath += lines;
  }
  return {
    core,
    trustPath,
    total,
    overCoreBudget: core > CORE_BUDGET,
    overTrustPathBudget: trustPath > TRUST_PATH_BUDGET,
    missingTrustPathFiles: TRUST_PATH_SCOPE.files.filter((file) => !seenFiles.has(file)),
    perFile,
  };
}

if (import.meta.main) {
  const args = process.argv.slice(2);
  const check = args.includes("--check");
  const root = args.find((a) => !a.startsWith("--")) ?? process.cwd();
  const r = locReport(root);
  for (const f of r.perFile.sort((a, b) => b.lines - a.lines)) {
    const scope = f.core ? "CORE " : f.trustPath ? "TRUST" : "     ";
    console.log(`${scope} ${String(f.lines).padStart(6)}  ${f.file}`);
  }
  console.log(
    `\ndependency-free core: ${r.core} / ${CORE_BUDGET} budget` +
      ` · trust path: ${r.trustPath} / ${TRUST_PATH_BUDGET} budget` +
      ` · total: ${r.total}`,
  );
  if (check && r.overCoreBudget) {
    console.error(`FAIL: dependency-free core LOC ${r.core} exceeds the ${CORE_BUDGET} budget (R9)`);
  }
  if (check && r.overTrustPathBudget) {
    console.error(`FAIL: trust-path LOC ${r.trustPath} exceeds the ${TRUST_PATH_BUDGET} budget (R9)`);
  }
  if (check && r.missingTrustPathFiles.length > 0) {
    console.error(`FAIL: trust-path manifest entries are missing: ${r.missingTrustPathFiles.join(", ")}`);
  }
  if (check && (r.overCoreBudget || r.overTrustPathBudget || r.missingTrustPathFiles.length > 0)) {
    process.exit(1);
  }
}
