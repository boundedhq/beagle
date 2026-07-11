// Runtime hedge (design §2): Bun-specific imports (`bun:*`) are confined to
// src/adapters so a runtime change lands in one adapter, not across the core.
// `bun:test` is allowed in *.test.ts anywhere.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface Violation {
  file: string;
  specifier: string;
}

const IMPORT_RE =
  /(?:from\s*|import\s*\(\s*|require\s*\(\s*)["'](bun:[a-z-]+)["']/g;

function* walk(dir: string): Generator<string> {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      if (entry === "node_modules" || entry === ".git") continue;
      yield* walk(p);
    } else if (p.endsWith(".ts")) {
      yield p;
    }
  }
}

export function findBunImportViolations(root: string): Violation[] {
  const srcDir = join(root, "src");
  const violations: Violation[] = [];
  let files: string[] = [];
  try {
    files = [...walk(srcDir)];
  } catch {
    return [];
  }
  for (const file of files) {
    const rel = relative(root, file);
    if (rel.startsWith(join("src", "adapters") + "/")) continue;
    const isTest = rel.endsWith(".test.ts");
    const source = readFileSync(file, "utf8");
    for (const m of source.matchAll(IMPORT_RE)) {
      const specifier = m[1];
      if (specifier === undefined) continue;
      if (isTest && specifier === "bun:test") continue;
      violations.push({ file: rel, specifier });
    }
  }
  return violations;
}

if (import.meta.main) {
  const violations = findBunImportViolations(process.argv[2] ?? process.cwd());
  if (violations.length > 0) {
    for (const v of violations) {
      console.error(`bun:* import outside src/adapters: ${v.specifier} in ${v.file}`);
    }
    process.exit(1);
  }
  console.log("bun-import lint: clean");
}
