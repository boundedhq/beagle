// Viewer XSS guard (design §6.8): everything in the store is
// attacker-influenceable, so the SPA must never interpolate captured content
// into markup. Forbid dangerouslySetInnerHTML and innerHTML assignment in the
// viewer's client code.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

const FORBIDDEN = [
  { pattern: /dangerouslySetInnerHTML/, why: "dangerouslySetInnerHTML" },
  { pattern: /\.innerHTML\s*=/, why: ".innerHTML assignment" },
  { pattern: /\.outerHTML\s*=/, why: ".outerHTML assignment" },
  { pattern: /insertAdjacentHTML/, why: "insertAdjacentHTML" },
];

export interface SafetyViolation {
  file: string;
  line: number;
  why: string;
}

export function findViewerSafetyViolations(root: string): SafetyViolation[] {
  const dir = join(root, "src", "viewer", "static");
  const violations: SafetyViolation[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir, { recursive: true } as { recursive: true }) as string[];
  } catch {
    return [];
  }
  for (const rel of entries) {
    if (!rel.endsWith(".js")) continue;
    if (rel.includes("vendor/")) continue; // vendored libs are pinned by hash
    const full = join(dir, rel);
    const lines = readFileSync(full, "utf8").split("\n");
    lines.forEach((line, i) => {
      for (const f of FORBIDDEN) {
        if (f.pattern.test(line)) {
          violations.push({ file: relative(root, full), line: i + 1, why: f.why });
        }
      }
    });
  }
  return violations;
}

if (import.meta.main) {
  const v = findViewerSafetyViolations(process.argv.slice(2).find((a) => !a.startsWith("--")) ?? process.cwd());
  if (v.length > 0) {
    for (const x of v) console.error(`viewer-safety: ${x.why} in ${x.file}:${x.line}`);
    process.exit(1);
  }
  console.log("viewer-safety lint: clean");
}
