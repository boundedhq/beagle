// CLI entry point (non-core). Real commands land in PR 7; this is the
// compile target that proves the single-binary build path.
export const VERSION = "0.1.0";

export function run(argv: string[]): number {
  const arg = argv[0];
  if (arg === "--version" || arg === "-v") {
    console.log(`beagle ${VERSION}`);
    return 0;
  }
  console.log(`beagle ${VERSION} — a local transparency proxy for AI agents`);
  console.log("Commands arrive in upcoming PRs: run, watch, status, search, leaks, show, purge, ui");
  return 0;
}

if (import.meta.main) {
  process.exit(run(process.argv.slice(2)));
}
