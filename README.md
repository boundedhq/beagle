# Beagle

Run one command and see exactly what your AI agents send to remote models —
with leaked secrets flagged the moment they leave your machine.

Beagle is a product of [Bounded](https://github.com/boundedhq). Local-only, no
telemetry, MIT-licensed, and small enough to read: the entire security path
(intercept → forward → capture → detect) is budgeted at ≤ 1,500 lines of
stdlib-only TypeScript, and CI publishes the count.

**Status: pre-release.** The skeleton builds a single self-contained binary
(`bun run build`); the proxy, scanner, CLI, and viewer land PR by PR.

## Layout

- `src/core/` — the audited security path (LOC-budgeted, stdlib-only, no `bun:*` imports)
- `src/adapters/` — the only home for Bun-specific surface
- `src/cli/`, `src/viewer/`, `src/parsers/` — non-core, disclosed in the same LOC report
- `scripts/` — budget enforcement (`loc-report.ts`, `lint-bun-imports.ts`)

## Development

```sh
bun install
bun run check   # lint + LOC budget + typecheck + tests
bun run build   # dist/beagle single binary
```
