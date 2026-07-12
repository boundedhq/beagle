# Contributing to Beagle

Thanks for looking under the hood — that's the point of this project.

## Dev setup

Beagle is TypeScript on [Bun](https://bun.sh) (≥ 1.3):

```sh
git clone https://github.com/boundedhq/beagle && cd beagle
bun install
bun run check     # lint + LOC budget + typecheck + full test suite
bun run build     # dist/beagle single binary
```

`bun run check` is exactly what CI runs. If it's green locally, CI will be
green.

## The rules that make this project what it is

These are enforced by CI, not by convention:

1. **The core LOC budget is a feature.** `src/core/` — the audited security
   path — must stay ≤ 1,500 lines (`bun run loc:check`). If your change
   pushes it over, either the change carves something non-security out of
   core, or it doesn't land. "Small enough to read" is Beagle's main trust
   property.
2. **Core is stdlib-only.** No third-party imports and no `bun:*` imports in
   `src/core/` (`scripts/lint-bun-imports.ts`). Bun-specific surface lives
   in `src/adapters/` only.
3. **Captured content is rendered as text nodes, never markup.** The viewer
   lint (`scripts/lint-viewer-safety.ts`) bans `innerHTML` and friends —
   captured traffic is hostile input.
4. **Detection rules are data, not code.** Rule changes edit
   `rules/beagle-rules.json` (and its pin); the matcher stays generic.
5. **No new runtime dependencies** without a discussion issue first. The
   viewer's Preact/htm are vendored and pinned deliberately.

## Pull requests

- Write tests first when you can; every behavior fix needs a test that
  fails without it.
- Keep PRs single-purpose. Mechanical renames, formatting-only, or
  vendored-file updates go in their own PRs.
- The precision gate (`tests/precision.test.ts`, <5% false positives) and
  the perf budgets (`tests/budget.test.ts`) are ship gates — a PR that
  trades them away needs a very good reason.

## Reporting bugs vs vulnerabilities

Ordinary bugs → GitHub issues, with `beagle status` output and repro steps.
Anything security-sensitive → see [SECURITY.md](SECURITY.md) (private
reporting); please don't open a public issue.
