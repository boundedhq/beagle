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

`bun run check` covers the same gates CI runs (CI additionally compiles the
binary and checks its size, on macOS and Ubuntu). If `check` is green
locally, CI almost certainly is too. Don't be alarmed by the test output:
it includes simulated leak banners and consent prompts (the tests exercise
the CLI's real output paths) — they're expected, and the run never waits
for input.

Useful day-to-day:

```sh
bun test tests/watch.test.ts        # one suite instead of all ~30
bun src/cli/main.ts <command>       # run the CLI uncompiled — picks up your
                                    # edits with no build step
./dist/beagle <command>             # or the compiled binary after bun run build
```

(Uncompiled `watch` installs a shim pointing at your working tree — fine for
dev, just `unwatch` before switching back to a release binary.)

## The rules CI enforces

Most of these have mechanical teeth — a lint script, the LOC checker, or a
pin test; where one doesn't, review holds the line:

1. **The LOC budgets are a feature.** `bun run loc:check` enforces two nested
   ceilings and fails if either is exceeded — or if a listed manifest file goes
   missing: the dependency-free runtime core (`src/core/`, ≤ 2,000 lines,
   stdlib-only) and the wider capture-to-alert trust path (`TRUST_PATH_SCOPE` in
   `scripts/loc-report.ts`, ≤ 5,000 lines, counting the core once inside it).
   `src/core/` is the portability boundary, **not** the whole security-audit
   scope — that is the trust path (daemon ingestion, parsers, redact-on-capture,
   scanner hosting, persistence adapters, rollout capture, alert delivery). The
   ceilings are published, CI-enforced trust properties — "small enough to read
   in one sitting" — so spend the headroom deliberately: prefer carving
   something out of a budgeted path to growing it, and don't treat the slack as
   free.
2. **Core is stdlib-only.** `scripts/lint-bun-imports.ts` bans `bun:*`
   imports everywhere in `src/` outside `src/adapters/` — Bun-specific
   surface lives in adapters only. The rest of the rule — no third-party
   imports in `src/core/`, `node:` stdlib and relative imports only — is
   stated in `src/core/README.md` and held by review.
3. **Captured content is rendered as text nodes, never markup.** The viewer
   lint (`scripts/lint-viewer-safety.ts`) bans `innerHTML` and friends —
   captured traffic is hostile input.
4. **Detection rules are data, not code.** Rule changes edit
   `rules/beagle-rules.json`, then regenerate the pin (tests fail on a
   mismatch):
   `shasum -a 256 rules/beagle-rules.json | cut -d' ' -f1 > rules/beagle-rules.sha256`.
   The matcher stays generic.
5. **No new runtime dependencies** without a discussion issue first. The
   viewer's Preact/htm are vendored and pinned deliberately.

## Things that will save you an hour

- **Viewer changes don't show up until you rebuild.** The dashboard's
  `app.js`/`style.css` are compiled *into* the binary
  (`import ... with { type: "text" }` in `src/viewer/server.ts`). If a
  daemon is already running — especially a service-managed one — it serves
  the old assets until it restarts. Loop: edit → `bun run build` →
  `beagle stop` → reopen `beagle ui`. Uncompiled works too, with the same
  catch: `ui` reuses any daemon that's already up, old assets and all — so
  `beagle stop` first, then `bun src/cli/main.ts ui` spawns one from your
  working tree. (On a watch-managed machine, `beagle stop` pauses always-on
  until your next `beagle watch` — re-run it when you're done.)
- **Need dashboard data without a real agent?** `bun scripts/seed-dev-store.ts`
  fills a scratch store (`/tmp/beagle-dev-store`) with synthetic sessions —
  including a masked leak, so the highlight/alert UI actually has something to
  render — then `BEAGLE_STATE_DIR=/tmp/beagle-dev-store bun src/cli/main.ts ui`.
  (`beagle run <agent>` gives you *real* capture, but it needs one of the four
  agents installed and signed in and makes a live provider call — a fresh
  session also has no leaks unless one is actually sent, so it's not a data
  generator. Never paste a real key to make one; the seed script or a
  fake-shaped string is the way.)
- **Never let a test touch the real service.** The launchd/systemd unit
  label (`com.boundedhq.beagle`) is per-user global — a test that calls the
  real `osServiceRunner` can unload the *developer's actual service* (this
  happened; it wasn't fun). Tests inject a fake: see `makeEnv()` in
  `tests/watch.test.ts` and the injectable `ServiceRunner`/`isActive`
  parameters. `cmdStatus`/`cmdStop` tests **must** stub `isActive` — CI
  runners have no `launchctl`/`systemctl`.
- **Never point an experiment at the real store.** Copy
  `~/.local/state/beagle` somewhere and set `BEAGLE_STATE_DIR` to the copy.
  Watch out for the inverse mistake too: running `watch` with a temp
  `BEAGLE_STATE_DIR` but your real `$HOME` once pinned a login service to a
  `/tmp` path — the code now guards against that combo, and the guard has a
  test; keep it that way.
- **The perf-budget test can flake on a loaded machine** (and occasionally
  on a noisy CI runner). If `tests/budget.test.ts` is the only failure,
  re-run before assuming your change caused a regression.

## Invariants that look like bugs but aren't

If your change "fixes" one of these, it's the change that's wrong. (The
R-numbers and §-references you'll see in source comments come from an
internal design doc; the header comment at each enforcement site is the
canonical public statement.)

- **Fail-open capture.** A capture or scan failure must never block, delay,
  or modify the agent's traffic — the gap is recorded
  (`captureState: "truncated"`) and surfaced as "⚠ capture truncated",
  never papered over, and never allowed to break the session.
- **Leak visibility (R7).** A detected secret is *always* visibly marked
  wherever its content is shown — folds force-open on a leak, and nothing
  that could hold the only visible copy of leaked content may be dropped or
  collapsed silently.
- **Record before mutating (§6.12).** Every persistent change `watch` makes
  lands in the change manifest *before* the mutation
  (`src/install/manifest.ts`), behind an itemized y/N prompt that lists
  every change before anything is written (the shell-rc PATH edit gets its
  own separate y/N), and must be mechanically revertible by
  `unwatch`/`uninstall`.
- **Credentials never rest.** Auth headers are stripped before capture is
  written. No code path may store, log, or display them.
- **Honesty over reassurance.** Status lines and badges only claim what was
  actually verified: `observed` vs `self-reported` provenance, "verified"
  only after a real re-probe, "scan incomplete" rather than a silent pass.
  When you add a message, make it earn its adjectives.

## Pull requests

- PRs target `main`. Commit messages follow `area: summary` (see `git log`
  — e.g. `watch: clearer coverage-fix flow`).
- No formatter is configured — match the surrounding style and don't
  reformat lines you aren't changing.
- For anything larger than a bug fix, an issue first saves everyone time
  (required for new runtime dependencies).
- Write tests first when you can; every behavior fix needs a test that
  fails without it.
- Keep PRs single-purpose. Mechanical renames, formatting-only, or
  vendored-file updates go in their own PRs.
- The precision gate (`tests/precision.test.ts`, <5% false positives) and
  the perf budgets (`tests/budget.test.ts`) are ship gates — a PR that
  trades them away needs a very good reason.
- Changes to `run`/`watch`/install paths deserve a live check against a
  real agent (your own machine is fine — use a scratch `BEAGLE_STATE_DIR`),
  and PR descriptions here typically say what was validated live.

## Adding support for a new agent

The most-wanted contribution. Start at `src/cli/agents.ts` — each agent is
a registry entry describing how to redirect it (base-URL env var, provider
override, config redirect, or extension flag) — plus detection in
`src/install/detect.ts`. The bar for merging: live-verify the login type
you actually have access to (your own machine is fine; say which in the
PR), and for the one you couldn't test, the detect/coverage output must
degrade honestly — say "untested" or "not covered" rather than guessing.
See README → Capture modes for the wire-vs-telemetry distinction; don't
claim telemetry capture unless the agent actually reports usage.

## Reporting bugs vs vulnerabilities

Ordinary bugs → GitHub issues, with `beagle status` output and repro steps.
Anything security-sensitive → see [SECURITY.md](SECURITY.md) (private
reporting); please don't open a public issue.
