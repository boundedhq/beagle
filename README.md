# Beagle

Run one command and see exactly what your AI agents send to remote models —
with leaked secrets flagged the moment they leave your machine.

Beagle is a product of [Bounded](https://github.com/boundedhq). Local-only, no
telemetry, MIT-licensed, and small enough to read: the entire security path
(intercept → forward → capture → detect) is budgeted at ≤ 1,500 lines of
stdlib-only TypeScript, and CI publishes the count.

## Install

```sh
# Homebrew (primary)
brew install boundedhq/tap/beagle

# or the one-line script (verifies checksum, no post-install code fetch)
curl -fsSL https://raw.githubusercontent.com/boundedhq/beagle/main/packaging/install.sh | sh
```

macOS and Linux at launch (Windows is post-v1).

## Use

```sh
beagle run claude          # watch one agent run, nothing changed on your system
beagle watch claude        # opt in to always-on (a PATH shim; revert any time)
beagle status              # trust strip: coverage, store size, retention, what changed
beagle search <string>     # "was this password ever sent?" — a definitive answer
beagle leaks               # the leak log
beagle show <id>           # one exchange, summarized or raw
beagle ui                  # open the dashboard (loopback, one-time token)
beagle purge [all|panic]   # erase captured data
beagle config redact-on-capture on   # drop raw secret values at capture time
```

The whole loop works headless — a skeptic never has to start the viewer.

## What it does

- **Faithful reverse proxy.** Streams raw bytes through unbuffered (SSE reaches
  the agent immediately); parses only a copy for display. Any provider format
  flows correctly on day one; Anthropic Messages / OpenAI Responses / OpenAI
  Chat Completions get the polished readable view.
- **High-precision secret detection** on outbound bodies — a homegrown matcher
  over the vendored gitleaks ruleset (data, not code). Structured detectors
  (AWS/GitHub/Stripe/private keys, Luhn-checked cards) drive the loud alert;
  generic/entropy matches stay a quiet "possible" tier.
- **Real-time, deduped alerts.** One notification per distinct leaked secret,
  even as the agent re-sends history every turn — dashboard open or not.
- **Subscription-safe (Mode B).** For Claude Code on a Claude.ai login, nothing
  goes on the wire: capture arrives via Claude Code's own OpenTelemetry export,
  labeled *agent-reported*.

## Budgets (published, enforced in CI)

| Budget | Target (R9/R5) | Enforcement |
|---|---|---|
| Core security path | ≤ 1,500 LOC | `bun run loc:check` — fails the build over budget |
| Detection false-positive rate | < 5% | `tests/precision.test.ts` — the ship gate |
| Scan time, 1 MB body | p99 ~10 ms | `tests/budget.test.ts` |
| Added request latency | p50 ≤ 5 ms | `tests/budget.test.ts` (warm baseline) |
| Install size | ≤ 100 MB | CI binary-size check |

**Current core count: 1,485 / 1,500 LOC.** Zero third-party runtime
dependencies in the core; `bun:*` imports confined to `src/adapters/`; the
viewer's Preact+htm is vendored, pinned, and buildless.

## Trust properties

- **Local only.** No network calls except forwarding to your model provider.
  No telemetry, no phone-home, no accounts, no server.
- **Your setup, untouched.** `beagle run` mutates nothing. `beagle watch` adds
  one PATH shim after showing a diff, records it in a change manifest, and
  reverts cleanly on `unwatch`/uninstall.
- **The store is the liability, minimized.** `0600` files, 7-day rolling
  payload window, opt-in `redact-on-capture`, one-click panic purge with
  secure delete.
- **Auditable.** The core data path traces agent → provider → disk in one
  sitting. See `src/core/`.

## Layout

- `src/core/` — the audited security path (LOC-budgeted, stdlib-only, no `bun:*`)
- `src/adapters/` — the only home for Bun-specific surface (`bun:sqlite`, workers)
- `src/parsers/`, `src/viewer/`, `src/cli/`, `src/daemon/`, `src/install/` — non-core, in the same LOC report
- `rules/` — vendored, pinned detection rules (data)

## Development

```sh
bun install
bun run check          # lint + LOC budget + typecheck + tests
bun run build          # dist/beagle single binary
bun scripts/build-release.ts   # per-platform release binaries
```
