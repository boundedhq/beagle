# 🐕 Beagle

[![CI](https://github.com/boundedhq/beagle/actions/workflows/ci.yml/badge.svg)](https://github.com/boundedhq/beagle/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**See exactly what your AI agents send to remote models — with leaked secrets
flagged the moment they leave your machine.**

AI coding agents read your files, your shell output, your git history — and
ship chunks of all of it to a model provider on every turn. Today that
traffic is invisible: you can't see what left, you can't search it, and if an
agent sent your AWS key along for the ride, nobody tells you. Beagle is a
local transparency proxy that makes that traffic visible, searchable, and
scanned for secrets — in one command, without changing your setup.

![The Beagle dashboard: a live feed of every model call, with a leaked AWS key highlighted inline](docs/assets/dashboard.png)

## Quick start

```sh
brew install boundedhq/tap/beagle    # or see Install below
beagle run claude                    # run your agent under beagle — that's it
```

`beagle run` wraps a single agent session and changes nothing on your system.
While it runs, every model call is captured locally; if a secret goes out,
you get an OS notification the moment it happens. Afterwards:

```sh
$ beagle search sk-live-abc123     # "was this key ever sent?"
found in 1 call across 1 session:
  01KXAK6K  2026-07-12T14:23:00Z  session a1b2c3d4

$ beagle ui                        # or browse it in the dashboard
dashboard: http://127.0.0.1:52341/?boot=…
(the link is one-time; run `beagle ui` again for a fresh one)
```

## How it works (and what it is *not*)

`beagle run claude` starts a loopback proxy and points the agent at it using
the provider's own base-URL environment variable (`ANTHROPIC_BASE_URL`,
`OPENAI_BASE_URL`, …). The agent talks to `127.0.0.1`; Beagle streams the
bytes to the real provider unmodified and keeps a copy locally:

```
agent ──HTTP──▶ beagle (127.0.0.1) ──HTTPS──▶ api.anthropic.com
                   │
                   ├─ scan outbound body for secrets → alert
                   └─ store request/response locally (SQLite, 0600)
```

Just as important, what Beagle is **not**:

- **Not a TLS man-in-the-middle.** No CA certificate is installed, no TLS is
  intercepted, no system proxy is configured. If an app doesn't honor the
  base-URL variable, its traffic simply doesn't route through Beagle — it
  can't silently observe anything else.
- **Not a cloud service.** No account, no server, no telemetry, no
  phone-home. The only outbound connections are the ones your agent was
  already making, forwarded verbatim.
- **Not a blocker.** v1 observes and alerts; it never rewrites or drops
  what the agent sends upstream (the optional `redact-on-capture` scrubs
  secrets from *the local copy*, not from the wire).

## Supported agents

| Agent | How it's wrapped | Capture |
|---|---|---|
| Claude Code (API key) | `ANTHROPIC_BASE_URL` | ✓ wire (full fidelity) |
| Codex CLI | `OPENAI_BASE_URL` | ✓ wire (full fidelity) |
| opencode | Beagle-owned config redirect, reverted after the run | ✓ wire (full fidelity) |
| pi | Beagle-owned config redirect, reverted after the run | ✓ wire (full fidelity) |
| Claude Code (Claude.ai subscription) | `beagle run claude --telemetry` — Claude Code's own OpenTelemetry export posts to Beagle's loopback receiver; nothing sits on the wire | *agent-reported* (Mode B) |

Every row in the dashboard is labeled **✓ wire** (observed on the wire) or
**agent** (the agent's own self-report), so you always know which kind of
evidence you're looking at. Mode B is implemented and unit-tested but **not
yet validated against a real Claude Code build** — treat it as best-effort
until the [Phase-0 spike checklist](docs/mode-b-spike.md) is complete.

## Install

Requirements: **none** — Beagle ships as a single self-contained binary
(macOS and Linux, x64 and arm64; Windows is post-v1).

```sh
# Homebrew (primary)
brew install boundedhq/tap/beagle

# or the one-line script (downloads from GitHub Releases, verifies the
# sha256 checksum before installing, never runs post-install code)
curl -fsSL https://raw.githubusercontent.com/boundedhq/beagle/main/packaging/install.sh | sh

# or build from source (requires Bun ≥ 1.3)
git clone https://github.com/boundedhq/beagle && cd beagle
bun install && bun run build     # → dist/beagle
```

Then `beagle detect` finds the supported agents on your machine and tells
you the next command.

## Use

```sh
beagle run <agent>         # watch one agent run; nothing changed on your system
beagle watch <agent>       # opt in to always-on (one PATH shim; revert any time)
beagle unwatch <agent>     # stop watching, restore your setup
beagle status              # trust strip: coverage, store size, retention, what changed
beagle search <string>     # "was this password ever sent?" — a definitive answer
beagle leaks               # the leak log
beagle show <id>           # one call, summarized or raw
beagle ui                  # open the dashboard (loopback, one-time token)
beagle purge [all|panic]   # erase captured data (panic = secure wipe + vacuum)
beagle config redact-on-capture on   # drop raw secret values at capture time
```

The whole loop works headless — a skeptic never has to start the viewer.

## What it does

- **Faithful reverse proxy.** Streams raw bytes through unbuffered (SSE
  reaches the agent immediately); parses only a copy for display. Any
  provider format flows correctly on day one; Anthropic Messages / OpenAI
  Responses / OpenAI Chat Completions get the polished readable view.
- **High-precision secret detection** on outbound bodies — a homegrown
  matcher over the vendored gitleaks ruleset (data, not code). Structured
  detectors (AWS/GitHub/Stripe/private keys, Luhn-checked cards) drive the
  loud alert; generic/entropy matches stay a quiet "possible" tier.
- **Real-time, deduped alerts.** One notification per distinct leaked
  secret, even as the agent re-sends history every turn — dashboard open
  or not.
- **A readable record.** Streamed responses are reassembled into readable
  text, each call gets a "what this turn did" summary, and detected secrets
  are highlighted inline where they appeared.

## Budgets (published, enforced in CI)

Trust needs numbers, not adjectives. These are the ship gates:

| Budget | Target | Enforcement |
|---|---|---|
| Core security path | ≤ 1,500 LOC | `bun run loc:check` — fails the build over budget |
| Detection false-positive rate | < 5% | `tests/precision.test.ts` — the ship gate |
| Scan time, 1 MB body | p99 ~10 ms | `tests/budget.test.ts` |
| Added request latency | p50 ≤ 5 ms | `tests/budget.test.ts` (warm baseline) |
| Install size | ≤ 100 MB | CI binary-size check |

**Current core count: 1,487 / 1,500 LOC.** Zero third-party runtime
dependencies in the core; `bun:*` imports confined to `src/adapters/`; the
viewer's Preact+htm is vendored, pinned, and buildless. The core data path
(intercept → forward → capture → detect) is small enough to audit in one
sitting: start at [`src/core/`](src/core/).

## Trust properties

- **Local only.** No network calls except forwarding to your model
  provider. No telemetry, no phone-home, no accounts, no server.
- **Your setup, untouched.** `beagle run` mutates nothing. `beagle watch`
  adds one PATH shim after showing you the diff, records it in a change
  manifest, and reverts cleanly on `unwatch`/uninstall.
- **Your API key never rests.** Auth headers are scrubbed before anything
  is written; the credential exists only in memory, in flight.
- **The store is the liability, minimized.** `0600` files in
  `~/.local/state/beagle`, 7-day rolling payload window, opt-in
  `redact-on-capture`, one-command panic purge with secure delete.
- **Auditable.** Found a hole? See [SECURITY.md](SECURITY.md) for private
  reporting.

## Uninstall

Beagle must leave no trace — that's part of the trust contract:

```sh
beagle unwatch <agent>         # remove that agent's PATH shim (if you used watch)
beagle purge all               # erase all captured data
rm -rf ~/.local/state/beagle   # remove the store directory
brew uninstall beagle          # or: rm /usr/local/bin/beagle
```

Everything Beagle ever changed on your system is listed by `beagle status`
while it's installed.

## FAQ

**Does my API key pass through Beagle?**
In flight, yes (that's what a proxy is); at rest, never. Auth headers are
stripped before capture and are not stored, logged, or displayed.

**What exactly is stored, and where?**
Request/response bodies, headers (minus credentials), timing and token
counts — in a SQLite file under `~/.local/state/beagle`, mode `0600`,
payloads pruned on a 7-day rolling window. `beagle purge` erases it on
demand.

**Can it see traffic from apps I didn't run under it?**
No. Coverage is opt-in per agent (`run` for one session, `watch` for
always-on). There is no system proxy, no packet capture, no TLS
interception.

**Why should I trust the detector?**
It's the gitleaks ruleset (vendored as data, sha256-pinned) run through a
matcher of about 140 lines you can read in one sitting
([`src/core/scanner/`](src/core/scanner/)), with a published <5%
false-positive gate in CI. Detection tiers are honest: structured hits
alert loudly; entropy-only hits stay a quiet "possible."

**What happens if Beagle crashes mid-run?**
The proxy fails open for observation, never blocking your agent: if
capture fails, your agent's traffic still flows; the gap is recorded as
`capture truncated` rather than silently papered over.

## Layout

- `src/core/` — the audited security path (LOC-budgeted, stdlib-only, no `bun:*`)
- `src/adapters/` — the only home for Bun-specific surface (`bun:sqlite`, workers)
- `src/parsers/`, `src/viewer/`, `src/cli/`, `src/daemon/`, `src/install/` — non-core, in the same LOC report
- `rules/` — vendored, pinned detection rules (data; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md))

## Development

```sh
bun install
bun run check          # lint + LOC budget + typecheck + tests
bun run build          # dist/beagle single binary
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Beagle is a product of
[Bounded](https://github.com/boundedhq), MIT-licensed.
