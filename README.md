# 🐕 Beagle

[![CI](https://github.com/boundedhq/beagle/actions/workflows/ci.yml/badge.svg)](https://github.com/boundedhq/beagle/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**See exactly what your AI agents send to remote models — with leaked secrets
flagged the moment they leave your machine.**

AI agents read your files, your shell output, your git history — and ship
chunks of all of it to a model provider on every turn. Today that traffic is
invisible: you can't see what left, you can't search it, and if an agent
sent your AWS key along for the ride, nobody tells you. Beagle is a local
transparency proxy that makes that traffic visible, searchable, and scanned
for secrets — in one command, without changing your setup.

![The Beagle dashboard: a live feed of every model call, with a leaked AWS key highlighted inline](docs/assets/dashboard.png)

## Quick start

```sh
brew install boundedhq/tap/beagle    # or see Install below
beagle run claude                    # wraps the `claude` CLI in your terminal — that's it
```

`beagle run` wraps a single agent session and changes nothing on your system.
While it runs, every model call is captured locally; if a secret goes out,
you get an OS notification the moment it happens. Afterwards:

```sh
$ beagle leaks                     # did anything leak? every call was already scanned
1 leak event:
  2026-07-12T14:22:15.000Z  aws-access-key-id → anthropic  ×3  first: 01KXAK6K

$ beagle ui                        # or browse it — leaks are highlighted inline
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
  redirect (the env var or per-run config), its traffic simply doesn't
  route through Beagle — it can't silently observe anything else.
- **Not a cloud service.** No account, no server, no telemetry, no
  phone-home. The only outbound connections are the ones your agent was
  already making, forwarded verbatim.
- **Not a blocker.** v1 observes and alerts; it never rewrites, drops, or
  delays anything. What reaches the provider is byte-for-byte what your
  agent sent. (There's an optional setting to censor detected secrets in
  *Beagle's own local records* so they aren't stored on your disk — but
  that only changes what Beagle keeps, never what goes over the wire.)

## Supported agents

v1 wraps **terminal CLI agents** — `beagle run` launches the agent's CLI
under the proxy, and `beagle watch` shims its PATH entry:

| Agent | How Beagle sees the traffic | Capture |
|---|---|---|
| Claude Code CLI (API key) | runs under the local proxy (via `ANTHROPIC_BASE_URL`) | ✓ wire (full fidelity) |
| Claude Code CLI (Claude.ai subscription) | Claude Code's own usage telemetry, received locally — see below | *agent-reported* (Mode B) |
| Codex CLI (API key) | runs under the local proxy (via `OPENAI_BASE_URL`) | ✓ wire (full fidelity) |
| opencode | runs under the local proxy (via a temporary Beagle-written config) | ✓ wire (full fidelity) |
| pi | runs under the local proxy (via a one-run Beagle extension, `pi -e`) | ✓ wire (full fidelity) |

**How the wrapping works.** Claude Code and Codex honor a standard
environment variable that changes where they send their API traffic;
`beagle run` sets it to the local proxy for that run and nothing else.
opencode doesn't read such a variable — its endpoint lives in a config
file — so for the duration of the run Beagle hands it a **temporary config
file of its own** (your real settings merged in, plus the proxy address).
pi has the cleanest knob of all: its `-e` flag loads an extension for one
run, so Beagle passes a **generated three-line extension** that re-points
pi's provider at the proxy — no config or auth files are even read. In
every case your real config files are never modified, and the generated
file is deleted when the run ends.

**Subscription logins are different.** A Claude.ai (Pro/Max) login only
works over Anthropic's own client-server connection, so Beagle stays off
that wire entirely. Instead, `beagle run claude --telemetry` switches on
Claude Code's **built-in usage reporting** (its vendor-shipped OpenTelemetry
export) and receives those reports on a local port. That means you see what
Claude Code *says* it sent rather than the bytes themselves — which is why
those rows are badged **agent** (*agent-reported*) in the dashboard instead
of **✓ wire**. This is **validated against Claude Code 2.1.193**: it
captures your prompts, the assistant's responses, tool inputs, **and tool
outputs** — so a secret that appears only in a file the agent reads (the
most common accidental leak) is caught too. Claude Code's telemetry omits
tool-result content, so Beagle also registers a `PostToolUse` hook (via the
vendor's own `--settings`, merged with your hooks, never replacing them)
that forwards each tool result to the local receiver for scanning. It's
still a self-report, so it differs from wire capture in a few honest ways:
reports are batched (alerts lag seconds, not wire-instant), the tool-output
hook is best-effort (a dropped report is a miss, never a block), and it
relies on Claude Code's hook system (which `--bare` turns off). Details and
the reproduction: [Phase-0 spike results](docs/mode-b-spike.md). Codex on a "Sign in with
ChatGPT" login is designed to work as a pure passthrough (Beagle forwards
the client's own login unchanged and never injects anything), but that path
is **still pending validation** — until then, API-key mode is the supported
way to watch Codex.

Desktop apps, IDE extensions, and web UIs launch their own processes and
don't inherit either mechanism, so their traffic is **not** captured in v1 —
`beagle status` always tells you exactly what is and isn't covered.

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
beagle leaks               # the leak log — every detected secret, deduped, automatic
beagle search [string]     # was this exact string ever sent? for things the detector
                           # can't know (an internal password, a hostname). With no
                           # argument it reads stdin, keeping the term out of history
beagle show <id>           # one call, summarized or raw
beagle ui                  # open the dashboard (loopback, one-time token)
beagle purge [all|panic]   # erase captured data (panic = secure wipe + vacuum)
beagle config redact-on-capture on   # censor detected secrets in Beagle's local
                                     # store (never changes what's on the wire)
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

**Does it cover the Claude Code desktop app, IDE extensions, or web UIs?**
Not in v1. Beagle wraps processes launched from your terminal — `beagle
run` spawns the CLI under the proxy, and `beagle watch` shims the CLI's
PATH entry. GUI apps launch their own processes and inherit neither, so
their traffic isn't captured. `beagle status` reports coverage honestly
rather than implying more than it sees.

**How do I find out whether a secret leaked?**
You don't have to go looking — every outbound call is scanned
automatically, and anything detected is in `beagle leaks` and highlighted
inline in the dashboard. Don't feed real keys into commands to check.
`beagle search` is for strings the detector *can't* know about (an internal
password, a customer hostname); if you ever do search for something
sensitive, run `beagle search` with no argument and it reads the term from
stdin, keeping it out of argv and shell history. The search runs locally
against your local store.

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
