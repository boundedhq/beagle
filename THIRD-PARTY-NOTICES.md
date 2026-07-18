# Third-party notices

Beagle's core has zero third-party runtime dependencies. The third-party
material it does ship is listed here in full.

## Detection rules (data)

- **gitleaks ruleset** — MIT, Copyright (c) 2019 Zachary Rice.
  The rule corpus in `rules/beagle-rules.json` is derived from the
  [gitleaks](https://github.com/gitleaks/gitleaks) ruleset, vendored as data
  (no gitleaks code is included) and pinned by sha256 at build time. Full
  license text: [`rules/GITLEAKS-LICENSE`](rules/GITLEAKS-LICENSE).

## Test fixtures (data)

- **leakproof adversarial corpus** — Apache-2.0, Copyright hamstudios.
  The scanner regression corpus in `tests/fixtures/leakproof-corpus.json` is
  adapted from [leakproof](https://github.com/acunningham-ship-it/leakproof)'s
  `tests/adversarial/corpus.py` (test data only; no leakproof code is
  included). Every credential in it is synthetic — right format, not a real
  secret. License text: <https://www.apache.org/licenses/LICENSE-2.0>.

## Viewer (vendored, pinned)

- **Preact** — MIT, Copyright (c) 2015-present Jason Miller
  (`src/viewer/static/vendor/preact*.module.js`, v10.24.3).
- **htm** — Apache-2.0, Copyright 2018 Google Inc.
  (`src/viewer/static/vendor/htm.module.js`, v3.1.1).

Both are vendored buildless and pinned via `package.json` devDependencies;
what ships is what's in the repo.

## Policy

No AGPL-licensed material (e.g. TruffleHog rules) is included, by policy.
