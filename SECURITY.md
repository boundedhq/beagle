# Security policy

Beagle's whole job is handling sensitive traffic, so security reports get
priority over everything else.

## Reporting a vulnerability

Please **do not open a public issue** for anything security-sensitive.
Instead, use GitHub's private vulnerability reporting: go to the repo's
**Security** tab → **Report a vulnerability**. You'll get an acknowledgment
within 72 hours and a fix or a plan within 14 days for anything that affects
the security path.

## What counts (this tool's threat model)

Especially interested in reports where:

- captured data (bodies, headers) can leave the machine, or be read by
  another local user (file permissions, viewer auth, control socket);
- the auth-header scrub can be bypassed so a provider credential reaches
  disk;
- `redact-on-capture` (on by default) can be bypassed, so a detected secret
  is written to the store unmasked;
- the viewer can be reached or read cross-origin, or the one-time bootstrap
  token / session credential can be replayed;
- the Mode-B telemetry receiver (a loopback listener used for subscription
  capture) can be reached from off-machine, or made to write forged or
  malformed self-reports into the store;
- the proxy can be made to alter, drop, or misroute agent traffic;
- the secret scanner can be trivially and systematically evaded (single-rule
  false negatives are ordinary bugs — file those publicly);
- `beagle watch`'s shim or the install/uninstall manifest can be abused to
  persist changes the user didn't approve.

## Scope notes

- Beagle runs with the user's own privileges on the user's own machine.
  Reports that require an attacker to already have arbitrary code execution
  as that user are generally out of scope.
- The store is local by design; "an attacker with root can read the SQLite
  file" is expected behavior, not a finding.

## Supply chain

Release binaries are built in CI from the tagged commit, published with
sha256 checksums, and the installer verifies the checksum before installing.
Nothing is fetched or executed post-install. The detection ruleset is
vendored as data and compiled into the binary; its sha256 pin is verified
when the rules load. On a mismatch the scanner refuses the tampered rules
and every scan reports `incomplete` rather than a false "clean" — capture
and forwarding continue, because Beagle never blocks your agent's traffic.
Signing (cosign/minisign) is on the roadmap — the published checksums are
the integrity check today.
