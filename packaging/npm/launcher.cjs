#!/usr/bin/env node
// Beagle npm launcher. The `@boundedhq/beagle` package ships no binary itself;
// the real per-platform executable rides an optionalDependency
// (`@boundedhq/beagle-<os>-<cpu>`) that npm installs only when its `os`/`cpu`
// match. This shim resolves that package and execs its binary, forwarding argv,
// stdio, and the exit status/signal. No network, no post-install code.
"use strict";
const { spawnSync } = require("node:child_process");
const { existsSync } = require("node:fs");
const { join, dirname } = require("node:path");

const cpu = process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : process.arch;
const pkg = `@boundedhq/beagle-${process.platform}-${cpu}`;

let bin = null;
try {
  // Resolve via the platform package's own package.json (always resolvable,
  // unlike a subpath that an `exports` map could block), then join the binary.
  bin = join(dirname(require.resolve(`${pkg}/package.json`)), "beagle");
} catch {
  /* optional dep absent (unsupported platform, or --no-optional install) */
}

if (!bin || !existsSync(bin)) {
  process.stderr.write(
    `beagle: no prebuilt binary for ${process.platform}-${cpu}.\n` +
      `  Supported: darwin-arm64, darwin-x64, linux-x64, linux-arm64.\n` +
      `  If your platform IS supported, reinstall without disabling optional ` +
      `dependencies:\n    npm install -g @boundedhq/beagle\n`,
  );
  process.exit(1);
}

const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (r.error) {
  process.stderr.write(`beagle: failed to run ${bin}: ${r.error.message}\n`);
  process.exit(1);
}
// Re-raise a terminating signal so callers see the real cause (e.g. Ctrl-C);
// otherwise propagate the child's exit code.
if (r.signal) process.kill(process.pid, r.signal);
else process.exit(r.status == null ? 1 : r.status);
