// PATH shim (design §6.7, R2): a `<agent>` earlier on PATH that redirects
// then execs the real binary. Uninstall = removing one symlink; the user's
// real config is untouched. A `telemetry` shim runs the agent in Mode B
// (`beagle run <agent> --telemetry`) — for subscription logins whose traffic
// the proxy can't see; a wire shim there would watch nothing.
import { openSync, readSync, closeSync } from "node:fs";

export interface ShimSpec {
  agent: string;
  realBinary: string;
  /** The beagle executable (compiled binary, or the runtime in dev). */
  beagleBinary: string;
  /** Dev only: the entry script `beagleBinary` must run (bun + main.ts). */
  beagleScript?: string;
  telemetry?: boolean;
  /** Pin wire mode in the shim (user passed an explicit --wire to watch) so
   *  run-time login detection can't override their stated choice. Auto-chosen
   *  wire stays unpinned — if the login later changes to a subscription,
   *  detection self-heals the capture instead of silently losing it. */
  pinWire?: boolean;
}

// Every generated shim carries this marker so Beagle can recognize its OWN
// shims BY CONTENT — path comparisons miss symlinked dirs and shims left by a
// different state dir, and mistaking a shim for the real binary writes a shim
// that exec's itself (fork bomb, reproduced live).
export const SHIM_MARKER = "# Beagle PATH shim";

/** Is this file a Beagle-generated shim? Reads at most 4KB; any error → false
 *  (a real binary must never be misclassified as a shim). */
export function isBeagleShim(path: string): boolean {
  try {
    const fd = openSync(path, "r");
    try {
      const buf = Buffer.alloc(4096);
      const n = readSync(fd, buf, 0, buf.length, 0);
      return buf.toString("utf8", 0, n).includes(SHIM_MARKER);
    } finally {
      closeSync(fd);
    }
  } catch {
    return false;
  }
}

function shQuote(s: string): string {
  // Wrap in double quotes and backslash-escape the four characters the shell
  // still interprets inside them (", \, $, `). Handles spaces and metachars.
  return `"${s.replace(/(["\\$`])/g, "\\$1")}"`;
}

export function shimScript(spec: ShimSpec): string {
  // Dev (bun + entry script) needs both parts on the exec line; compiled is
  // just the binary. Without this, a dev-installed shim exec'd a bare runtime
  // with no script — every watched invocation would fail.
  const beagle = shQuote(spec.beagleBinary) + (spec.beagleScript ? ` ${shQuote(spec.beagleScript)}` : "");
  const real = shQuote(spec.realBinary);
  const mode = spec.telemetry ? " --telemetry" : spec.pinWire ? " --wire" : "";
  const how = spec.telemetry
    ? "# Watches via the agent's own telemetry (Mode B — subscription login),"
    : "# Redirects this agent's model traffic through Beagle,";
  return `#!/bin/sh
${SHIM_MARKER} for ${spec.agent} — created by 'beagle watch'.
${how} then execs the real
# binary. Remove with 'beagle unwatch ${spec.agent}'. Your config is untouched.
exec ${beagle} run ${spec.agent}${mode} --real ${real} -- "$@"
`;
}

export interface CoverageVerdict {
  covered: boolean;
  reason: string;
}

// Parses `$SHELL -ic 'type <agent>'` output to confirm resolution lands on the
// shim, else name the exact bypass (design §6.7, the shim honesty clause).
export function parseCoverageVerdict(
  agent: string,
  shimPath: string,
  typeOutput: string,
): CoverageVerdict {
  const out = typeOutput.trim();
  // Match how shells announce an alias ("is an alias for", "is aliased to"),
  // not any path that merely contains the substring "alias".
  if (/\bis (an alias|aliased)\b/i.test(out)) {
    return {
      covered: false,
      reason: `an alias bypasses the shim (${out}) — remove it or the alias will keep going direct`,
    };
  }
  // `<agent> is <path>` — the resolved path
  const m = out.match(/is\s+(\/\S+)/);
  const resolved = m?.[1];
  if (resolved && resolved === shimPath) {
    return { covered: true, reason: `resolves to the shim at ${shimPath}` };
  }
  if (resolved) {
    return {
      covered: false,
      reason: `resolves to ${resolved}, which bypasses the shim at ${shimPath}`,
    };
  }
  return { covered: false, reason: `could not resolve ${agent} from your shell: ${out}` };
}
