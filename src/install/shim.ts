// PATH shim (design §6.7, R2): a `<agent>` earlier on PATH that redirects
// then execs the real binary. Uninstall = removing one symlink; the user's
// real config is untouched.
export interface ShimSpec {
  agent: string;
  realBinary: string;
  beagleBinary: string;
}

function shQuote(s: string): string {
  // POSIX-safe single-quote wrapping.
  return `"${s.replace(/(["\\$`])/g, "\\$1")}"`;
}

export function shimScript(spec: ShimSpec): string {
  const beagle = shQuote(spec.beagleBinary);
  const real = shQuote(spec.realBinary);
  return `#!/bin/sh
# Beagle PATH shim for ${spec.agent} — created by 'beagle watch'.
# Redirects this agent's model traffic through Beagle, then execs the real
# binary. Remove with 'beagle unwatch ${spec.agent}'. Your config is untouched.
exec ${beagle} run ${spec.agent} --real ${real} -- "$@"
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
  if (out.includes("alias")) {
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
