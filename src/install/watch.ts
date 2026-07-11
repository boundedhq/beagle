// watch/unwatch orchestration (design §6.7, §6.12, R2). Places a PATH shim
// after a diff-and-confirm, verifies coverage via the user's real shell, and
// records every mutation in the change manifest so revert is mechanical.
import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AGENTS } from "../cli/agents";
import { ChangeManifest } from "./manifest";
import { shimScript, parseCoverageVerdict, type CoverageVerdict } from "./shim";

export interface WatchEnv {
  stateDir: string;
  shimDir: string; // a Beagle-owned dir placed early on PATH
  beagleBinary: string;
  shell: string; // $SHELL
  resolveReal: (agent: string) => string | null; // where the real binary is
  runType: (agent: string) => string; // `$SHELL -ic 'type <agent>'` output
  confirm: (diff: string) => boolean; // interactive y/N (or --yes)
}

export interface WatchResult {
  applied: boolean;
  message: string;
  verdict?: CoverageVerdict;
}

export function planWatch(agent: string, env: WatchEnv): { shimPath: string; real: string } | null {
  const spec = AGENTS[agent];
  if (!spec) return null;
  // v1 shims work only for env-base-URL agents; a shim for a config-driven
  // agent (opencode/pi) would exec `beagle run <agent>`, which run rejects —
  // don't place a shim that can't work. Config-redirect support lands later.
  if (!spec.baseUrlEnv) return null;
  const real = env.resolveReal(agent);
  if (!real) return null;
  return { shimPath: join(env.shimDir, agent), real };
}

export function watchAgent(agent: string, env: WatchEnv): WatchResult {
  const spec = AGENTS[agent];
  if (spec && !spec.baseUrlEnv) {
    return {
      applied: false,
      message: `${agent} is config-driven; automatic watch for it isn't supported yet (env-base-URL agents only in v1).`,
    };
  }
  const plan = planWatch(agent, env);
  if (!plan) {
    return { applied: false, message: `cannot watch ${agent}: not found or unsupported` };
  }
  const diff =
    `Beagle will make one change:\n` +
    `  + create a PATH shim at ${plan.shimPath}\n` +
    `    (execs the real ${agent} at ${plan.real} through Beagle)\n` +
    `  Your ${agent} config is NOT touched. Undo any time with 'beagle unwatch ${agent}'.\n`;
  if (!env.confirm(diff)) {
    return { applied: false, message: "cancelled — nothing changed." };
  }

  mkdirSync(env.shimDir, { recursive: true, mode: 0o755 });
  const manifest = new ChangeManifest(env.stateDir);
  // Record BEFORE mutating (design §6.12).
  manifest.record({ kind: "shim", agent, path: plan.shimPath, backup: null });
  writeFileSync(plan.shimPath, shimScript({ agent, realBinary: plan.real, beagleBinary: env.beagleBinary }), {
    mode: 0o755,
  });

  // Verify coverage against the user's actual shell (the honesty clause).
  const verdict = parseCoverageVerdict(agent, plan.shimPath, env.runType(agent));
  let msg: string;
  if (verdict.covered) {
    msg = `watching ${agent} — verified: ${verdict.reason}. New shells are covered; run 'rehash' or open a new terminal for existing ones.`;
  } else {
    // Never report a failure without the fix (R2: name the exact cause AND
    // how to close it) — the usual cause is the shim dir not being on PATH.
    msg =
      `shim placed, but coverage is NOT yet active: ${verdict.reason}\n` +
      `To fix, add Beagle's shim directory to the FRONT of your PATH — put this line in your shell rc (~/.zshrc or ~/.bashrc):\n` +
      `  export PATH="${env.shimDir}:$PATH"\n` +
      `then open a new terminal and run 'beagle status' to re-verify.`;
  }
  return { applied: true, message: msg, verdict };
}

export function unwatchAgent(agent: string, env: WatchEnv): WatchResult {
  const manifest = new ChangeManifest(env.stateDir);
  let removed = false;
  manifest.removeFor(agent, (e) => {
    if (e.kind === "shim" && existsSync(e.path)) {
      rmSync(e.path, { force: true });
      removed = true;
    }
    if ((e.kind === "config-backup" || e.kind === "config-redirect") && e.backup && existsSync(e.backup)) {
      // Copy the backed-up original back into place (a symlink into the state
      // dir would break the moment the store is purged).
      rmSync(e.path, { force: true });
      copyFileSync(e.backup, e.path);
      removed = true;
    }
    if (e.kind === "service" && existsSync(e.path)) {
      rmSync(e.path, { force: true });
      removed = true;
    }
  });
  chmodSyncSafe(env.stateDir);
  return {
    applied: removed,
    message: removed ? `unwatched ${agent} — shim removed, config restored.` : `${agent} was not being watched.`,
  };
}

function chmodSyncSafe(dir: string): void {
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* best effort */
  }
}
