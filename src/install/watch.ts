// watch/unwatch orchestration (design §6.7, §6.12, R2). Places a PATH shim
// after a diff-and-confirm, verifies coverage via the user's real shell, and
// records every mutation in the change manifest so revert is mechanical.
import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { AGENTS } from "../cli/agents";
import { ChangeManifest } from "./manifest";
import { isBeagleShim, shimScript, parseCoverageVerdict, type CoverageVerdict } from "./shim";
import {
  installService,
  removeService,
  servicePlan,
  osServiceRunner,
  type ServiceKind,
  type ServiceRunner,
} from "./service";

export interface WatchEnv {
  stateDir: string;
  shimDir: string; // a Beagle-owned dir placed early on PATH
  beagleBinary: string;
  /** Dev only: entry script the runtime must execute (bun + main.ts). */
  beagleScript?: string;
  shell: string; // $SHELL
  platform: NodeJS.Platform;
  home: string;
  resolveReal: (agent: string) => string | null; // where the real binary is
  runType: (agent: string) => string; // `$SHELL -ic 'type <agent>'` output
  confirm: (diff: string) => boolean; // interactive y/N (or --yes)
  serviceRunner?: ServiceRunner; // injectable for tests; defaults to the OS one
  /** Is this agent on a subscription login the proxy can't see? Drives the
   *  auto mode choice (codex: read from ~/.codex/auth.json; claude: not
   *  statically detectable → false). Optional so tests stay minimal. */
  detectSubscription?: (agent: string) => boolean;
}

export interface WatchResult {
  applied: boolean;
  message: string;
  verdict?: CoverageVerdict;
}

/** How a watched agent is captured. "auto" resolves per agent: telemetry when
 *  a subscription login is detected (wire mode would watch nothing there),
 *  else wire. */
export type WatchMode = "wire" | "telemetry";
export type WatchModeRequest = WatchMode | "auto";

function wireSupported(agent: string): boolean {
  const spec = AGENTS[agent];
  // The shim execs `beagle run <agent>`, so anything cmdRun can redirect is
  // shimmable: env-base-URL, config-driven, or extension-driven agents.
  return Boolean(spec && (spec.baseUrlEnv || spec.config || spec.extension));
}

function telemetrySupported(agent: string): boolean {
  return Boolean(AGENTS[agent]?.telemetry);
}

/** Resolve the requested mode against what the agent supports. Returns null
 *  with a reason when the combination is impossible. */
export function resolveWatchMode(
  agent: string,
  requested: WatchModeRequest,
  env: WatchEnv,
): { mode: WatchMode; why: string } | { error: string } {
  if (!AGENTS[agent]) return { error: `unknown agent '${agent}'` };
  if (requested === "telemetry") {
    if (!telemetrySupported(agent)) {
      return { error: `${agent} has no telemetry (agent self-report) mode — only claude and codex do.` };
    }
    return { mode: "telemetry", why: "requested with --telemetry" };
  }
  if (requested === "wire") {
    if (!wireSupported(agent)) {
      return { error: `${agent}'s wire-redirect mechanism isn't confirmed yet — automatic watch isn't supported for it in v1.` };
    }
    return { mode: "wire", why: "requested with --wire" };
  }
  // auto: a detected subscription login makes wire mode a shim that watches
  // nothing — telemetry is the only honest choice there.
  if (telemetrySupported(agent) && env.detectSubscription?.(agent)) {
    return { mode: "telemetry", why: "subscription login detected — the proxy can't see that traffic" };
  }
  if (wireSupported(agent)) return { mode: "wire", why: "default (wire capture, full fidelity)" };
  if (telemetrySupported(agent)) return { mode: "telemetry", why: "only supported mode for this agent" };
  return { error: `${agent}'s wire-redirect mechanism isn't confirmed yet — automatic watch isn't supported for it in v1.` };
}

export function planWatch(
  agent: string,
  env: WatchEnv,
  mode: WatchMode = "wire",
): { shimPath: string; real: string } | null {
  const spec = AGENTS[agent];
  if (!spec) return null;
  if (mode === "telemetry" ? !telemetrySupported(agent) : !wireSupported(agent)) return null;
  const real = env.resolveReal(agent);
  if (!real) return null;
  return { shimPath: join(env.shimDir, agent), real };
}

export function watchAgent(agent: string, env: WatchEnv, requested: WatchModeRequest = "auto"): WatchResult {
  const resolved = resolveWatchMode(agent, requested, env);
  if ("error" in resolved) {
    return { applied: false, message: resolved.error };
  }
  const { mode, why } = resolved;
  const plan = planWatch(agent, env, mode);
  if (!plan) {
    return { applied: false, message: `cannot watch ${agent}: not found or unsupported` };
  }
  // Defense in depth against a shim that execs itself (fork bomb): if the
  // "real" binary resolved into Beagle's own shim dir — possible when the shim
  // dir is on PATH and the resolver didn't exclude it — refuse loudly rather
  // than write a self-referential shim. Confirmed live before this guard.
  if (dirname(resolve(plan.real)) === resolve(env.shimDir) || isBeagleShim(plan.real)) {
    return {
      applied: false,
      message:
        `refusing to watch ${agent}: the resolved "real" binary (${plan.real}) is Beagle's own shim — ` +
        `a shim exec'ing itself would loop forever. Run 'beagle unwatch ${agent}' first, or check your PATH.`,
    };
  }
  // The always-on daemon service is installed once, on the first graduation.
  const svc = servicePlan(env.platform, env.home, env.beagleBinary, env.stateDir);
  const svcAlreadyInstalled = svc ? existsSync(svc.path) : true;
  const diffLines = [
    `Beagle will make ${svc && !svcAlreadyInstalled ? "these changes" : "one change"}:`,
    `  + create a PATH shim at ${plan.shimPath}`,
    mode === "telemetry"
      ? `    (runs the real ${agent} at ${plan.real} with its own telemetry reporting to Beagle — ${why})`
      : `    (execs the real ${agent} at ${plan.real} through Beagle)`,
  ];
  if (svc && !svcAlreadyInstalled) {
    diffLines.push(
      `  + install a background service (${svc.kind}) so watched agents stay covered across reboots`,
      `    at ${svc.path}`,
    );
  }
  if (mode === "wire" && telemetrySupported(agent)) {
    // The one honest caveat of wire mode for these agents: a subscription
    // login never crosses the proxy, so this shim would watch nothing for it.
    // Shown even for an explicit --wire — louder when we KNOW the login is a
    // subscription, because then this shim is a no-op by construction.
    diffLines.push(
      env.detectSubscription?.(agent)
        ? `  ▲ a subscription login was detected for ${agent} — this WIRE shim will capture NOTHING for it.\n` +
          `  Use 'beagle watch ${agent} --telemetry' unless you are switching to an API key.`
        : `  Note: if you sign in with a subscription (Claude.ai / ChatGPT) rather than an API key,\n` +
          `  the proxy can't see that traffic — use 'beagle watch ${agent} --telemetry' instead.`,
    );
  }
  diffLines.push(
    `  Your ${agent} config is NOT touched. Undo any time with 'beagle unwatch ${agent}'.`,
  );
  if (!env.confirm(diffLines.join("\n") + "\n")) {
    return { applied: false, message: "cancelled — nothing changed." };
  }

  mkdirSync(env.shimDir, { recursive: true, mode: 0o755 });
  const manifest = new ChangeManifest(env.stateDir);
  // Record BEFORE mutating (design §6.12). recordReplacing so re-watching (to
  // switch modes) updates the entry instead of stacking duplicates.
  manifest.recordReplacing({ kind: "shim", agent, path: plan.shimPath, backup: null, mode });
  writeFileSync(
    plan.shimPath,
    shimScript({
      agent,
      realBinary: plan.real,
      beagleBinary: env.beagleBinary,
      beagleScript: env.beagleScript,
      telemetry: mode === "telemetry",
    }),
    { mode: 0o755 },
  );

  // Install the always-on service on first graduation (§6.7). Recorded with a
  // null agent (it's shared, not per-agent) so it's removed only at uninstall
  // or when the last watched agent is unwatched.
  if (svc && !svcAlreadyInstalled) {
    manifest.record({ kind: "service", agent: null, path: svc.path, backup: svc.kind });
    installService(svc, env.serviceRunner ?? osServiceRunner);
  }

  // Verify coverage against the user's actual shell (the honesty clause).
  const verdict = parseCoverageVerdict(agent, plan.shimPath, env.runType(agent));
  const modeTag = mode === "telemetry" ? " (agent telemetry — subscription-safe)" : "";
  let msg: string;
  if (verdict.covered) {
    msg = `watching ${agent}${modeTag} — verified: ${verdict.reason}. New shells are covered; run 'rehash' or open a new terminal for existing ones.`;
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
  const runner = env.serviceRunner ?? osServiceRunner;
  let removed = false;
  manifest.removeFor(agent, (e) => {
    if (e.kind === "shim") {
      // The manifest entry — not the file — is the watch relationship: a
      // hand-deleted shim must still count as "unwatched" (rmSync tolerates
      // the missing file), or this would report "not being watched" while
      // quietly dropping the entry and tearing down the shared service.
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
  });

  // The daemon service is shared across watched agents; tear it down only when
  // the last one is unwatched (no shim/config-redirect entries remain).
  const remaining = manifest.list();
  const anyAgentLeft = remaining.some((e) => e.kind === "shim" || e.kind === "config-redirect");
  let serviceRemoved = false;
  if (!anyAgentLeft) {
    manifest.removeFor(null, (e) => {
      if (e.kind === "service") {
        removeService(e.path, (e.backup as ServiceKind) ?? "systemd", runner);
        serviceRemoved = true;
      }
    });
  }
  chmodSyncSafe(env.stateDir);
  if (!removed) return { applied: false, message: `${agent} was not being watched.` };
  return {
    applied: true,
    message:
      `unwatched ${agent} — shim removed, config restored.` +
      (serviceRemoved ? " Background service removed (no agents left watched)." : ""),
  };
}

function chmodSyncSafe(dir: string): void {
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* best effort */
  }
}
