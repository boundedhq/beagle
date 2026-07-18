// watch/unwatch orchestration (design §6.7, §6.12, R2). Places a PATH shim
// after a diff-and-confirm, verifies coverage via the user's real shell, and
// records every mutation in the change manifest so revert is mechanical.
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { AGENTS } from "../cli/agents";
import { ChangeManifest } from "./manifest";
import { isBeagleShim, shimScript, parseCoverageVerdict, type CoverageVerdict } from "./shim";
import { installPathBlock, rcTargetFor, removePathBlock } from "./shellrc";
import {
  installService,
  reinstallService,
  removeService,
  servicePlan,
  serviceStateDir,
  osServiceRunner,
  type ServiceKind,
  type ServiceRunner,
} from "./service";

// A path that lives in a throwaway location. A REAL home plus a tmp state dir
// is the poison combo: it would pin the user's login service to a directory
// that evaporates — which is exactly what a Jul-13 acceptance-test run did
// live (launchd agent left pointing at /tmp/beagle-lease.*).
function isTmpPath(p: string): boolean {
  const r = resolve(p);
  return (
    r.startsWith("/tmp/") ||
    r.startsWith("/private/tmp/") ||
    r.startsWith("/private/var/folders/") ||
    r.startsWith("/var/folders/") ||
    r.startsWith(resolve(tmpdir()) + "/")
  );
}

export interface WatchEnv {
  stateDir: string;
  shimDir: string; // a Beagle-owned dir placed early on PATH
  beagleBinary: string;
  /** Dev only: entry script the runtime must execute (bun + main.ts). */
  beagleScript?: string;
  shell: string; // $SHELL
  platform: NodeJS.Platform;
  home: string;
  /** zsh's rc dir override, when set — .zshrc lives there, not in $HOME. */
  zdotdir?: string;
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
  /** unwatch only: the shared background service was torn down too (this was
   *  the last watched agent) — the caller may also stop a running daemon. */
  serviceRemoved?: boolean;
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
  return Boolean(spec && (spec.baseUrlEnv || spec.config || spec.extension || spec.wireArgs));
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
  // The always-on daemon service is installed once, on the first graduation —
  // and VERIFIED on every later watch: an installed unit whose baked state dir
  // doesn't match this one is keeping a daemon alive for the wrong store (the
  // exact failure a stale test unit caused live) and gets repaired. A unit we
  // can't parse was hand-edited — the user's; left alone. The poison-combo
  // guard skips service install entirely when a REAL home would be pointed at
  // a throwaway state dir.
  let svc = servicePlan(env.platform, env.home, env.beagleBinary, env.stateDir);
  const svcSkippedTmp = Boolean(svc && isTmpPath(env.stateDir) && !isTmpPath(env.home));
  if (svcSkippedTmp) svc = null;
  const runner = env.serviceRunner ?? osServiceRunner;
  const svcOnDisk = svc && existsSync(svc.path) ? readFileSync(svc.path, "utf8") : null;
  const svcInstall = Boolean(svc && svcOnDisk === null);
  const svcBakedState = svcOnDisk !== null ? serviceStateDir(svcOnDisk) : null;
  const svcRepair = Boolean(svc && svcBakedState !== null && resolve(svcBakedState) !== resolve(env.stateDir));
  // Paused (e.g. by `beagle stop`) but otherwise healthy: watch re-enables
  // always-on — the stop message promises exactly this.
  const svcReenable = Boolean(
    svc && !svcInstall && !svcRepair && runner.isActive && !runner.isActive(svc),
  );
  const svcChanges = svcInstall || svcRepair || svcReenable;
  const diffLines = [
    `Beagle will make ${svcChanges ? "these changes" : "one change"}:`,
    `  + create a PATH shim at ${plan.shimPath}`,
    mode === "telemetry"
      ? `    (runs the real ${agent} at ${plan.real} with its own telemetry reporting to Beagle — ${why})`
      : `    (execs the real ${agent} at ${plan.real} through Beagle)`,
  ];
  if (svc && svcInstall) {
    diffLines.push(
      `  + install a background service (${svc.kind}) so watched agents stay covered across reboots`,
      `    at ${svc.path}`,
    );
  }
  if (svc && svcRepair) {
    diffLines.push(
      `  + repair the background service at ${svc.path}`,
      `    (it keeps a daemon alive for ${svcBakedState} — a stale/test path; it will point at ${env.stateDir})`,
    );
  }
  if (svc && svcReenable) {
    diffLines.push(
      `  + re-enable the background service (currently paused — e.g. by 'beagle stop')`,
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

  // 0700, and tighten the state-dir root too: `beagle watch` can be the first
  // command to create ~/.local/state/beagle (before the daemon's Store.open
  // sets 0700), and every other creator uses 0700. A 0755 root/shim dir would
  // let other local users traverse it and read the shims.
  mkdirSync(env.shimDir, { recursive: true, mode: 0o700 });
  chmodSyncSafe(env.stateDir);
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
      pinWire: mode === "wire" && requested === "wire",
    }),
    { mode: 0o755 },
  );

  // Install the always-on service on first graduation (§6.7), or repair a
  // stale one. Recorded with a null agent (it's shared, not per-agent) so
  // it's removed only at uninstall or when the last watched agent is
  // unwatched. recordReplacing on repair: the entry may already exist.
  if (svc && svcInstall) {
    manifest.record({ kind: "service", agent: null, path: svc.path, backup: svc.kind });
    installService(svc, runner);
  } else if (svc && svcRepair) {
    manifest.recordReplacing({ kind: "service", agent: null, path: svc.path, backup: svc.kind });
    reinstallService(svc, runner);
  } else if (svc && svcReenable) {
    manifest.recordReplacing({ kind: "service", agent: null, path: svc.path, backup: svc.kind });
    runner.activate(svc);
  } else if (svc && !manifest.list().some((e) => e.kind === "service")) {
    // A healthy unit on disk that the manifest doesn't know about — orphaned
    // by an older CLI's history. Adopt it (bookkeeping only, no OS action) so
    // unwatch/uninstall can revert it and `stop` can pause it via the entry.
    manifest.recordReplacing({ kind: "service", agent: null, path: svc.path, backup: svc.kind });
  }

  // Verify coverage against the user's actual shell (the honesty clause).
  const verdict = parseCoverageVerdict(agent, plan.shimPath, env.runType(agent));
  const modeTag = mode === "telemetry" ? " (agent telemetry — subscription-safe)" : "";
  let msg: string;
  if (verdict.covered) {
    msg = `watching ${agent}${modeTag} — verified: ${verdict.reason}. New shells are covered; run 'rehash' or open a new terminal for existing ones.`;
  } else {
    // Never report a failure without the fix (R2) — and when the fix is a
    // PATH-order problem, OFFER to apply it rather than dictating homework:
    // one marker-guarded block in the shell rc, recorded in the manifest,
    // removed by unwatch-of-last-agent/uninstall. An alias bypass is the one
    // cause a PATH edit can't fix, so it keeps the manual explanation. An
    // unknown shell (or a declined offer / malformed prior block) falls back
    // to the printed instructions.
    const aliasCase = verdict.reason.startsWith("an alias bypasses");
    const rc = aliasCase
      ? null
      : rcTargetFor(env.shell, env.home, env.platform, env.shimDir, env.zdotdir);
    const manual =
      `To fix, add Beagle's shim directory to the FRONT of your PATH — put this line in your shell rc (~/.zshrc or ~/.bashrc):\n` +
      `  export PATH="${env.shimDir}:$PATH"\n` +
      `then open a new terminal and run 'beagle status' to re-verify.`;
    msg = `shim placed, but coverage is NOT yet active: ${verdict.reason}\n${manual}`;
    if (
      rc &&
      env.confirm(
        `Coverage isn't active yet: ${verdict.reason}\n` +
          `Beagle can fix this by adding one guarded block to ${rc.path}:\n` +
          `  ${rc.line}\n` +
          `(removed automatically by 'beagle unwatch' / 'beagle uninstall')`,
      )
    ) {
      // Record BEFORE mutating (§6.12). agent null: one PATH block serves
      // every shim, so it lives and dies with the LAST watched agent.
      manifest.recordReplacing({ kind: "shellrc", agent: null, path: rc.path, backup: null });
      const r = installPathBlock(rc.path, rc.line);
      msg = r.ok
        ? `shim placed. PATH updated in ${rc.path} — a guarded block Beagle owns and removes on unwatch/uninstall.\n` +
          `This terminal predates the change: open a new one (or run 'source ${rc.path}'), then 'beagle status' to re-verify.`
        : `shim placed, but ${rc.path} has a malformed beagle block (a begin marker with no end) — not touching it.\n` +
          `Remove the stray '# >>> beagle shims >>>' line, or apply the fix by hand:\n${manual}`;
    }
  }
  if (svcSkippedTmp) {
    msg +=
      `\nNote: background service NOT installed — the state dir (${env.stateDir}) is a temporary path ` +
      `(test context); a login service must never be pointed at one.`;
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

  // The daemon service and the shell-rc PATH block are shared across watched
  // agents; tear them down only when the last one is unwatched (no
  // shim/config-redirect entries remain). The rc edit removes exactly the
  // marker-guarded block Beagle added — the user's file is otherwise theirs.
  const remaining = manifest.list();
  const anyAgentLeft = remaining.some((e) => e.kind === "shim" || e.kind === "config-redirect");
  let serviceRemoved = false;
  let rcCleaned: string | null = null;
  if (!anyAgentLeft) {
    manifest.removeFor(null, (e) => {
      if (e.kind === "service") {
        removeService(e.path, (e.backup as ServiceKind) ?? "systemd", runner);
        serviceRemoved = true;
      }
      if (e.kind === "shellrc" && removePathBlock(e.path)) {
        rcCleaned = e.path;
      }
    });
  }
  chmodSyncSafe(env.stateDir);
  if (!removed) return { applied: false, message: `${agent} was not being watched.` };
  return {
    applied: true,
    serviceRemoved,
    message:
      `unwatched ${agent} — shim removed, config restored.` +
      (serviceRemoved ? " Background service removed (no agents left watched)." : "") +
      (rcCleaned ? ` PATH block removed from ${rcCleaned}.` : ""),
  };
}

function chmodSyncSafe(dir: string): void {
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* best effort */
  }
}
