// Service unit install (design §6.7, §6.12): at `beagle watch` graduation, a
// user-level service (launchd agent / systemd user unit) keeps the daemon
// running so watched coverage survives reboot. Installed only inside the
// diff-and-confirm, recorded in the change manifest, removed on unwatch.
// Non-core: OS-service glue.
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const SERVICE_LABEL = "com.boundedhq.beagle";

export interface ServiceInputs {
  beagleBinary: string;
  stateDir: string;
}

export type ServiceKind = "launchd" | "systemd";

export interface ServicePlan {
  kind: ServiceKind;
  path: string;
  content: string;
}

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function launchdPlist(i: ServiceInputs): string {
  const bin = xmlEscape(i.beagleBinary);
  const state = xmlEscape(i.stateDir);
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SERVICE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${bin}</string>
    <string>daemon</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>BEAGLE_STATE_DIR</key>
    <string>${state}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
`;
}

export function systemdUnit(i: ServiceInputs): string {
  // systemd splits ExecStart on unquoted whitespace and treats an unquoted
  // Environment value the same way, so a path with a space would break both.
  // Quote defensively: the binary path on its own, and the whole KEY=value for
  // Environment (systemd honors double quotes with backslash escapes).
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `[Unit]
Description=Beagle — local transparency proxy for AI agents
After=network.target

[Service]
Type=simple
ExecStart="${esc(i.beagleBinary)}" daemon
Environment="BEAGLE_STATE_DIR=${esc(i.stateDir)}"
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
`;
}

export function servicePlan(
  platform: NodeJS.Platform,
  home: string,
  beagleBinary: string,
  stateDir: string,
): ServicePlan | null {
  const inputs = { beagleBinary, stateDir };
  if (platform === "darwin") {
    return {
      kind: "launchd",
      path: join(home, "Library", "LaunchAgents", `${SERVICE_LABEL}.plist`),
      content: launchdPlist(inputs),
    };
  }
  if (platform === "linux") {
    return {
      kind: "systemd",
      path: join(home, ".config", "systemd", "user", "beagle.service"),
      content: systemdUnit(inputs),
    };
  }
  return null; // Windows is post-v1
}

// The OS activation step, injectable so the write path is testable without
// touching launchctl/systemctl.
export interface ServiceRunner {
  activate(plan: ServicePlan): void;
  deactivate(plan: { kind: ServiceKind; path: string }): void;
  /** Is the unit currently loaded/enabled? Optional — a runner without it
   *  (older tests) reads as "active", so nothing re-activates spuriously. */
  isActive?(plan: { kind: ServiceKind; path: string }): boolean;
}

export const osServiceRunner: ServiceRunner = {
  activate(plan) {
    if (plan.kind === "launchd") {
      spawnQuiet(["launchctl", "load", "-w", plan.path]);
    } else {
      spawnQuiet(["systemctl", "--user", "enable", "--now", "beagle.service"]);
    }
  },
  deactivate(plan) {
    if (plan.kind === "launchd") {
      spawnQuiet(["launchctl", "unload", "-w", plan.path]);
    } else {
      spawnQuiet(["systemctl", "--user", "disable", "--now", "beagle.service"]);
    }
  },
  isActive(plan) {
    if (plan.kind === "launchd") {
      const uid = typeof process.getuid === "function" ? process.getuid() : 501;
      return spawnOk(["launchctl", "print", `gui/${uid}/${SERVICE_LABEL}`]);
    }
    return spawnOk(["systemctl", "--user", "is-active", "--quiet", "beagle.service"]);
  },
};

function spawnQuiet(argv: string[]): void {
  try {
    Bun.spawnSync(argv, { stdio: ["ignore", "ignore", "ignore"] });
  } catch {
    /* best effort — the file is written regardless; user can activate manually */
  }
}

function spawnOk(argv: string[]): boolean {
  try {
    return Bun.spawnSync(argv, { stdio: ["ignore", "ignore", "ignore"] }).exitCode === 0;
  } catch {
    return false;
  }
}

/** Which state dir does an installed unit point its daemon at? Parses both
 *  formats WE generate; anything unrecognizable → null (a hand-edited unit is
 *  the user's — repair must not clobber what it can't read). */
export function serviceStateDir(content: string): string | null {
  const plist = content.match(
    /<key>BEAGLE_STATE_DIR<\/key>\s*<string>([^<]*)<\/string>/,
  );
  if (plist) {
    return plist[1]!
      .replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  }
  const unit = content.match(/Environment="BEAGLE_STATE_DIR=((?:[^"\\]|\\.)*)"/);
  if (unit) return unit[1]!.replace(/\\(["\\])/g, "$1");
  return null;
}

/** Write + activate the unit. Returns false if it was already installed. */
export function installService(plan: ServicePlan, runner: ServiceRunner): boolean {
  if (existsSync(plan.path)) return false;
  mkdirSync(dirname(plan.path), { recursive: true });
  writeFileSync(plan.path, plan.content, { mode: 0o644 });
  chmodSync(plan.path, 0o644);
  runner.activate(plan);
  return true;
}

/** Overwrite + re-activate an EXISTING unit (repair path: the installed one
 *  points its daemon at the wrong state dir). Deactivate first so launchd/
 *  systemd re-read the corrected file rather than keeping the old process. */
export function reinstallService(plan: ServicePlan, runner: ServiceRunner): void {
  runner.deactivate(plan);
  mkdirSync(dirname(plan.path), { recursive: true });
  writeFileSync(plan.path, plan.content, { mode: 0o644 });
  chmodSync(plan.path, 0o644);
  runner.activate(plan);
}

export function removeService(path: string, kind: ServiceKind, runner: ServiceRunner): void {
  runner.deactivate({ kind, path });
  rmSync(path, { force: true });
}
