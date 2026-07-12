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
  // Paths in Exec/Environment aren't shell-quoted by systemd; agents install
  // to plain paths, so this is fine for the common case.
  return `[Unit]
Description=Beagle — local transparency proxy for AI agents
After=network.target

[Service]
Type=simple
ExecStart=${i.beagleBinary} daemon
Environment=BEAGLE_STATE_DIR=${i.stateDir}
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
};

function spawnQuiet(argv: string[]): void {
  try {
    Bun.spawnSync(argv, { stdio: ["ignore", "ignore", "ignore"] });
  } catch {
    /* best effort — the file is written regardless; user can activate manually */
  }
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

export function removeService(path: string, kind: ServiceKind, runner: ServiceRunner): void {
  runner.deactivate({ kind, path });
  rmSync(path, { force: true });
}
