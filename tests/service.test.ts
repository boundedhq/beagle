import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, existsSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  launchdPlist,
  systemdUnit,
  servicePlan,
  installService,
  removeService,
  SERVICE_LABEL,
} from "../src/install/service";

function tmp() {
  return mkdtempSync(join(tmpdir(), "beagle-svc-"));
}

describe("service unit generation", () => {
  test("launchd plist runs `beagle daemon`, RunAtLoad + KeepAlive, loopback-safe", () => {
    const plist = launchdPlist({ beagleBinary: "/usr/local/bin/beagle", stateDir: "/home/u/.state/beagle" });
    expect(plist).toContain(`<string>${SERVICE_LABEL}</string>`);
    expect(plist).toContain("<string>/usr/local/bin/beagle</string>");
    expect(plist).toContain("<string>daemon</string>");
    expect(plist).toContain("<key>RunAtLoad</key>");
    expect(plist).toContain("<key>KeepAlive</key>");
    // state dir passed via env so the service targets the same store
    expect(plist).toContain("BEAGLE_STATE_DIR");
    expect(plist).toContain("/home/u/.state/beagle");
  });

  test("launchd plist escapes XML metacharacters in paths", () => {
    const plist = launchdPlist({ beagleBinary: "/opt/A&B/beagle", stateDir: "/x" });
    expect(plist).toContain("/opt/A&amp;B/beagle");
    expect(plist).not.toContain("/opt/A&B/beagle");
  });

  test("systemd unit runs the daemon with Restart=always and user WantedBy", () => {
    const unit = systemdUnit({ beagleBinary: "/usr/local/bin/beagle", stateDir: "/home/u/.state/beagle" });
    expect(unit).toContain("ExecStart=/usr/local/bin/beagle daemon");
    expect(unit).toContain("Restart=always");
    expect(unit).toContain("Environment=BEAGLE_STATE_DIR=/home/u/.state/beagle");
    expect(unit).toContain("[Install]");
    expect(unit).toContain("WantedBy=default.target");
  });
});

describe("servicePlan (per-platform paths)", () => {
  test("macOS → LaunchAgents plist", () => {
    const p = servicePlan("darwin", "/Users/u", "/bin/beagle", "/Users/u/.state/beagle")!;
    expect(p.path).toBe(`/Users/u/Library/LaunchAgents/${SERVICE_LABEL}.plist`);
    expect(p.kind).toBe("launchd");
    expect(p.content).toContain("RunAtLoad");
  });

  test("Linux → systemd user unit under XDG config", () => {
    const p = servicePlan("linux", "/home/u", "/bin/beagle", "/home/u/.state/beagle")!;
    expect(p.path).toBe("/home/u/.config/systemd/user/beagle.service");
    expect(p.kind).toBe("systemd");
    expect(p.content).toContain("ExecStart");
  });

  test("unsupported platform returns null (windows post-v1)", () => {
    expect(servicePlan("win32", "C:/Users/u", "beagle.exe", "C:/state")).toBeNull();
  });
});

describe("install/remove service", () => {
  let dir: string;
  const activated: string[] = [];
  const deactivated: string[] = [];
  const runner = {
    activate: (plan: { kind: string; path: string }) => { activated.push(`${plan.kind}:${plan.path}`); },
    deactivate: (plan: { kind: string; path: string }) => { deactivated.push(`${plan.kind}:${plan.path}`); },
  };

  beforeEach(() => {
    dir = tmp();
    activated.length = 0;
    deactivated.length = 0;
  });

  test("installs the unit file (0644), activates it, is idempotent", () => {
    const plan = servicePlan("linux", dir, "/bin/beagle", join(dir, "state"))!;
    const first = installService(plan, runner);
    expect(first).toBe(true);
    expect(existsSync(plan.path)).toBe(true);
    expect(statSync(plan.path).mode & 0o777).toBe(0o644);
    expect(activated).toEqual([`systemd:${plan.path}`]);

    // second call is a no-op (already installed)
    const second = installService(plan, runner);
    expect(second).toBe(false);
    expect(activated.length).toBe(1);
  });

  test("removeService deactivates and deletes the file", () => {
    const plan = servicePlan("linux", dir, "/bin/beagle", join(dir, "state"))!;
    installService(plan, runner);
    removeService(plan.path, plan.kind, runner);
    expect(existsSync(plan.path)).toBe(false);
    expect(deactivated).toEqual([`systemd:${plan.path}`]);
  });

  test("removeService on a missing file still deactivates, never throws", () => {
    expect(() => removeService(join(dir, "nope.service"), "systemd", runner)).not.toThrow();
  });
});
