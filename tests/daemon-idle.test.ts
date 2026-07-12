import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Daemon } from "../src/daemon/daemon";
import { openLease, controlRequest } from "../src/daemon/control";

function stateDir(): string {
  return mkdtempSync(join(tmpdir(), "beagle-idle-"));
}

describe("daemon idle-exit (design §6.7)", () => {
  const daemons: Daemon[] = [];
  afterEach(async () => {
    for (const d of daemons) await d.stop().catch(() => {});
    daemons.length = 0;
  });

  async function start(opts: Partial<Parameters<typeof Daemon.start>[0]> = {}) {
    const d = await Daemon.start({
      stateDir: stateDir(),
      idleTimeoutMs: 150,
      exitProcessOnIdle: false, // tests observe stop(), never kill the runner
      ...opts,
    });
    daemons.push(d);
    return d;
  }

  test("ephemeral daemon with no lease stops after the idle timeout", async () => {
    const d = await start();
    expect(d.isRunning).toBe(true);
    await Bun.sleep(400);
    expect(d.isRunning).toBe(false);
  });

  test("a held lease keeps the daemon alive past the timeout; release lets it exit", async () => {
    const d = await start();
    const lease = await openLease(d.socketPath);
    await Bun.sleep(400);
    expect(d.isRunning).toBe(true); // lease held it open
    lease.end();
    await Bun.sleep(400);
    expect(d.isRunning).toBe(false); // released → idle-exit
  });

  test("a killed lease connection still releases (crash-safe)", async () => {
    const d = await start();
    const lease = await openLease(d.socketPath);
    await Bun.sleep(200);
    expect(d.isRunning).toBe(true);
    lease.destroy(); // simulate `beagle run` being killed
    await Bun.sleep(400);
    expect(d.isRunning).toBe(false);
  });

  test("two leases: daemon stays until BOTH release", async () => {
    const d = await start();
    const a = await openLease(d.socketPath);
    const b = await openLease(d.socketPath);
    a.end();
    await Bun.sleep(300);
    expect(d.isRunning).toBe(true); // b still holding
    b.end();
    await Bun.sleep(400);
    expect(d.isRunning).toBe(false);
  });

  test("persistent (service) daemon never idle-exits", async () => {
    const d = await start({ persistent: true });
    await Bun.sleep(500);
    expect(d.isRunning).toBe(true);
    // still serves control
    const r = await controlRequest(d.socketPath, { cmd: "ping" });
    expect(r.ok).toBe(true);
  });
});
