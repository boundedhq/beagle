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

  test("active proxy traffic blocks idle-exit even with NO lease (lost-lease backstop)", async () => {
    const { createServer, connect } = await import("node:net");
    const upstream = createServer((sock) => {
      sock.on("data", () => sock.write("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}"));
      sock.on("error", () => {});
    });
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
    const upPort = (upstream.address() as { port: number }).port;

    // Wide margin (100ms fire interval vs 500ms idle window, 5x) so a slow
    // shared CI runner stalling between fires doesn't idle the daemon out —
    // that would be a runner hiccup, not the lost-lease backstop failing.
    const d = await start({ idleTimeoutMs: 500 });
    await controlRequest(d.socketPath, {
      cmd: "register-run",
      args: { id: "busy", agent: "a", provider: "anthropic", upstream: `http://127.0.0.1:${upPort}` },
    });

    const fire = () =>
      new Promise<void>((resolve) => {
        const s = connect(d.proxyPort, "127.0.0.1", () =>
          s.write("POST /run/busy/v1/messages HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}"),
        );
        s.on("data", () => s.end());
        s.on("close", () => resolve());
        s.on("error", () => resolve());
      });

    // traffic every ~100ms for ~1.2s, well past the 500ms idle window
    for (let i = 0; i < 12; i++) {
      await fire();
      await Bun.sleep(100);
    }
    expect(d.isRunning).toBe(true); // traffic held it open without any lease

    // traffic stops → winds down; poll instead of a fixed sleep so a slow
    // runner gets up to 4s without the fast path waiting longer than needed
    for (let i = 0; i < 40 && d.isRunning; i++) await Bun.sleep(100);
    expect(d.isRunning).toBe(false);
    upstream.close();
  }, 15_000); // fires (~1.5s) + wind-down poll (≤4s) can brush bun's 5s default on a slow runner
});
