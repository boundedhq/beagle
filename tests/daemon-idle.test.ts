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

    const d = await start({ idleTimeoutMs: 250 });
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

    // traffic every ~120ms for ~700ms, well past the 250ms idle window
    for (let i = 0; i < 6; i++) {
      await fire();
      await Bun.sleep(120);
    }
    expect(d.isRunning).toBe(true); // traffic held it open without any lease

    // traffic stops → winds down within a couple idle windows
    await Bun.sleep(700);
    expect(d.isRunning).toBe(false);
    upstream.close();
  });
});
