import { describe, expect, test } from "bun:test";
import { createServer } from "node:net";
import { listenReady } from "../src/core/net/listen";

describe("listenReady", () => {
  test("resolves once the server is listening", async () => {
    const server = createServer();
    try {
      await listenReady(server, () => server.listen(0, "127.0.0.1"));
      expect(server.listening).toBe(true);
    } finally {
      server.close();
    }
  });

  test("REJECTS on a bind error instead of hanging forever", async () => {
    // Occupy an ephemeral port, then try to bind a second server to it.
    const blocker = createServer();
    await listenReady(blocker, () => blocker.listen(0, "127.0.0.1"));
    const port = (blocker.address() as { port: number }).port;
    const clash = createServer();
    try {
      const outcome = await Promise.race([
        listenReady(clash, () => clash.listen(port, "127.0.0.1")).then(() => "resolved"),
        new Promise((r) => setTimeout(() => r("HUNG"), 1500)),
      ]).catch((e: NodeJS.ErrnoException) => `rejected:${e.code}`);
      expect(outcome).toBe("rejected:EADDRINUSE"); // not "HUNG", not "resolved"
    } finally {
      clash.close();
      blocker.close();
    }
  });

  test("removes its error handler after a clean bind (no lingering listeners)", async () => {
    const server = createServer();
    try {
      await listenReady(server, () => server.listen(0, "127.0.0.1"));
      expect(server.listenerCount("error")).toBe(0);
      expect(server.listenerCount("listening")).toBe(0);
    } finally {
      server.close();
    }
  });
});
