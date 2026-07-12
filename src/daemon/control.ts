// Control socket (design §6.7): unix domain socket, 0600, line-delimited
// JSON. Live actions only — reads go straight to SQLite.
import { createServer, connect, type Server, type Socket } from "node:net";
import { chmodSync, rmSync } from "node:fs";

export interface ControlRequest {
  cmd: string;
  args?: Record<string, unknown>;
}

export interface ControlResponse {
  ok: boolean;
  data?: unknown;
  error?: string;
}

// The socket is passed so a handler can hold the connection open (a `lease`
// keeps the daemon alive for the caller's lifetime — §6.7 idle-exit).
export type ControlHandler = (
  req: ControlRequest,
  socket: Socket,
) => Promise<ControlResponse> | ControlResponse;

export function startControlServer(socketPath: string, handler: ControlHandler): Promise<Server> {
  rmSync(socketPath, { force: true });
  const server = createServer((sock) => {
    let buf = "";
    sock.on("data", async (d) => {
      buf += d.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        let resp: ControlResponse;
        try {
          resp = await handler(JSON.parse(line) as ControlRequest, sock);
        } catch (e) {
          resp = { ok: false, error: (e as Error).message };
        }
        if (!sock.destroyed) sock.write(JSON.stringify(resp) + "\n");
      }
    });
    sock.on("error", () => {});
  });
  return new Promise((resolve) => {
    server.listen(socketPath, () => {
      chmodSync(socketPath, 0o600);
      resolve(server);
    });
  });
}

// Open a lease: the daemon counts this connection as a live run and won't
// idle-exit while it's held. The returned socket must be kept open for the
// caller's lifetime; closing it (or crashing) releases the lease.
export function openLease(socketPath: string, timeoutMs = 3000): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const sock = connect(socketPath, () => sock.write(JSON.stringify({ cmd: "lease" }) + "\n"));
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("lease timeout"));
    }, timeoutMs);
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      if (buf.indexOf("\n") === -1) return;
      clearTimeout(timer);
      // keep the socket OPEN — it is the lease
      resolve(sock);
    });
    sock.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

export function controlRequest(
  socketPath: string,
  req: ControlRequest,
  timeoutMs = 3000,
): Promise<ControlResponse> {
  return new Promise((resolve, reject) => {
    const sock = connect(socketPath, () => sock.write(JSON.stringify(req) + "\n"));
    let buf = "";
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("control socket timeout"));
    }, timeoutMs);
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl === -1) return;
      clearTimeout(timer);
      sock.end();
      try {
        resolve(JSON.parse(buf.slice(0, nl)) as ControlResponse);
      } catch (e) {
        reject(e as Error);
      }
    });
    sock.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}
