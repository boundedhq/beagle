// Bind a server and resolve on 'listening' / reject on 'error'. A naked
// `server.listen(port, cb)` resolves only on success — an EADDRINUSE/EACCES
// surfaces as an unhandled 'error' event (which Node escalates to a process
// crash) while the caller awaits a promise that never settles. Shared by every
// listener Beagle opens: proxy, OTLP receiver, viewer, control socket.
import type { Server } from "node:net";

export function listenReady(server: Server, start: () => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error): void => {
      server.removeListener("listening", onListening);
      reject(err);
    };
    const onListening = (): void => {
      server.removeListener("error", onError); // don't linger past a clean bind
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    start();
  });
}
