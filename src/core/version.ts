// The single source of truth for the beagle version. Lives in core so the
// daemon can report it in its ping handshake without importing from the CLI
// layer; `src/cli/main.ts` re-exports it as VERSION for the existing surface.
export const BEAGLE_VERSION = "0.1.0";
