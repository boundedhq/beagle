// Corrupt-DB quarantine (design §6.6, §8 failure table): a corrupt store must
// never block the agent. Move the bad file into quarantine/ (0600, swept +
// panic-purged), then a fresh DB opens. Quarantined data is liability too, so
// it's disclosed and aged out, not silently dropped.
import { existsSync, mkdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { ulid } from "./ulid";

const DB_SIDECARS = ["beagle.db", "beagle.db-wal", "beagle.db-shm"];

export function quarantineCorruptDb(stateDir: string): boolean {
  const dbPath = join(stateDir, "beagle.db");
  if (!existsSync(dbPath)) return false;
  const qdir = join(stateDir, "quarantine");
  mkdirSync(qdir, { recursive: true, mode: 0o700 });
  const stamp = ulid();
  let moved = false;
  for (const name of DB_SIDECARS) {
    const src = join(stateDir, name);
    if (existsSync(src)) {
      renameSync(src, join(qdir, `${stamp}-${name}`));
      moved = true;
    }
  }
  return moved;
}
