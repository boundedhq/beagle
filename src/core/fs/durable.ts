// Durable state-file IO: Beagle's own trust-bearing files (config.json,
// changes.json) must fail EXPLICITLY on corruption — never silently revert to
// defaults — and must never be left half-written. Two stdlib-only primitives
// shared by the core config path and the non-core install manifest.
import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

/** Result of reading a JSON state file WITHOUT ever touching disk: `missing` and
 *  `corrupt` are values, not exceptions, so a read-only caller (`beagle status`)
 *  can surface corruption without repairing it — repairing would make the trust
 *  strip's "beagle has modified nothing" a lie by the mere act of checking. */
export type JsonLoad = { status: "ok"; value: unknown } | { status: "missing" } | { status: "corrupt" };

export function loadJsonFile(path: string): JsonLoad {
  if (!existsSync(path)) return { status: "missing" };
  try {
    return { status: "ok", value: JSON.parse(readFileSync(path, "utf8")) };
  } catch {
    return { status: "corrupt" };
  }
}

/** Write atomically: a temp file in the SAME directory (so rename stays on one
 *  filesystem) → fsync the bytes → rename over the target → re-assert `mode`
 *  (openSync's mode is masked by umask). A crash or full disk mid-write leaves
 *  either the intact old file or the intact new one — never a truncated file
 *  that would silently load as defaults next time. writeFileSync (NOT writeSync)
 *  loops until every byte lands, so a short write on a near-full disk can't
 *  truncate the temp; and the temp is unlinked, not orphaned, if any step
 *  throws. The temp name carries the pid so two writers never share a scratch. */
export function writeFileAtomic(path: string, data: string | Uint8Array, mode = 0o600): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.tmp`);
  try {
    const fd = openSync(tmp, "w", mode);
    try {
      writeFileSync(fd, data); // fd form writes all bytes and does not close the fd
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
  chmodSync(path, mode);
}
