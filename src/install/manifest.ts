// Change manifest (design §6.12): every persistent mutation recorded at apply
// time, before the mutation. The trust strip reads it; unwatch and uninstall
// revert from it. Without this, "what did Beagle touch" is guesswork.
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { loadJsonFile, writeFileAtomic } from "../core/fs/durable";
import { ulid } from "../core/store/ulid";

export interface ChangeEntry {
  kind: "shim" | "config-backup" | "config-redirect" | "service" | "shellrc";
  agent: string | null;
  path: string; // the file created/edited
  backup: string | null; // where the original was backed up, if any
  /** How a shim watches: wire (proxy) or telemetry (Mode B). Absent on
   *  pre-telemetry entries → wire. */
  mode?: "wire" | "telemetry";
  ts?: number;
}

export class ChangeManifest {
  private path: string;
  private entries: ChangeEntry[];
  /** True when changes.json existed but was unreadable at load time. The trust
   *  strip reads this to warn "cannot account for what beagle changed" instead
   *  of the reassuring (and now false) "modified nothing". */
  corrupt = false;

  constructor(private stateDir: string) {
    this.path = join(stateDir, "changes.json");
    this.entries = this.load();
  }

  record(entry: ChangeEntry): void {
    this.entries.push({ ...entry, ts: entry.ts ?? Date.now() });
    this.persist();
  }

  /** Record, replacing any existing entry for the same (kind, agent, path) —
   *  re-watching an agent (e.g. to switch wire↔telemetry) updates the one
   *  entry instead of stacking duplicates that would misreport in `status`. */
  recordReplacing(entry: ChangeEntry): void {
    this.entries = this.entries.filter(
      (e) => !(e.kind === entry.kind && e.agent === entry.agent && e.path === entry.path),
    );
    this.record(entry);
  }

  list(): ChangeEntry[] {
    return [...this.entries];
  }

  /** Revert every mutation in reverse order; the caller performs the undo. */
  revert(undo: (e: ChangeEntry) => void): void {
    for (let i = this.entries.length - 1; i >= 0; i--) {
      undo(this.entries[i]!);
    }
    this.entries = [];
    this.persist();
  }

  removeFor(agent: string | null, undo: (e: ChangeEntry) => void): void {
    const keep: ChangeEntry[] = [];
    for (let i = this.entries.length - 1; i >= 0; i--) {
      const e = this.entries[i]!;
      if (e.agent === agent) undo(e);
      else keep.unshift(e);
    }
    this.entries = keep;
    this.persist();
  }

  summary(): string {
    if (this.entries.length === 0) return "0";
    const labels = [
      ...new Set(
        this.entries
          .filter((e) => e.agent)
          .map((e) => (e.mode === "telemetry" ? `${e.agent} (telemetry)` : e.agent!)),
      ),
    ];
    return `${this.entries.length} (${labels.join(", ")})`;
  }

  private load(): ChangeEntry[] {
    const r = loadJsonFile(this.path);
    if (r.status === "ok" && Array.isArray(r.value)) return r.value as ChangeEntry[];
    if (r.status === "missing") return [];
    // Corrupt (unparseable) or parsed-but-not-an-array: do NOT silently become
    // [] — this file is the record of everything Beagle changed on the system,
    // and losing it means uninstall/unwatch can no longer reverse those changes
    // while `status` would still claim "modified nothing". Flag it so status
    // warns and persist() preserves the bad file instead of overwriting it.
    this.corrupt = true;
    return [];
  }

  private persist(): void {
    // Only mutating callers reach here (record/revert/removeFor) — `beagle
    // status` never persists, so the read-only trust surface still writes
    // nothing. If the ledger we loaded was corrupt, preserve a COPY in
    // quarantine/ (same layout as quarantineCorruptDb: 0700 dir, `<ulid>-<name>`)
    // before the overwrite, so the record stays recoverable. We copy rather than
    // move so changes.json is never momentarily absent: a crash before the atomic
    // rewrite below leaves the corrupt file in place, re-detected as corrupt next
    // load instead of read as an empty "modified nothing". `beagle status` also
    // surfaces the quarantined copy, so the corruption stays visible even after
    // a command that reverts nothing rewrites a fresh empty ledger here.
    if (this.corrupt) {
      if (existsSync(this.path)) {
        const qdir = join(this.stateDir, "quarantine");
        mkdirSync(qdir, { recursive: true, mode: 0o700 });
        copyFileSync(this.path, join(qdir, `${ulid()}-changes.json`));
      }
      this.corrupt = false;
    }
    // Atomic: a crash mid-write must never truncate the change record into a
    // file that then loads as "modified nothing".
    writeFileAtomic(this.path, JSON.stringify(this.entries, null, 2));
  }
}
