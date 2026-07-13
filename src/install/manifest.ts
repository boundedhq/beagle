// Change manifest (design §6.12): every persistent mutation recorded at apply
// time, before the mutation. The trust strip reads it; unwatch and uninstall
// revert from it. Without this, "what did Beagle touch" is guesswork.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface ChangeEntry {
  kind: "shim" | "config-backup" | "config-redirect" | "service";
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
    if (this.entries.length === 0) return "configs changed: 0";
    const labels = [
      ...new Set(
        this.entries
          .filter((e) => e.agent)
          .map((e) => (e.mode === "telemetry" ? `${e.agent} (telemetry)` : e.agent!)),
      ),
    ];
    return `configs changed: ${this.entries.length} (${labels.join(", ")})`;
  }

  private load(): ChangeEntry[] {
    if (!existsSync(this.path)) return [];
    try {
      return JSON.parse(readFileSync(this.path, "utf8")) as ChangeEntry[];
    } catch {
      return [];
    }
  }

  private persist(): void {
    writeFileSync(this.path, JSON.stringify(this.entries, null, 2), { mode: 0o600 });
  }
}
