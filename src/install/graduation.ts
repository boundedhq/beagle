// Graduation nudge (design §6.12, R2): after the 3rd wrapper run of the same
// agent, one dismissable prompt to watch it automatically — shown once,
// never nags if declined, never applies without an explicit yes.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const NUDGE_AT = 3;

interface GraduationState {
  runs: Record<string, number>;
  nudged: Record<string, boolean>;
  dismissed: Record<string, boolean>;
  watched: Record<string, boolean>;
}

export class GraduationTracker {
  private path: string;
  private state: GraduationState;

  constructor(stateDir: string) {
    this.path = join(stateDir, "graduation.json");
    this.state = this.load();
  }

  /** Record a wrapper run; return true exactly once, when the nudge should show. */
  recordRunAndCheck(agent: string): boolean {
    if (this.state.watched[agent] || this.state.dismissed[agent] || this.state.nudged[agent]) {
      this.bump(agent);
      return false;
    }
    this.bump(agent);
    if ((this.state.runs[agent] ?? 0) >= NUDGE_AT) {
      this.state.nudged[agent] = true;
      this.persist();
      return true;
    }
    this.persist();
    return false;
  }

  dismiss(agent: string): void {
    this.state.dismissed[agent] = true;
    this.persist();
  }

  markWatched(agent: string): void {
    this.state.watched[agent] = true;
    this.persist();
  }

  private bump(agent: string): void {
    this.state.runs[agent] = (this.state.runs[agent] ?? 0) + 1;
  }

  private load(): GraduationState {
    const empty: GraduationState = { runs: {}, nudged: {}, dismissed: {}, watched: {} };
    if (!existsSync(this.path)) return empty;
    try {
      return { ...empty, ...(JSON.parse(readFileSync(this.path, "utf8")) as GraduationState) };
    } catch {
      return empty;
    }
  }

  private persist(): void {
    writeFileSync(this.path, JSON.stringify(this.state), { mode: 0o600 });
  }
}
