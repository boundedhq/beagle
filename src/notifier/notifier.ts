// OS notifier (design §6.10, non-core). Exec hygiene is non-negotiable:
// alert text embeds traffic-derived strings, so we always spawn with an argv
// array — never a shell string — escape AppleScript literals, and strip
// ANSI/control characters before anything reaches a TTY or notification.
import { spawn } from "node:child_process";

export interface AlertMessage {
  title: string;
  body: string;
}

// Removes C0/C1 control chars (incl. full ANSI CSI/OSC sequences); keeps \t \n \r.
export function stripControlChars(s: string): string {
  return s
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "") // OSC sequences
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "") // CSI sequences
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
}

export function escapeAppleScript(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export function osascriptArgs(msg: AlertMessage): string[] {
  const title = escapeAppleScript(stripControlChars(msg.title));
  const body = escapeAppleScript(stripControlChars(msg.body));
  return ["osascript", "-e", `display notification "${body}" with title "${title}"`];
}

export function notifySendArgs(msg: AlertMessage): string[] {
  return [
    "notify-send",
    "--urgency=critical",
    "--app-name=beagle",
    stripControlChars(msg.title),
    stripControlChars(msg.body),
  ];
}

export class Notifier {
  private degraded = false;

  constructor(private platform: NodeJS.Platform = process.platform) {}

  /** True when OS notifications are unavailable and only the terminal line fires. */
  get isDegraded(): boolean {
    return this.degraded;
  }

  notify(msg: AlertMessage): void {
    const argv = this.platform === "darwin" ? osascriptArgs(msg) : notifySendArgs(msg);
    try {
      const child = spawn(argv[0]!, argv.slice(1), { stdio: "ignore", detached: false });
      child.on("error", () => { this.degraded = true; });
    } catch {
      this.degraded = true;
    }
  }

  /** Terminal fallback/backstop line (full-screen TUIs eat stderr, R2). */
  terminalLine(msg: AlertMessage): string {
    return `beagle ▲ ${stripControlChars(msg.title)} — ${stripControlChars(msg.body)}`;
  }
}
