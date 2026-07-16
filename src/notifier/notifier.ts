// OS notifier (design §6.10, non-core). Exec hygiene is non-negotiable:
// alert text embeds traffic-derived strings, so we always spawn with an argv
// array — never a shell string — escape AppleScript literals, and strip
// ANSI/control characters before anything reaches a TTY or notification.
import { spawn } from "node:child_process";

export interface AlertMessage {
  title: string;
  /** Second line on macOS banners (its own truncation budget); folded into
   *  the body elsewhere. Carries the specifics the short title can't. */
  subtitle?: string;
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

// macOS silently truncates long notification bodies; trim from the middle so
// the trailing `beagle show <id>` reference survives.
export function trimBody(s: string, max = 200): string {
  if (s.length <= max) return s;
  const keepTail = 60;
  return s.slice(0, max - keepTail - 1) + "…" + s.slice(s.length - keepTail);
}

export function osascriptArgs(msg: AlertMessage): string[] {
  const title = escapeAppleScript(stripControlChars(msg.title));
  const body = escapeAppleScript(trimBody(stripControlChars(msg.body)));
  // The subtitle is macOS's second banner line — it gives the specifics
  // their own truncation budget so the short title always fits.
  const subtitle = msg.subtitle
    ? ` subtitle "${escapeAppleScript(stripControlChars(msg.subtitle))}"`
    : "";
  // A leak alert should be heard, not just seen — "Ping" is a stock macOS
  // sound, so this stays dependency-free. (Known limitation of osascript
  // notifications: the icon is Script Editor's and a click activates Script
  // Editor — Apple offers no hook there without shipping a signed .app, so
  // the TITLE carries the Beagle branding instead.)
  return [
    "osascript", "-e",
    `display notification "${body}" with title "${title}"${subtitle} sound name "Ping"`,
  ];
}

export function notifySendArgs(msg: AlertMessage): string[] {
  // notify-send has no subtitle slot — it leads the body on its own line.
  const body = msg.subtitle ? `${msg.subtitle}\n${msg.body}` : msg.body;
  return [
    "notify-send",
    "--urgency=critical",
    "--app-name=beagle",
    stripControlChars(msg.title),
    stripControlChars(body),
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

  /** Terminal fallback/backstop line (full-screen TUIs eat stderr, R2).
   *  The string opens with an invisible BEL (\\u0007) — the terminal beeps
   *  when the alert prints. Deliberate since PR 5; easy to miss in an editor. */
  terminalLine(msg: AlertMessage): string {
    const mid = msg.subtitle ? `${stripControlChars(msg.subtitle)} — ` : "";
    return `beagle ▲ ${stripControlChars(msg.title)} — ${mid}${stripControlChars(msg.body)}`;
  }
}
