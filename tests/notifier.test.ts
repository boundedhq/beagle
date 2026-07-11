import { describe, expect, test } from "bun:test";
import {
  stripControlChars,
  escapeAppleScript,
  osascriptArgs,
  notifySendArgs,
} from "../src/notifier/notifier";

describe("exec hygiene (design §6.10)", () => {
  test("strips ANSI escapes and control chars from traffic-derived text", () => {
    expect(stripControlChars("\x1b[31mred\x1b[0m alert")).toBe("red alert");
    expect(stripControlChars("normal text")).toBe("normal text");
    expect(stripControlChars("bell\x07 gone")).toBe("bell gone");
    expect(stripControlChars("tab\tand\nnewline kept")).toBe("tab\tand\nnewline kept");
  });

  test("AppleScript literal escaping neutralizes quotes and backslashes", () => {
    expect(escapeAppleScript('say "hi" \\ there')).toBe('say \\"hi\\" \\\\ there');
  });

  test("osascript invocation is an argv array, never a shell string", () => {
    const args = osascriptArgs({
      title: 'Leak: "aws-key"',
      body: "sent to model `rm -rf` \x1b[31m$(evil)\x1b[0m",
    });
    expect(args[0]).toBe("osascript");
    expect(args[1]).toBe("-e");
    // single script arg; shell metacharacters inert because there is no shell
    expect(args.length).toBe(3);
    expect(args[2]).toContain('\\"aws-key\\"');
    expect(args[2]).not.toContain("\x1b");
  });

  test("notify-send invocation is an argv array with sanitized text", () => {
    const args = notifySendArgs({ title: "t\x1b[2Jitle", body: "b$(x)" });
    expect(args[0]).toBe("notify-send");
    expect(args).toContain("title");
    expect(args.some((a) => a.includes("$(x)"))).toBe(true); // inert without a shell
    expect(args.every((a) => !a.includes("\x1b"))).toBe(true);
  });
});
