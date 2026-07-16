import { describe, expect, test } from "bun:test";
import {
  stripControlChars,
  escapeAppleScript,
  osascriptArgs,
  notifySendArgs,
  Notifier,
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

  test("subtitle rides macOS's second banner line, escaped like the rest", () => {
    const args = osascriptArgs({ title: "Beagle — secret sent", subtitle: 'AWS "key"', body: "b" });
    expect(args[2]).toContain('subtitle "AWS \\"key\\""');
    // and stays absent when not provided
    expect(osascriptArgs({ title: "t", body: "b" })[2]).not.toContain("subtitle");
  });

  test("notify-send has no subtitle slot — it leads the body instead", () => {
    const args = notifySendArgs({ title: "t", subtitle: "AWS access key", body: "the rest" });
    expect(args.at(-1)).toBe("AWS access key\nthe rest");
  });

  test("a body newline becomes an AppleScript \\n escape, never a raw newline", () => {
    // AppleScript renders "a\\nb" as two lines; a raw newline in the -e source
    // is the thing we must avoid (it would split the script argument).
    expect(escapeAppleScript("line one\nline two")).toBe("line one\\nline two");
    const args = osascriptArgs({ title: "t", body: "did it.\nrun beagle ui" });
    expect(args[2]).toContain("did it.\\nrun beagle ui");
    expect(args[2]).not.toContain("did it.\nrun beagle ui"); // no raw newline
  });

  test("notify-send keeps body newlines so the next step gets its own line", () => {
    const args = notifySendArgs({ title: "t", body: "did it.\nrun beagle ui" });
    expect(args.at(-1)).toBe("did it.\nrun beagle ui");
  });

  test("the terminal backstop stays one line even when the body has a newline", () => {
    const line = new Notifier().terminalLine({ title: "t", body: "did it.\nrun beagle ui" });
    expect(line).not.toContain("\n");
    expect(line).toContain("did it. run beagle ui");
  });
});
