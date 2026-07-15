import { describe, expect, test } from "bun:test";
import { buildSummary } from "../src/daemon/daemon";
import type { ParsedRequest } from "../src/parsers/parsers";

// Regression for the Mode B display bug: rows whose only message wasn't from
// the user (a tool output, an assistant-only turn) summarized to a bare
// "N messages" count instead of their content. buildSummary now falls back to
// the last message of ANY role.
const req = (messages: ParsedRequest["messages"]): ParsedRequest => ({ messages });

describe("buildSummary", () => {
  test("a normal turn shows the last user message", () => {
    expect(buildSummary(req([{ role: "user", content: "read the config" }]))).toBe("read the config");
  });

  test("a tool-output row shows the tool content, NOT '1 messages'", () => {
    const s = buildSummary(req([{ role: "tool", content: "ToolSearch: matched 2 calendar tools" }]));
    expect(s).toBe("ToolSearch: matched 2 calendar tools");
    expect(s).not.toContain("1 messages");
  });

  test("an assistant-only turn shows the assistant text, not a count", () => {
    const s = buildSummary(req([{ role: "assistant", content: "Done — calendar is readable now." }]));
    expect(s).toBe("Done — calendar is readable now.");
    expect(s).not.toMatch(/\d+ messages/);
  });

  test("prefers the LAST user message when several roles are present", () => {
    expect(
      buildSummary(req([
        { role: "user", content: "first ask" },
        { role: "assistant", content: "some reply" },
        { role: "user", content: "second ask" },
      ])),
    ).toBe("second ask");
  });

  test("an empty turn reads '(no message content)', not '0 messages'", () => {
    const s = buildSummary(req([]));
    expect(s).toBe("(no message content)");
    expect(s).not.toContain("0 messages");
  });

  test("a null parse still says so plainly", () => {
    expect(buildSummary(null)).toContain("unparsed call");
  });

  test("response text and tool actions still win over the message fallback", () => {
    expect(buildSummary(req([{ role: "tool", content: "x" }]), "the model's answer")).toBe("the model's answer");
  });
});
