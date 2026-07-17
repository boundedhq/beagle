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

// The two-sided line (turn-clarity): lead = what came back (unchanged rules),
// suffix = what the agent sent, judged from the request's TRAILING messages
// only — the daemon has no previous-call diff to lean on.
describe("buildSummary — sent suffix", () => {
  test("actions lead + trailing user message → — to \"…\"", () => {
    const s = buildSummary(
      req([
        { role: "assistant", content: "old answer" },
        { role: "user", content: "now run the tests" },
      ]),
      undefined,
      [{ tool: "bash", detail: "bun test" }],
    );
    expect(s).toBe('ran `bun test` — to "now run the tests"');
  });

  test("actions lead + trailing tool results → — after N tool results", () => {
    const s = buildSummary(
      req([
        { role: "user", content: "q" },
        { role: "tool", content: "bash: {}", kind: "call" },
        { role: "tool", content: "out1", kind: "result" },
        { role: "tool", content: "out2", kind: "result" },
      ]),
      undefined,
      [{ tool: "webfetch", detail: "https://x.test/readme" }],
    );
    expect(s).toBe("fetched `https://x.test/readme` — after 2 tool results");
  });

  test("response-text lead gets the suffix too", () => {
    const s = buildSummary(
      req([{ role: "user", content: "what's 2+2?" }]),
      "4.",
    );
    expect(s).toBe('4. — to "what\'s 2+2?"');
  });

  test("a one-shot keeps its bare summary — sessionTitle's JSON unwrap depends on it", () => {
    const s = buildSummary(
      { messages: [{ role: "user", content: "name this chat" }], oneShot: true },
      '{"title":"Calendar access"}',
    );
    expect(s).toBe('{"title":"Calendar access"}');
  });

  test("the user-message fallback lead never doubles itself with a suffix", () => {
    const s = buildSummary(req([{ role: "user", content: "just this" }]));
    expect(s).toBe("just this");
  });

  test("a secret in the trailing user message is scrubbed before the suffix truncates", () => {
    const SECRET = "AKIAZQ3DRSTUVWXY2345";
    const s = buildSummary(
      req([{ role: "user", content: `use key ${SECRET} for deploy` }]),
      "Deploying.",
      undefined,
      [{ value: SECRET, type: "aws-access-key-id" }],
    );
    expect(s).not.toContain(SECRET);
    expect(s).toContain("[REDACTED:aws-access-key-id:");
  });
});
