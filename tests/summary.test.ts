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

  test("an anthropic tool-result turn (results ride USER-role messages) is never quoted as the user's ask", () => {
    // Anthropic's protocol: tool results arrive as {role:"user", content:
    // [{type:"tool_result",…}]} — the parser stamps kind:"result". The suffix
    // must say "after N tool results", not caption tool output as human words.
    const s = buildSummary(
      req([
        { role: "user", content: "run the tests" },
        { role: "assistant", content: "Running." },
        { role: "user", content: "452 pass, 0 fail", kind: "result" },
      ]),
      "All green.",
    );
    expect(s).toBe("All green. — after 1 tool result");
    expect(s).not.toContain('to "452 pass');
  });

  test("the suffix names the tool when the trailing results agree on one", () => {
    const s = buildSummary(
      req([
        { role: "user", content: "q" },
        { role: "tool", content: "out1", kind: "result", tool: "webfetch" },
        { role: "tool", content: "out2", kind: "result", tool: "webfetch" },
      ]),
      undefined,
      [{ tool: "grep", detail: "opencode" }],
    );
    expect(s).toBe("searched `opencode` — after 2 webfetch results");
  });

  test("mixed-tool trailing results fall back to the generic name", () => {
    const s = buildSummary(
      req([
        { role: "tool", content: "a", kind: "result", tool: "bash" },
        { role: "tool", content: "b", kind: "result", tool: "webfetch" },
      ]),
      "Done.",
    );
    expect(s).toBe("Done. — after 2 tool results");
  });

  test("with a suffix, the lead budgets to 2 actions and shows the overflow as +N", () => {
    const s = buildSummary(
      req([{ role: "tool", content: "r", kind: "result", tool: "bash" }]),
      undefined,
      [
        { tool: "webfetch", detail: "https://a.test/x" },
        { tool: "webfetch", detail: "https://b.test/y" },
        { tool: "webfetch", detail: "https://c.test/z" },
      ],
    );
    expect(s).toBe("fetched `https://a.test/x`, fetched `https://b.test/y` +1 — after 1 bash result");
  });

  test("without a suffix, 3 actions show and deeper overflow is +N, never silent", () => {
    const s = buildSummary(
      req([{ role: "user", content: "go" }, { role: "assistant", content: "x" }]),
      undefined,
      [
        { tool: "bash", detail: "a" }, { tool: "bash", detail: "b" },
        { tool: "bash", detail: "c" }, { tool: "bash", detail: "d" },
      ],
    );
    expect(s).toBe("ran `a`, ran `b`, ran `c` +1");
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
