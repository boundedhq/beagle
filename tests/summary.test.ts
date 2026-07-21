import { describe, expect, test } from "bun:test";
import { buildSummary } from "../src/daemon/daemon";
import { redactionPlaceholder } from "../src/transform/redact";
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
describe("buildSummary — wire-order sent half", () => {
  test("trailing user message leads: \"ask\" → actions", () => {
    const s = buildSummary(
      req([
        { role: "assistant", content: "old answer" },
        { role: "user", content: "now run the tests" },
      ]),
      undefined,
      [{ tool: "bash", detail: "bun test" }],
    );
    expect(s).toBe('"now run the tests" → ran `bun test`');
  });

  test("every action branch bounds its detail — the summary is one stored line", () => {
    // `detail` reaches here UNCLAMPED on purpose: a parse-time clamp cut a
    // secret in half before the scrub could match it (toolAction). That makes
    // this the only thing bounding what lands in the summary column and rides
    // every feed frame — and a basename or bare path is not self-limiting, so
    // it has to be every branch, not just the two that quote a command or URL.
    const huge = "P".repeat(50_000);
    for (const detail of [huge, `/a/b/${huge}`, `${huge}\nsecond line`]) {
      for (const tool of ["Grep", "Read", "Bash", "WebFetch", "Skill"]) {
        const s = buildSummary(req([]), undefined, [{ tool, detail }]);
        expect(s.length).toBeLessThan(200);
        expect(s).not.toContain("\n"); // one line, always
      }
    }
  });

  test("trailing tool results lead: N results → actions", () => {
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
    expect(s).toBe("2 tool results → fetched `https://x.test/readme`");
  });

  test("response-text turns read ask → reply", () => {
    const s = buildSummary(
      req([{ role: "user", content: "what's 2+2?" }]),
      "4.",
    );
    expect(s).toBe('"what\'s 2+2?" → 4.');
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
    expect(s).toBe("1 tool result → All green.");
    expect(s).not.toContain('"452 pass');
  });

  test("the sent half names the tool when the trailing results agree on one", () => {
    const s = buildSummary(
      req([
        { role: "user", content: "q" },
        { role: "tool", content: "out1", kind: "result", tool: "webfetch" },
        { role: "tool", content: "out2", kind: "result", tool: "webfetch" },
      ]),
      undefined,
      [{ tool: "grep", detail: "opencode" }],
    );
    expect(s).toBe("2 webfetch results → searched `opencode`");
  });

  test("mixed-tool trailing results fall back to the generic name", () => {
    const s = buildSummary(
      req([
        { role: "tool", content: "a", kind: "result", tool: "bash" },
        { role: "tool", content: "b", kind: "result", tool: "webfetch" },
      ]),
      "Done.",
    );
    expect(s).toBe("2 tool results → Done.");
  });

  test("with a sent half, the response budgets to 2 actions and shows the overflow as +N", () => {
    const s = buildSummary(
      req([{ role: "tool", content: "r", kind: "result", tool: "bash" }]),
      undefined,
      [
        { tool: "webfetch", detail: "https://a.test/x" },
        { tool: "webfetch", detail: "https://b.test/y" },
        { tool: "webfetch", detail: "https://c.test/z" },
      ],
    );
    expect(s).toBe("1 bash result → fetched `https://a.test/x`, fetched `https://b.test/y` +1");
  });

  test("without a sent half, 3 actions show and deeper overflow is +N, never silent", () => {
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

  test("a placeholder straddling a cap renders WHOLE, not cut to a `[RED…` stump", () => {
    // The scrub runs before every truncation, so on a leak row a placeholder
    // straddling a cap is the NORMAL case, not an edge one: a placeholder is
    // ~35 chars against caps of 40 (the quoted ask) and 100 (the fallback).
    // Half of one reads as a corrupted transcript AND drops the secret type.
    const SECRET = "AKIAZQ3DRSTUVWXY2345";
    const vals = [{ value: SECRET, type: "aws-access-key-id" }];
    const P = redactionPlaceholder("aws-access-key-id", SECRET);

    // The 40-char quoted ask — the tightest budget in buildSummary.
    const ask = buildSummary(
      req([{ role: "user", content: `use key ${SECRET} for deploy` }]),
      "Deploying.", undefined, vals,
    );
    expect(ask).toBe(`"use key ${P}…" → Deploying.`);
    // ...and the run-past still fits the bound sessionTitle/summaryParts parse
    // the sent half with — the tripwire if a longer rule id ever lands.
    expect(ask).toMatch(/^"[^"]{1,200}" → /);

    // The 100-char fallback, with the secret starting at char 95.
    const fallback = buildSummary(
      req([{ role: "user", content: `${"p".repeat(94)} ${SECRET}` }]),
      undefined, undefined, vals,
    );
    expect(fallback).toBe(`${"p".repeat(94)} ${P}`);
    expect(fallback).not.toContain("…"); // nothing followed the secret to drop
  });

  test("running past a placeholder in BOTH halves still leaves the summary bounded", () => {
    // The run-past is what keeps a placeholder whole; a ceiling on it is what
    // keeps the summary a feed LINE — "the summary became unbounded" was a
    // review finding, and overshooting must not walk it back. Worst real case:
    // a secret straddling the 40-char ask AND the 80-char reply, each half
    // overshooting by one placeholder (≤39 chars — the longest rule id is 21).
    // Ceiling: ask (2 quotes + 38 + 39 + ellipsis = 80) + " → " + reply
    // (78 + 39 + ellipsis = 118) = 201.
    const SECRET = "AKIAZQ3DRSTUVWXY2345";
    const vals = [{ value: SECRET, type: "aws-access-key-id" }];
    const P = redactionPlaceholder("aws-access-key-id", SECRET);
    const s = buildSummary(
      req([{ role: "user", content: `${"a".repeat(30)}${SECRET}${"b".repeat(500)}` }]),
      `${"c".repeat(70)}${SECRET}${"d".repeat(500)}`,
      undefined, vals,
    );
    expect(s).toBe(`"${"a".repeat(30)}${P}…" → ${"c".repeat(70)}${P}…`);
    expect(s.length).toBeLessThan(250);
    expect(s).not.toContain("\n");
  });
});
