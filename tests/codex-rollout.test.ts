import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { codexPromptKey, answersFromText, RolloutPairing } from "../src/parsers/codex-rollout";

// A minimal, controlled 2-turn rollout — the exact shape captured in the
// Phase-0 spike (docs/codex-rollout-response-capture-design.md §8.7): a
// session_meta, developer base-instructions, one injected <environment_context>
// user message, then per turn a turn_context, the real user prompt, and the
// assistant answer.
function line(type: string, payload: unknown, ts = "2026-07-20T21:32:45.000Z"): string {
  return JSON.stringify({ timestamp: ts, type, payload });
}
const msg = (role: string, text: string) => ({ type: "message", role, content: [{ type: "output_text", text }] });

const TWO_TURN = [
  line("session_meta", { session_id: "conv-1", id: "conv-1" }),
  line("response_item", msg("developer", "You are a coding agent.")),
  line("response_item", msg("user", "<environment_context>\n  <cwd>/tmp</cwd>\n</environment_context>")),
  line("turn_context", { turn_id: "turn-1", model: "gpt-5.6-sol" }),
  line("response_item", msg("user", "Reply with exactly this token and nothing else: ALPHA111")),
  line("response_item", msg("assistant", "ALPHA111"), "2026-07-20T21:32:45.500Z"),
  line("event_msg", { type: "token_count" }),
  line("turn_context", { turn_id: "turn-2", model: "gpt-5.6-sol" }),
  line("response_item", msg("user", "Reply with exactly this token and nothing else: BRAVO222")),
  line("response_item", msg("assistant", "BRAVO222"), "2026-07-20T21:32:51.500Z"),
].join("\n");

describe("codexPromptKey", () => {
  test("is deterministic and whitespace-normalized", () => {
    expect(codexPromptKey("hello world")).toBe(codexPromptKey("hello world"));
    expect(codexPromptKey("  hello   world  ")).toBe(codexPromptKey("hello world"));
    expect(codexPromptKey("hello\n\tworld")).toBe(codexPromptKey("hello world"));
  });

  test("distinct prompts → distinct keys", () => {
    expect(codexPromptKey("ALPHA")).not.toBe(codexPromptKey("BRAVO"));
  });

  // Cross-language anchor: these exact values came out of the Python spike
  // (sha256 of the normalized prompt, first 16 hex). If this drifts, the OTel
  // side and the rollout side would compute different keys and never stitch.
  test("matches the Phase-0 spike hashes byte-for-byte", () => {
    expect(codexPromptKey("Reply with exactly this token and nothing else: ALPHA111")).toBe("7959d7bb7b5c2ac5");
    expect(codexPromptKey("Reply with exactly this token and nothing else: BRAVO222")).toBe("64bb53f6acd066f0");
  });
});

describe("answersFromText", () => {
  test("pairs each answer with its own prompt's key, in order", () => {
    const answers = answersFromText(TWO_TURN);
    expect(answers.map((a) => a.answer)).toEqual(["ALPHA111", "BRAVO222"]);
    expect(answers[0]!.promptKey).toBe(codexPromptKey("Reply with exactly this token and nothing else: ALPHA111"));
    expect(answers[1]!.promptKey).toBe(codexPromptKey("Reply with exactly this token and nothing else: BRAVO222"));
  });

  test("carries the rollout line timestamp (ms)", () => {
    const answers = answersFromText(TWO_TURN);
    expect(answers[0]!.tsMs).toBe(Date.parse("2026-07-20T21:32:45.500Z"));
  });

  test("never keys an answer to the injected <environment_context> message", () => {
    // env_context is a role=user message but not a real prompt; if it were used
    // as the key, ALPHA's answer would carry env_context's hash and miss.
    const answers = answersFromText(TWO_TURN);
    const envKey = codexPromptKey("<environment_context>\n  <cwd>/tmp</cwd>\n</environment_context>");
    expect(answers.every((a) => a.promptKey !== envKey)).toBe(true);
  });

  test("ignores developer messages as prompts", () => {
    const text = [
      line("response_item", msg("developer", "system stuff")),
      line("response_item", msg("assistant", "orphan")),
    ].join("\n");
    // no real user prompt precedes the answer → nothing to key it to → dropped
    expect(answersFromText(text)).toEqual([]);
  });

  test("skips a tool-only turn (assistant message with no text)", () => {
    const text = [
      line("response_item", msg("user", "run ls")),
      line("response_item", { type: "message", role: "assistant", content: [] }),
    ].join("\n");
    expect(answersFromText(text)).toEqual([]);
  });

  test("degrades over malformed / blank lines without throwing (R3)", () => {
    const text = ["", "not json", "{unterminated", TWO_TURN, ""].join("\n");
    const answers = answersFromText(text);
    expect(answers.map((a) => a.answer)).toEqual(["ALPHA111", "BRAVO222"]);
  });

  test("extracts both turns of the real captured session, keyed to their own prompts", () => {
    // What makes this fixture worth pinning exactly: its turn 2 sits past a
    // thread_rolled_back event, behind a RE-INJECTED developer + env-context
    // preamble — the one shape none of the synthetic cases above cover. A
    // regression that drops that turn, or keys it to anything but the real
    // BRAVO222 prompt, passed the old "≥1 answer, keys look like keys" form of
    // this test. The expected keys are the Phase-0 spike hashes of the
    // fixture's own prompt texts (pinned as such above), re-verified by
    // running the extractor over the fixture before writing them here.
    const real = readFileSync(join(import.meta.dir, "fixtures/codex-rollout-clean.jsonl"), "utf8");
    const answers = answersFromText(real);
    expect(answers.map((a) => [a.answer, a.promptKey])).toEqual([
      ["ALPHA111", "7959d7bb7b5c2ac5"],
      ["BRAVO222", "64bb53f6acd066f0"],
    ]);
  });

  // Codex narrates: a turn with tool calls carries SEVERAL assistant messages —
  // short "what I'm about to do" preambles between tools, then the real answer.
  // Emitting them separately let the first preamble claim the turn row and the
  // double-attach guard dropped the final answer (live session
  // 01KY1F0V56X9B64ZQEPC9CPPZB lost its actual reply this way).
  describe("multi-message turns", () => {
    const PROMPT = "how does codex memory work?";
    const MULTI = [
      line("response_item", msg("user", PROMPT)),
      line("response_item", msg("assistant", "I’m checking the docs first."), "2026-07-20T21:30:24.000Z"),
      line("response_item", { type: "function_call", name: "shell" }),
      line("response_item", msg("assistant", "The site is unreachable, trying the mirror."), "2026-07-20T21:30:40.000Z"),
      line("response_item", msg("assistant", "Codex has three memory-like layers: …the real answer…"), "2026-07-20T21:30:58.000Z"),
    ].join("\n");
    const MERGED =
      "I’m checking the docs first.\n\n" +
      "The site is unreachable, trying the mirror.\n\n" +
      "Codex has three memory-like layers: …the real answer…";

    test("merges a turn's preambles and final answer into ONE answer, in order", () => {
      const answers = answersFromText(MULTI);
      expect(answers).toHaveLength(1);
      expect(answers[0]!.promptKey).toBe(codexPromptKey(PROMPT));
      expect(answers[0]!.answer).toBe(MERGED);
    });

    test("tsMs is the LAST message's timestamp (when the answer completed)", () => {
      expect(answersFromText(MULTI)[0]!.tsMs).toBe(Date.parse("2026-07-20T21:30:58.000Z"));
    });

    test("fed incrementally, each push yields the merged-so-far answer — a prefix chain", () => {
      // The tailer feeds only NEW lines each poll; the pairing must re-yield
      // the turn's merged whole so the grown answer replaces the shorter view.
      // Earlier snapshots must stay intact (the tailer keys them by content).
      const pairing = new RolloutPairing();
      const lines = MULTI.split("\n");
      const first = pairing.push(lines.slice(0, 2).join("\n") + "\n");
      expect(first.map((a) => a.answer)).toEqual(["I’m checking the docs first."]);
      const rest = pairing.push(lines.slice(2).join("\n") + "\n");
      expect(rest.map((a) => a.answer)).toEqual([MERGED]);
      expect(first[0]!.answer).toBe("I’m checking the docs first."); // snapshot not mutated
      expect(MERGED.startsWith(first[0]!.answer)).toBe(true); // grow-only prefix invariant
      expect(rest[0]!.ordinal).toBe(first[0]!.ordinal); // same turn, same routing
    });

    test("messages merge per turn, never across turns", () => {
      const twoTurns = [
        line("response_item", msg("user", "first question")),
        line("response_item", msg("assistant", "preamble one")),
        line("response_item", msg("assistant", "answer one")),
        line("response_item", msg("user", "second question")),
        line("response_item", msg("assistant", "answer two")),
      ].join("\n");
      const answers = answersFromText(twoTurns);
      expect(answers.map((a) => a.answer)).toEqual(["preamble one\n\nanswer one", "answer two"]);
    });

    test("REPEATED identical prompts stay separate turns with rising ordinals", () => {
      // hash(prompt) is the only join key, so two turns asking the same thing
      // share it — the ordinal is what lets each answer find its own row.
      const repeated = [
        line("response_item", msg("user", "continue")),
        line("response_item", msg("assistant", "part one")),
        line("response_item", msg("user", "continue")),
        line("response_item", msg("assistant", "part two")),
        line("response_item", msg("user", "something else")),
        line("response_item", msg("assistant", "done")),
      ].join("\n");
      const answers = answersFromText(repeated);
      expect(answers.map((a) => [a.answer, a.ordinal])).toEqual([
        ["part one", 0],
        ["part two", 1],
        ["done", 0],
      ]);
    });
  });
});
