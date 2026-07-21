import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { codexPromptKey, answersFromText } from "../src/parsers/codex-rollout";

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
});
