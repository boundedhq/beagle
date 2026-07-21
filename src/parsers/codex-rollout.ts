// Codex writes the full turn — including the assistant answer that its OTel
// export omits — to a per-session rollout log
// (~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl). This module parses
// that log and pairs each answer with its prompt so the answer can be stitched
// onto the self-reported (OTel) turn row. PURE (no fs/timers) so the pairing is
// unit-testable; the fs polling lives in src/adapters/codex-rollout-tailer.ts.
// See docs/codex-rollout-response-capture-design.md.
import { createHash } from "node:crypto";

// The per-turn join key, computed IDENTICALLY here and in the Codex OTel mapper
// (otlp-map buildCodexCall) so a rollout answer and its OTel prompt row share a
// prompt_key. Normalize conservatively — collapse whitespace, NFC — then
// sha256, first 16 hex. Verified byte-identical to the Phase-0 Python spike
// (design §8.2). Hash-of-prompt is the ONLY per-turn join: Codex OTel carries no
// turn/prompt id (§8.7), and a mis-key fails safe (no attach, never a wrong one).
export function codexPromptKey(text: string): string {
  const normalized = text.normalize("NFC").split(/\s+/).join(" ").trim();
  return createHash("sha256").update(normalized).digest("hex").slice(0, 16);
}

export interface RolloutAnswer {
  /** codexPromptKey of the user prompt this answer replies to. */
  promptKey: string;
  answer: string;
  /** Rollout line timestamp in ms, or undefined if absent/unparseable. */
  tsMs?: number;
}

interface RolloutItem {
  type?: string;
  payload?: { type?: string; role?: string; content?: unknown };
  timestamp?: string;
}

// Text of a rollout `message` payload: concatenate every content part's `text`
// (assistant answers use `output_text`, prompts `input_text` — take any).
function messageText(payload: RolloutItem["payload"]): string {
  const parts = Array.isArray(payload?.content) ? payload!.content : [];
  return parts.map((c) => (c && typeof (c as { text?: unknown }).text === "string" ? (c as { text: string }).text : "")).join("");
}

// A real user prompt: a role=user message that is NOT the injected
// <environment_context> block (which Codex writes as a user message at session
// start but is not something the user typed — it carries no OTel-side key).
function realPromptText(item: RolloutItem): string | null {
  const p = item.payload;
  if (item.type !== "response_item" || p?.type !== "message" || p?.role !== "user") return null;
  const text = messageText(p);
  return text.startsWith("<environment_context>") ? null : text;
}

function assistantText(item: RolloutItem): string | null {
  const p = item.payload;
  if (item.type === "response_item" && p?.type === "message" && p?.role === "assistant") return messageText(p);
  return null;
}

// Defensive JSONL parse: a blank or malformed line is skipped, never thrown (R3
// — one bad line must not discard the rest of the file).
function parseRollout(text: string): RolloutItem[] {
  const out: RolloutItem[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as RolloutItem);
    } catch {
      /* skip a malformed line */
    }
  }
  return out;
}

// Walk the rollout in order; pair each assistant answer with the nearest
// preceding real user prompt (validated 2/2 in the spike). An answer with no
// preceding prompt, or with no text (a tool-only turn), yields nothing.
//
// Stateful so the tailer can feed the file incrementally (only the new bytes
// each poll): the nearest-preceding-prompt state must survive across chunks —
// a prompt in one read keys an answer that arrives in a later one. push()
// takes whole lines only; the caller carries any partial trailing line.
export class RolloutPairing {
  private currentKey: string | null = null;
  push(text: string): RolloutAnswer[] {
    const out: RolloutAnswer[] = [];
    for (const item of parseRollout(text)) {
      const prompt = realPromptText(item);
      if (prompt !== null) {
        this.currentKey = codexPromptKey(prompt);
        continue;
      }
      const answer = assistantText(item);
      if (answer && this.currentKey) {
        const ms = item.timestamp ? Date.parse(item.timestamp) : NaN;
        out.push({ promptKey: this.currentKey, answer, tsMs: Number.isFinite(ms) ? ms : undefined });
      }
    }
    return out;
  }
}

export function answersFromText(text: string): RolloutAnswer[] {
  return new RolloutPairing().push(text);
}
