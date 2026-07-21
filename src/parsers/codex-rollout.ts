// Codex writes the full turn — including the assistant answer that its OTel
// export omits — to a per-session rollout log
// (~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl). This module parses
// that log and pairs each answer with its prompt so the answer can be stitched
// onto the self-reported (OTel) turn row. PURE (no fs/timers) so the pairing is
// unit-testable; the fs polling lives in src/adapters/codex-rollout-tailer.ts.
// Stitching an answer does NOT upgrade fidelity: the rollout is Codex's own
// post-hoc record of the turn, so the row stays badged self-reported, never
// wire-verified.
import { createHash } from "node:crypto";

// The per-turn join key, computed IDENTICALLY here and in the Codex OTel mapper
// (otlp-map buildCodexCall) so a rollout answer and its OTel prompt row share a
// prompt_key. Normalize conservatively — collapse whitespace, NFC — then
// sha256, first 16 hex. Verified byte-identical to the Phase-0 Python spike
// against Codex 0.144.6. Hash-of-prompt is the ONLY per-turn join: Codex OTel
// carries no turn/prompt id — its codex.user_prompt attribute set has no
// prompt.id, turn_id or ordinal — and a mis-key fails safe (no attach, never a
// wrong one).
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
  /** Which same-key turn this is (0-based): hash(prompt) is the only join key,
   *  so two turns asking the identical thing share it — the ordinal routes each
   *  answer to its own row (store.attachOtelResponse extend.ordinal). Counts
   *  ANSWERED turns only (a tool-only turn yields no entry) while rows count
   *  every prompt, so a SILENT same-key turn misaligns the two and the answer
   *  lands on the earlier same-text row — the exact outcome the pre-ordinal
   *  earliest-unanswered rule produced there. Accepted: same failure, same
   *  rarity, and the ts staleness bound still refuses anything newer. */
  ordinal: number;
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

// Walk the rollout in order; pair assistant text with the nearest preceding
// real user prompt (validated 2/2 in the spike). ONE answer per turn: codex
// narrates, so a tool-using turn carries several assistant messages (preambles
// between tools, then the real reply) — merged in order, because emitting each
// separately let the first preamble claim the turn row and the double-attach
// guard then dropped the actual final answer (live session
// 01KY1F0V56X9B64ZQEPC9CPPZB lost its real reply this way). A turn's answer
// therefore GROWS: each new message yields the turn's merged-so-far answer
// again, every earlier view a strict PREFIX of a later one — the invariant
// behind the store's replace-if-longer extend rule, and what makes the grown
// content hash differently in the tailer (a fresh content key → a fresh emit).
// An answer with no preceding prompt, or a tool-only turn, yields nothing.
//
// Stateful so the tailer can feed the file incrementally (only the new bytes
// each poll): the nearest-preceding-prompt state — and the open turn's
// accumulated answer — must survive across chunks. push() takes whole lines
// only; the caller carries any partial trailing line.
export class RolloutPairing {
  private currentKey: string | null = null;
  private open: RolloutAnswer | null = null; // the current turn's merged answer so far
  private readonly turns = new Map<string, number>(); // promptKey → same-key turns seen
  push(text: string): RolloutAnswer[] {
    const out: RolloutAnswer[] = [];
    for (const item of parseRollout(text)) {
      const prompt = realPromptText(item);
      if (prompt !== null) {
        this.currentKey = codexPromptKey(prompt);
        this.open = null; // a new turn — never merge across prompts
        continue;
      }
      const answer = assistantText(item);
      if (answer && this.currentKey) {
        const ms = item.timestamp ? Date.parse(item.timestamp) : NaN;
        const tsMs = Number.isFinite(ms) ? ms : undefined;
        if (this.open) {
          // Copy, never mutate: the tailer keeps earlier snapshots (keyed by
          // their content hash), so growing one in place would corrupt them.
          const grown: RolloutAnswer = {
            ...this.open,
            answer: this.open.answer + "\n\n" + answer,
            tsMs: tsMs ?? this.open.tsMs, // completion time = last message's
          };
          // Within one push, supersede the same turn's earlier snapshot rather
          // than returning both — answersFromText stays one answer per turn.
          if (out.length && out[out.length - 1] === this.open) out[out.length - 1] = grown;
          else out.push(grown);
          this.open = grown;
        } else {
          const ordinal = this.turns.get(this.currentKey) ?? 0;
          this.turns.set(this.currentKey, ordinal + 1);
          this.open = { promptKey: this.currentKey, answer, tsMs, ordinal };
          out.push(this.open);
        }
      }
    }
    return out;
  }
}

export function answersFromText(text: string): RolloutAnswer[] {
  return new RolloutPairing().push(text);
}
