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
  /** The NEWEST assistant message in `answer` (equal to it until a turn merges
   *  a second one). Codex narrates before it answers, so a merged answer opens
   *  with a preamble — "I'm using the docs skill…" — and the one-line summary,
   *  which reads the FIRST line, would describe the narration while the row
   *  holds the real reply. The feed line summarizes this instead; the stored
   *  body stays the whole merged answer. */
  latest: string;
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

/** A turn's tool calls, for display grouping (turn_link). Grows as the turn
 *  runs, like answers: each new call re-yields the turn's list-so-far. */
export interface RolloutTurnLinks {
  promptKey: string;
  /** Nth REAL user prompt with this key — ALL turns, answered or not, because
   *  the viewer counts prompt rows the same way. Deliberately not
   *  RolloutAnswer.ordinal, which counts answered turns only (the shipped
   *  attach semantics; see that field's note). */
  ordinal: number;
  /** call_ids in rollout order — seq is the index. */
  callIds: string[];
}

interface RolloutItem {
  type?: string;
  payload?: { type?: string; role?: string; content?: unknown; call_id?: unknown };
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

// A tool call the turn made: custom_tool_call / function_call / any future
// `*_call` item carrying a call_id — the same generic suffix rule the wire
// Responses parser uses (parsers.ts responsesItem). Outputs (`*_call_output`)
// are excluded FIRST: they share the suffix and the call_id, and counting both
// halves would double every call's seq.
function toolCallId(item: RolloutItem): string | null {
  const p = item.payload;
  if (item.type !== "response_item" || typeof p?.type !== "string") return null;
  if (p.type.endsWith("_call_output") || !p.type.endsWith("_call")) return null;
  return typeof p.call_id === "string" && p.call_id !== "" ? p.call_id : null;
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
  private readonly turns = new Map<string, number>(); // promptKey → ANSWERED same-key turns seen
  private readonly allTurns = new Map<string, number>(); // promptKey → ALL same-key turns seen (links)
  private openLinks: RolloutTurnLinks | null = null; // the current turn's calls so far
  push(text: string): { answers: RolloutAnswer[]; links: RolloutTurnLinks[] } {
    const out: RolloutAnswer[] = [];
    const links: RolloutTurnLinks[] = [];
    for (const item of parseRollout(text)) {
      const prompt = realPromptText(item);
      if (prompt !== null) {
        this.currentKey = codexPromptKey(prompt);
        this.open = null; // a new turn — never merge across prompts
        // Links get their turn ordinal HERE, at the prompt, counting every
        // turn — a tool-only turn has links but no answer, and counting only
        // answered turns would land its calls on the wrong same-text row.
        const ordinal = this.allTurns.get(this.currentKey) ?? 0;
        this.allTurns.set(this.currentKey, ordinal + 1);
        this.openLinks = { promptKey: this.currentKey, ordinal, callIds: [] };
        continue;
      }
      const callId = toolCallId(item);
      if (callId && this.openLinks) {
        // Copy-on-grow, like answers: the tailer content-hashes each yielded
        // state, so growing a yielded object in place would mutate its key.
        const grown = { ...this.openLinks, callIds: [...this.openLinks.callIds, callId] };
        if (links.length && links[links.length - 1] === this.openLinks) links[links.length - 1] = grown;
        else links.push(grown);
        this.openLinks = grown;
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
            latest: answer, // the substantive reply, once narration precedes it
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
          this.open = { promptKey: this.currentKey, answer, latest: answer, tsMs, ordinal };
          out.push(this.open);
        }
      }
    }
    return { answers: out, links };
  }
}

export function answersFromText(text: string): RolloutAnswer[] {
  return new RolloutPairing().push(text).answers;
}

export function linksFromText(text: string): RolloutTurnLinks[] {
  return new RolloutPairing().push(text).links;
}
