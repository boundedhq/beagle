// Session resolver (design §6.4): the R4 precedence ladder. Session =
// conversation, not process. Every resolution records which tier keyed it —
// this is the design's concentration of heuristic risk, so its decisions
// stay auditable, never silent.
import { createHash } from "node:crypto";
import type { Message } from "../exchange";
import type { Store } from "../store/store";
import { ulid } from "../store/ulid";

export type SessionTier = "conv-id" | "prefix" | "compaction-link" | "run" | "time-gap";

export interface ResolveInput {
  agent?: string;
  provider: string;
  runId?: string;
  ts: number;
  convId?: string;
  prevResponseId?: string;
  messages?: Message[];
  systemPrompt?: string;
}

export interface Resolution {
  sessionId: string;
  tier: SessionTier;
}

const TIME_GAP_MS = 30 * 60_000;

export class SessionResolver {
  constructor(private store: Store) {}

  resolve(input: ResolveInput): Resolution {
    // Tier 1 — explicit conversation identity.
    const explicitId = input.convId ?? input.prevResponseId;
    if (explicitId) {
      const found = this.store.findSessionBy("conv_id", [explicitId]);
      if (found) {
        this.store.updateSession(found, { lastTs: input.ts });
        return { sessionId: found, tier: "conv-id" };
      }
      if (input.convId) {
        return { sessionId: this.create(input, { convId: input.convId }), tier: "conv-id" };
      }
      // A prev_response_id we never saw: fall through to the other tiers.
    }

    // Tier 2 — history-prefix chaining.
    if (input.messages && input.messages.length > 0) {
      const prefixHashes = chainHashes(input.messages);
      const fullHash = prefixHashes[prefixHashes.length - 1]!;
      const byPrefix = this.store.findSessionBy("head_hash", prefixHashes);
      if (byPrefix) {
        this.store.updateSession(byPrefix, { lastTs: input.ts, headHash: fullHash });
        return { sessionId: byPrefix, tier: "prefix" };
      }
      // Compaction rewrote history: fuzzy-link on system + first user message.
      const fuzzy = fuzzyHash(input.systemPrompt, input.messages);
      if (fuzzy) {
        const byFuzzy = this.store.findSessionBy("fuzzy_hash", [fuzzy]);
        if (byFuzzy) {
          this.store.updateSession(byFuzzy, { lastTs: input.ts, headHash: fullHash });
          return { sessionId: byFuzzy, tier: "compaction-link" };
        }
      }
      return {
        sessionId: this.create(input, { headHash: fullHash, fuzzyHash: fuzzy }),
        tier: "prefix",
      };
    }

    // Tier 3 — the floor: run identity, then time gap.
    if (input.runId) {
      const byRun = this.store.findSessionBy("run_id", [input.runId]);
      if (byRun) {
        this.store.updateSession(byRun, { lastTs: input.ts });
        return { sessionId: byRun, tier: "run" };
      }
      return { sessionId: this.create(input, { runId: input.runId }), tier: "run" };
    }
    const recent = this.store.findRecentSession(
      input.agent ?? "", input.provider, input.ts - TIME_GAP_MS,
    );
    if (recent) {
      this.store.updateSession(recent, { lastTs: input.ts });
      return { sessionId: recent, tier: "time-gap" };
    }
    return { sessionId: this.create(input, {}), tier: "time-gap" };
  }

  /** Update chaining state once the response is known. */
  recordResponse(r: { sessionId: string; messages?: Message[]; responseId?: string }): void {
    const fields: { headHash?: string; convId?: string } = {};
    if (r.messages && r.messages.length > 0) {
      const hashes = chainHashes(r.messages);
      fields.headHash = hashes[hashes.length - 1]!;
    }
    if (r.responseId) fields.convId = r.responseId;
    if (fields.headHash !== undefined || fields.convId !== undefined) {
      this.store.updateSession(r.sessionId, fields);
    }
  }

  private create(
    input: ResolveInput,
    extra: { convId?: string; headHash?: string; fuzzyHash?: string; runId?: string },
  ): string {
    const id = ulid(input.ts);
    this.store.insertSession({
      id,
      agent: input.agent,
      provider: input.provider,
      firstTs: input.ts,
      lastTs: input.ts,
      ...extra,
    });
    return id;
  }
}

// Rolling hash chain over the message array; element i is the hash of
// messages[0..i]. A request whose array extends a known head matches one of
// these prefix hashes.
export function chainHashes(messages: Message[]): string[] {
  const hashes: string[] = [];
  let prev = "beagle-session-v1";
  for (const m of messages) {
    prev = createHash("sha256")
      .update(prev).update("\x1e").update(m.role).update("\x1f").update(m.content)
      .digest("hex");
    hashes.push(prev);
  }
  return hashes;
}

function fuzzyHash(systemPrompt: string | undefined, messages: Message[]): string | undefined {
  const firstUser = messages.find((m) => m.role === "user");
  if (!systemPrompt || !firstUser) return undefined;
  return createHash("sha256")
    .update("fuzzy\x1e").update(systemPrompt).update("\x1f").update(firstUser.content)
    .digest("hex");
}
