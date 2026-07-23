// Viewer session projection (non-core): the "see a whole session" view. Two
// faces: listSessions (the browse tab) and buildSessionTurns (one session
// rendered as a chronological conversation, like the agent's own UI).
//
// The delta problem: wire-mode requests each carry the FULL growing message
// history (turn N resends turns 1..N-1), so replaying every call verbatim
// would repeat every message dozens of times. Each wire turn therefore shows
// only the messages ADDED since the previous wire call in the session. Mode B
// (otel) rows are already per-turn — their messages are always all new.
import type { Store } from "../core/store/store";
import { buildDetail, leakSpansFor, type DetailLeak } from "./detail";
import { DEMO_AGENT, type Message } from "../core/call";
import { sanitizeTool, type DisplayMessage, type ToolAction } from "../parsers/parsers";

// Summaries that are placeholders, not content — skipped when picking a
// session title (shared by both title subqueries below). Static strings only:
// they are inlined into SQL.
const SENTINEL_SUMMARIES = ["(no message content)", "unparsed call (raw view available)"] as const;
const SENTINEL_SQL = SENTINEL_SUMMARIES.map((s) => `'${s}'`).join(", ");

export interface SessionRow {
  sessionId: string;
  agent?: string;
  provider?: string;
  model?: string; // most recent non-null model in the session
  firstTs: number;
  lastTs: number;
  calls: number;
  leaks: number; // leak events pinned to this session
  source: string; // 'wire' | 'otel' | 'mixed'
  title?: string; // earliest meaningful call summary — reads like a conversation title
  utility: boolean; // every call is a stateless one-shot (e.g. a title-generation turn)
  demo: boolean;
}

// The browse tab: one row per session, newest activity first. Display query,
// non-core (rides Store.queryAll like the feed).
export function listSessions(store: Store, limit: number): SessionRow[] {
  return store
    .queryAll<Record<string, unknown>>(
      `SELECT e.session_id,
              MAX(e.agent) AS agent, MAX(e.provider) AS provider,
              (SELECT model FROM exchanges m WHERE m.session_id = e.session_id
                 AND m.model IS NOT NULL ORDER BY m.ts_request DESC LIMIT 1) AS model,
              MIN(e.ts_request) AS first_ts, MAX(e.ts_request) AS last_ts,
              COUNT(*) AS calls,
              -- Every call a stateless one-shot → the session is a utility
              -- turn (e.g. opencode's title generation), badged in the list.
              MIN(COALESCE(e.one_shot, 0)) AS utility,
              COUNT(DISTINCT e.source) AS n_sources, MAX(e.source) AS one_source,
              (SELECT COUNT(*) FROM leak_events le WHERE le.session_id = e.session_id) AS leaks,
              -- The session's opening summary as a title. Skip buildSummary's
              -- placeholder sentinels so a tool-only / empty opening turn doesn't
              -- title the session; take the next real prompt instead. Summaries
              -- are already secret-scrubbed at capture, so no leak enters a title.
              (SELECT t.summary FROM exchanges t
                 WHERE t.session_id = e.session_id
                   AND t.summary IS NOT NULL AND t.summary != ''
                   AND t.summary NOT IN (${SENTINEL_SQL})
                 ORDER BY t.ts_request ASC, t.id ASC LIMIT 1) AS title
       FROM exchanges e GROUP BY e.session_id
       ORDER BY last_ts DESC LIMIT ?`,
      [limit],
    )
    .map((r) => ({
      sessionId: r.session_id as string,
      agent: (r.agent as string) ?? undefined,
      provider: (r.provider as string) ?? undefined,
      model: (r.model as string) ?? undefined,
      firstTs: r.first_ts as number,
      lastTs: r.last_ts as number,
      calls: r.calls as number,
      leaks: (r.leaks as number) ?? 0,
      source: (r.n_sources as number) > 1 ? "mixed" : ((r.one_source as string) ?? "wire"),
      title: (r.title as string) ?? undefined,
      utility: Boolean(r.utility),
      demo: r.agent === DEMO_AGENT,
    }));
}

export interface SessionHeadline { title?: string; agent?: string }

// Title + agent for a SET of sessions in one query — the leaks CLI groups its
// log by session and needs a headline per group (one query, not N). Same
// sentinel-skipping title pick as listSessions. Sessions with a leak event but
// no surviving exchanges (retention aged the calls out, 7d, before the event,
// 90d) simply don't appear in the map — the caller falls back to a placeholder.
export function sessionHeadlines(store: Store, sessionIds: string[]): Map<string, SessionHeadline> {
  const out = new Map<string, SessionHeadline>();
  if (sessionIds.length === 0) return out;
  const placeholders = sessionIds.map(() => "?").join(",");
  const rows = store.queryAll<Record<string, unknown>>(
    `SELECT e.session_id AS sid,
       (SELECT t.summary FROM exchanges t
          WHERE t.session_id = e.session_id
            AND t.summary IS NOT NULL AND t.summary != ''
            AND t.summary NOT IN (${SENTINEL_SQL})
          ORDER BY t.ts_request ASC, t.id ASC LIMIT 1) AS title,
       (SELECT a.agent FROM exchanges a
          WHERE a.session_id = e.session_id AND a.agent IS NOT NULL
          ORDER BY a.ts_request ASC LIMIT 1) AS agent
     FROM exchanges e
     WHERE e.session_id IN (${placeholders})
     GROUP BY e.session_id`,
    sessionIds,
  );
  for (const r of rows) {
    out.set(r.sid as string, {
      title: (r.title as string) ?? undefined,
      agent: (r.agent as string) ?? undefined,
    });
  }
  return out;
}

export interface SessionTurn {
  id: string; // call id — the transcript links each turn back to its call
  tsRequest: number;
  model?: string;
  source: string;
  status?: number;
  messages: DisplayMessage[]; // only what this turn ADDED (see delta note above)
  responseText: string | null;
  /** Original capture row when a late-stitched Claude response is displayed
   *  on a later request boundary. Keeps that response's raw bytes reachable. */
  responseSourceId?: string;
  /** Tool calls the model made in THIS turn's response — the "what was sent
   *  back" half the transcript used to show one turn late (as request echoes). */
  responseCalls: ToolAction[];
  leaks: DetailLeak[];
  /** Leaks detected on the NEXT request, where this response's content (tool
   *  args, echoed text) is actually scanned — used to highlight the response
   *  section. Display-only; the leak event stays pinned to the next call. */
  responseLeaks: DetailLeak[];
}

export interface SessionView {
  sessionId: string;
  system: string | null; // shown once, from the first call that carries one
  turns: SessionTurn[];
  truncated: boolean; // true when the session has more calls than the cap
  // Served with the transcript so the badge doesn't depend on HOW the user
  // navigated here (sessions tab, feed row, call detail, deep link).
  utility: boolean; // every call is a stateless one-shot
  demo: boolean;
}

// One session as a conversation. Reuses buildDetail per call so the transcript
// shows the same parsed messages/response/leak highlights as the detail view.
export function buildSessionTurns(store: Store, sessionId: string, cap = 200): SessionView {
  const ids = store.queryAll<{ id: string; endpoint: string | null; prompt_key: string | null }>(
    `SELECT id, endpoint, prompt_key FROM exchanges WHERE session_id = ? ORDER BY ts_request ASC, id ASC LIMIT ?`,
    [sessionId, cap + 1],
  );
  const truncated = ids.length > cap;
  const turns: SessionTurn[] = [];
  // Row facts the subscription sequencer below keys on; SessionTurn stays the
  // render shape (the client has no use for endpoints).
  const rowMeta = new Map<SessionTurn, RowMeta>();
  let system: string | null = null;
  let prevWire: Message[] = [];
  let prevResponseText: string | null = null;
  let lastWireTurn: SessionTurn | undefined;
  for (const { id, endpoint, prompt_key } of ids.slice(0, cap)) {
    const call = store.getCall(id);
    if (!call) continue;
    const d = buildDetail(call, leakSpansFor(store, id));
    system ??= d.system;
    let messages = d.messages;
    if (d.source === "otel" && messages.length === 0 && d.requestRaw) {
      // Legacy Mode B rows (captured before display_messages existed) still
      // have their scan text — show it as one block rather than an empty turn.
      // Labeled by what the content IS (the request: prompt + tool inputs);
      // provenance ("self-reported") is the session/turn chip's job, not this.
      messages = [{ role: "request", content: d.requestRaw }];
    }
    if (d.source === "wire") {
      // Show only the tail this call added on top of the previous wire call's
      // history. Guard against a shrunk/reshaped history (compaction, branch,
      // retry): if the recorded prefix doesn't actually match, fall back to
      // the newest message rather than mis-attributing old ones as new.
      const from = wireDeltaIndex(messages, prevWire);
      if (from != null) {
        messages = messages.slice(from);
      } else if (messages.length > 0) {
        messages = messages.slice(-1);
      }
      // Resolve this turn's request-side tool items against the PREVIOUS wire
      // turn's response. An fc echo the previous response already DISPLAYED
      // (matched by call_id) is dropped: the call card sits one card up, at
      // the end of that turn's response section, so call and result read
      // adjacently across the turn boundary — repeating the card here would
      // be the duplication the delta view exists to kill. The ▸ details and
      // raw views keep the resent bytes. Guards: an UNMATCHED echo stays
      // visible (unparseable/truncated previous response — a wrong drop must
      // be impossible by construction), and NOTHING is dropped from a turn
      // that carries a detected secret — the request copy is where a secret
      // in tool args is scanned (R7). That's a turn-level check on purpose: it
      // makes R7 hold at the drop site itself, rather than leaning on a
      // value-match (which escaping could defeat) plus the leak-not-visible
      // note downstream. A result that lost its tool name (previous_response_id
      // -chained clients send no fc echo to pair with) borrows name + detail
      // from the call it answers.
      const prevCalls = lastWireTurn?.responseCalls ?? [];
      if (prevCalls.length > 0) {
        const turnHasLeak = d.leaks.length > 0;
        messages = messages
          .map((m) => {
            if (m.kind === "result" && !m.tool && m.callId) {
              const origin = prevCalls.find((c) => c.callId === m.callId);
              if (origin) return { ...m, tool: sanitizeTool(origin.tool), detail: origin.detail };
            }
            return m;
          })
          .filter((m) => {
            const isEcho =
              m.kind === "call" && m.callId && prevCalls.some((c) => c.callId === m.callId);
            return !isEcho || turnHasLeak;
          });
      }
      // Stateless APIs echo the previous RESPONSE back as the next request's
      // assistant message — new to the wire history, but the reader just read
      // it one card up. Drop the leading echo (exact match only; anything
      // reworded stays visible). The raw view keeps every byte.
      // R7 guard: NEVER drop an echo that carries a leak. A secret first seen
      // in a response isn't a leak there (responses aren't request-scanned),
      // so this resend is the ONLY place the transcript can highlight it —
      // dropping it would show "secret sent" with nothing highlighted.
      const echoHasLeak =
        messages.length > 0 && d.leaks.some((l) => l.value && messages[0]!.content.includes(l.value));
      if (
        messages.length > 0 && prevResponseText !== null && !echoHasLeak &&
        messages[0]!.role === "assistant" && messages[0]!.content === prevResponseText
      ) {
        messages = messages.slice(1);
      }
      // Only advance the baseline on a turn that actually parsed. A truncated /
      // unparseable wire body yields 0 messages; clobbering prevWire with [] would
      // make the NEXT turn re-show its whole history as new (the repetition this
      // delta exists to kill). Keep the last good history as the diff base.
      if (d.messages.length > 0) prevWire = d.messages;
      prevResponseText = d.responseText ?? prevResponseText;
    }
    const turn: SessionTurn = {
      id: d.id,
      tsRequest: d.tsRequest,
      model: d.model,
      source: d.source,
      status: d.status,
      messages,
      responseText: d.responseText,
      responseCalls: d.responseCalls,
      leaks: d.leaks,
      responseLeaks: [],
    };
    turns.push(turn);
    rowMeta.set(turn, {
      endpoint: endpoint ?? "",
      promptKey: prompt_key,
      responseTs: call.tsResponse ?? call.tsRequest,
    });
    if (d.source === "wire") lastWireTurn = turn;
  }
  // Backward leak propagation (R7): a secret inside a response (tool args,
  // echoed text) is only ever SCANNED on the next request — so the turn that
  // DISPLAYS that content (its response section) must highlight with the next
  // turn's leak values, or the first render site would show it unmarked.
  // Wire-to-wire, like the resent stamping above: a Mode B row interposed
  // between two wire calls (tool hooks fire between response and next
  // request) must not absorb the leaks meant for the wire response card.
  let prevWireIdx = -1;
  for (let i = 0; i < turns.length; i++) {
    if (turns[i]!.source !== "wire") continue;
    if (turns[i]!.leaks.length > 0 && prevWireIdx >= 0) {
      turns[prevWireIdx]!.responseLeaks = turns[i]!.leaks;
    }
    prevWireIdx = i;
  }
  const utility =
    ids.length > 0 &&
    Boolean(
      store.queryAll<{ u: number }>(
        `SELECT MIN(COALESCE(one_shot, 0)) AS u FROM exchanges WHERE session_id = ?`,
        [sessionId],
      )[0]?.u,
    );
  const demo = Boolean(
    store.queryAll<{ demo: number }>(
      `SELECT EXISTS(SELECT 1 FROM exchanges WHERE session_id = ? AND agent = ?) AS demo`,
      [sessionId, DEMO_AGENT],
    )[0]?.demo,
  );
  return {
    sessionId,
    system,
    turns: sequenceModeBTurns(store, sessionId, turns, rowMeta),
    truncated,
    utility,
    demo,
  };
}

// ---- Subscription turn sequencing ----
//
// Pi's wire transcript uses provider-call boundaries: response N asks for a
// tool, request N+1 carries its result. Claude/Codex subscription telemetry
// arrives in different rows (turn reports plus per-tool reports), but the UI
// must keep the same boundary model. The old projection instead appended every
// tool card to the first prompt's REQUEST and deleted the tool rows from the
// transcript/feed. Besides changing under a live user's feet, that collapsed a
// 19-row Codex session to one turn and could discard later Claude responses
// sharing a prompt.id.
//
// This is display-only: stored/scanned rows remain untouched. Codex tool rows
// become the next request in a chain, with the following tool call on their
// response side; Claude hook results join the next reported response row. Every
// source card/action carries sourceId, and unplaceable rows remain standalone.
type RowMeta = { endpoint: string; promptKey: string | null; responseTs: number };

function cardAction(card: DisplayMessage, sourceId: string): ToolAction {
  return {
    tool: card.tool ?? "tool",
    args: card.content || undefined,
    detail: card.detail,
    callId: card.callId,
    sourceId,
  };
}

// The subset of `leaks` whose secret value actually appears in these cards.
// A split tool row shows its command on one turn (the response call) and its
// result on the next (the request) — this routes each secret's highlight to the
// turn that displays it, so a moved card still highlights and an unrelated turn
// gets no phantom "secret sent" flag. Never used to DECIDE visibility: a leak
// always keeps its own row's feed line regardless (R7).
function leaksIn(leaks: DetailLeak[], cards: DisplayMessage[]): DetailLeak[] {
  if (leaks.length === 0) return leaks;
  const text = cards.map((c) => `${c.content ?? ""}\n${c.detail ?? ""}`).join("\n");
  return leaks.filter((l) => l.value && text.includes(l.value));
}

function sequenceModeBTurns(
  store: Store,
  sessionId: string,
  turns: SessionTurn[],
  rowMeta: Map<SessionTurn, RowMeta>,
): SessionTurn[] {
  const links = new Map<string, { promptKey: string; ordinal: number; seq: number }>();
  for (const r of store.queryAll<{ link_key: string; prompt_key: string; ordinal: number; seq: number }>(
    `SELECT link_key, prompt_key, ordinal, seq FROM turn_link WHERE session_id = ?`,
    [sessionId],
  )) {
    links.set(r.link_key, { promptKey: r.prompt_key, ordinal: r.ordinal, seq: r.seq });
  }
  // Codex turn index: the Nth prompt row per prompt_key, matching rollout link
  // ordinals. Claude prompt ids span several provider calls, so its repeated
  // rows must remain distinct and never go through this occurrence merge.
  const occurrence = new Map<string, number>();
  const index = new Map<string, SessionTurn>();
  const anchorsAsc: Array<{ ts: number; turn: SessionTurn }> = [];
  for (const t of turns) {
    const m = rowMeta.get(t);
    if (!m || m.endpoint !== "otel:codex:user_prompt") continue;
    if (m.promptKey) {
      const n = occurrence.get(m.promptKey) ?? 0;
      occurrence.set(m.promptKey, n + 1);
      index.set(`${m.promptKey}#${n}`, t);
    }
    anchorsAsc.push({ ts: t.tsRequest, turn: t });
  }
  const coveringTurn = (ts: number): SessionTurn | null => {
    for (let i = anchorsAsc.length - 1; i >= 0; i--) {
      if (anchorsAsc[i]!.ts <= ts) return anchorsAsc[i]!.turn;
    }
    return null;
  };
  const codexGroups = new Map<SessionTurn, Array<{ turn: SessionTurn; ts: number; seq?: number }>>();
  const codexOrder = new Map<SessionTurn, SessionTurn[]>();
  const codexChildren = new Set<SessionTurn>();
  for (const t of turns) {
    const m = rowMeta.get(t);
    if (!m?.endpoint.startsWith("otel:codex:tool_result:")) continue;
    const link = t.messages.reduce<
      { promptKey: string; ordinal: number; seq: number } | null
    >((got, c) => got ?? (c.callId ? links.get(`call:${c.callId}`) ?? null : null), null);
    const target = link ? index.get(`${link.promptKey}#${link.ordinal}`) : coveringTurn(t.tsRequest);
    if (!target || target === t) continue;
    const list = codexGroups.get(target) ?? [];
    list.push({ turn: t, ts: t.tsRequest, seq: link?.seq });
    codexGroups.set(target, list);
  }

  for (const [target, list] of codexGroups) {
    const linkedByTs = list.filter((a) => a.seq !== undefined).sort((x, y) => x.ts - y.ts);
    const tier = (a: { ts: number; seq?: number }): [number, number] => {
      if (a.seq !== undefined) return [a.seq, 0];
      let anchor = -1;
      for (const l of linkedByTs) {
        if (l.ts <= a.ts) anchor = l.seq!;
        else break;
      }
      return [anchor, 1];
    };
    const ordered = list
      .map((a) => ({ a, k: tier(a) }))
      .sort((x, y) => x.k[0] - y.k[0] || x.k[1] - y.k[1] || x.a.ts - y.a.ts)
      .map(({ a }) => a.turn);
    codexOrder.set(target, ordered);
    for (const t of ordered) codexChildren.add(t);
    const calls = ordered.map((t) => t.messages.filter((m) => m.kind === "call").map((m) => cardAction(m, t.id)));
    const finalResponse = target.responseText;
    const finalResponseLeaks = [...target.responseLeaks];
    target.responseText = null;
    target.responseCalls.push(...calls[0]!);
    target.responseLeaks = [...ordered[0]!.leaks];
    for (let i = 0; i < ordered.length; i++) {
      const t = ordered[i]!;
      // This row's output is the next provider request. Keep any unusual
      // non-call card rather than guessing it away; only the call half moves.
      t.messages = t.messages
        .filter((m) => m.kind !== "call")
        .map((m) => ({ ...m, sourceId: t.id }));
      t.responseCalls = i + 1 < calls.length ? calls[i + 1]! : [];
      t.responseText = i === ordered.length - 1 ? finalResponse : null;
      t.responseLeaks = i === ordered.length - 1 ? finalResponseLeaks : [...ordered[i + 1]!.leaks];
    }
  }

  // Claude already yields one response-bearing row per reported model cycle.
  // Move tool calls to that row's RESPONSE, then carry PostToolUse results
  // forward into the next same-prompt cycle's REQUEST. Repeated prompt.id rows
  // are intentionally preserved: they contain distinct responses.
  const dropped = new Set<SessionTurn>();
  let lastClaude: SessionTurn | null = null;
  // Hook rows waiting to become the next cycle's request. `callShown` records
  // whether this hook's command was already surfaced (the turn event listed it,
  // or it was recovered onto a response). If not, the command card must survive
  // rather than being stripped to the bare result — capture must stay visible.
  let pending: Array<{ turn: SessionTurn; promptKey?: string; callShown: boolean }> = [];
  // Calls already on the current turn's response, per tool, so a hook that
  // merely re-reports a call the turn event listed isn't shown twice. Counted
  // DOWN as hooks match it (seeded when the turn becomes current) — no re-scan
  // of the growing responseCalls array per hook.
  let reportedByTool = new Map<string, number>();
  const seedReported = (t: SessionTurn) => {
    reportedByTool = new Map();
    for (const c of t.responseCalls) reportedByTool.set(c.tool, (reportedByTool.get(c.tool) ?? 0) + 1);
  };
  const mergePending = (target: SessionTurn, promptKey: string | null): void => {
    // Only a CONTINUATION cycle (one carrying no fresh user prompt) may absorb a
    // prior cycle's tool results — a NEW prompt's turn must never show the
    // previous turn's output as its own request (the row would render above that
    // turn's user message). A keyed hook still needs a matching prompt; an
    // unlinked hook rides any continuation.
    if (target.messages.some((c) => c.role === "user")) return;
    const kept: typeof pending = [];
    const cards: DisplayMessage[] = [];
    for (const p of pending) {
      if (p.promptKey && promptKey && p.promptKey !== promptKey) { kept.push(p); continue; }
      const results = p.turn.messages.filter((c) => c.kind === "result");
      cards.push(...results.map((c) => ({ ...c, sourceId: p.turn.id })));
      // The result carries this row's output-side secrets; an input-side secret
      // rode the call card and highlights where that card is shown (above).
      target.leaks.push(...leaksIn(p.turn.leaks, results));
      dropped.add(p.turn);
    }
    if (cards.length) target.messages.unshift(...cards);
    pending = kept;
  };
  for (const t of turns) {
    const m = rowMeta.get(t);
    if (!m) continue;
    if (m.endpoint === "otel:claude_code.turn") {
      mergePending(t, m.promptKey);
      const callCards = t.messages.filter((card) => card.kind === "call");
      t.messages = t.messages.filter((card) => card.kind !== "call");
      t.responseCalls.push(...callCards.map((card) => cardAction(card, t.id)));
      lastClaude = t;
      seedReported(t);
      continue;
    }
    if (!m.endpoint.startsWith("otel:tool_output:")) continue;
    const rowLink = links.get(`row:${t.id}`);
    const callCards = t.messages.filter((card) => card.kind === "call");
    let callShown = false;
    if (lastClaude && callCards.length) {
      // Claude can report a call both in its turn event and in PostToolUse.
      // Skip a card the turn already listed (matched by tool occurrence);
      // recover the rest so an under-reported command isn't lost — and carry the
      // hook's matching leaks onto the response so the recovered arg still
      // highlights (the turn row never scanned this arg). The codex chain sets
      // responseLeaks the same way — keep the two paths symmetric (R7).
      for (const card of callCards) {
        const tool = card.tool ?? "tool";
        const dup = reportedByTool.get(tool) ?? 0;
        if (dup > 0) {
          reportedByTool.set(tool, dup - 1);
        } else {
          lastClaude.responseCalls.push(cardAction(card, t.id));
          lastClaude.responseLeaks = [...lastClaude.responseLeaks, ...leaksIn(t.leaks, [card])];
        }
      }
      callShown = true;
    }
    pending.push({ turn: t, promptKey: rowLink?.promptKey, callShown });
  }

  // Results with no following cycle stay as their own pending request. Strip a
  // hook to its result once its command has been shown elsewhere; keep the
  // command card when nothing else did (a hook before any turn) so the tool
  // input never vanishes from the transcript.
  for (const p of pending) {
    const results = p.turn.messages.filter((c) => c.kind === "result");
    p.turn.messages = (p.callShown && results.length ? results : p.turn.messages)
      .map((c) => ({ ...c, sourceId: p.turn.id }));
    p.turn.responseText = null;
    p.turn.responseCalls = [];
  }

  const out: SessionTurn[] = [];
  for (const t of turns) {
    if (dropped.has(t) || codexChildren.has(t)) continue;
    out.push(t);
    const children = codexOrder.get(t);
    if (children) out.push(...children.filter((child) => !dropped.has(child)));
  }

  // A response-only Claude OTLP batch is stitched onto the original prompt
  // row in storage. That preserves capture, but the row keeps its old request
  // timestamp: a final answer arriving after several tool cycles would render
  // above them. Place only those late-stitched responses on the latest empty
  // response boundary for the SAME prompt. Exact hook links make this
  // fail-closed: without a matching later boundary, the stored placement wins.
  const claudePrompt = (t: SessionTurn): string | null => {
    const m = rowMeta.get(t);
    if (!m) return null;
    if (m.endpoint === "otel:claude_code.turn") return m.promptKey;
    if (m.endpoint.startsWith("otel:tool_output:")) return links.get(`row:${t.id}`)?.promptKey ?? null;
    return null;
  };
  for (const source of out) {
    const m = rowMeta.get(source);
    if (
      m?.endpoint !== "otel:claude_code.turn" || !m.promptKey ||
      !source.responseText || m.responseTs <= source.tsRequest
    ) continue;
    let target: SessionTurn | null = null;
    for (const candidate of out) {
      if (
        candidate.tsRequest <= source.tsRequest || candidate.tsRequest > m.responseTs ||
        candidate.responseText !== null || candidate.responseCalls.length > 0 ||
        claudePrompt(candidate) !== m.promptKey
      ) continue;
      target = candidate;
    }
    if (!target) continue;
    target.responseText = source.responseText;
    target.responseSourceId = source.id;
    target.model = source.model ?? target.model;
    source.responseText = null;
  }
  return out;
}

// Where does this request's NEW content start, given the previous wire call's
// history? Returns the slice index when the recorded history truthfully
// extends the previous one; null when no claim can be made (first call,
// rewritten history, shrunk history) — callers choose their own fallback.
// Shared by the transcript AND the call-detail view so both surfaces agree on
// what "new this turn" means (single audit site).
export function wireDeltaIndex(cur: Message[], prev: Message[]): number | null {
  // An empty prev is a valid base: the session's first call is ALL new.
  return cur.length > prev.length && sameHistoryPrefix(cur, prev) ? prev.length : null;
}

// Cheap prefix check: same roles + same content lengths. Full string compares
// over a 200-call session would be O(history²) bytes; role+length catches the
// real mismatch cases (compaction rewrote history, branch, different session
// glued by the resolver) without that cost.
function sameHistoryPrefix(cur: Message[], prev: Message[]): boolean {
  for (let i = 0; i < prev.length; i++) {
    const a = cur[i];
    const b = prev[i];
    if (!a || a.role !== b!.role) return false;
    const al = typeof a.content === "string" ? a.content.length : JSON.stringify(a.content)?.length;
    const bl = typeof b!.content === "string" ? b!.content.length : JSON.stringify(b!.content)?.length;
    if (al !== bl) return false;
  }
  return true;
}
