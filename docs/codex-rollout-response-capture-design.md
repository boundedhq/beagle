# Codex rollout-file response capture

**Status:** Design — **Phase 0 spike validated live (2026-07-20, Codex 0.144.6).**
All §8 questions resolved GO; ready for Phase 1 implementation.
**Scope:** Close the one gap in Codex-subscription capture — the model's answer —
by reading the assistant messages Codex already writes to its local rollout log
and stitching them onto the self-reported (OTel) turn rows Beagle already builds.
No TLS interception, no CA, no new trust ask.
**Out of scope (named, deferred):** wire-verified Codex capture (that's the
CA-trust design, `docs/wire-capture-consent-design.md`); reasoning/thinking
capture; tool-call reconciliation between rollout and OTel; non-Codex agents.

---

## 1. The gap, precisely

Codex on a "Sign in with ChatGPT" subscription can't be wire-redirected, so
Beagle captures it via Codex's OpenTelemetry self-report (`codex.*` events,
`src/parsers/otlp-map.ts`). That self-report is rich on the **outbound** side —
it carries the user prompt plus every tool call's arguments **and** output (the
full leak surface Beagle scans and alerts on) plus token counts. But it has a
hard vendor limit, verified live against 0.144.x and re-confirmed here: **the
`codex.*` event vocabulary contains no assistant-message event.** The model's
answer is never self-reported. Codex-subscription turns therefore render in the
viewer with a question and no answer.

The fix does not require seeing the wire. Codex **persists the full assistant
answer to a local file itself** — the session *rollout log*. Reading that file
and attaching the answer to the turn row Beagle already has closes the gap
entirely, at self-reported fidelity, with the machinery Beagle shipped for
Claude Code cross-batch stitching (PR #91) reused almost verbatim.

### 1.1 Fidelity classification (normative)

This stays **self-reported capture** — the row badge does **not** change to
wire-verified. The rollout is Codex's own post-hoc record of the turn, the same
fidelity class as its OTel self-report (arguably one step further from the wire,
since it's disk state written after the fact). We are **completing** a
self-reported turn, not upgrading it.

That is acceptable specifically because the piece we're adding is the
**response**, which is *inbound* and never Beagle's leak surface. Beagle alerts
on outbound content; the answer only becomes a leak vector once it's echoed into
the next request, which the OTel path already captures as that turn's context.
So a self-reported answer, honestly badged, is the right fidelity for the job.
Wire-verification of Codex responses remains the separate CA-trust design.

---

## 2. What Codex writes, and where (verified)

Path (per session): `~/.codex/sessions/YYYY/MM/DD/rollout-<ISO-ts>-<uuid>.jsonl`,
where `<uuid>` is the session id. `CODEX_HOME` overrides `~/.codex`; Beagle
launches Codex, so it controls/knows that env and resolves the base the same way.

The file is JSONL, appended as the session progresses. Top-level line types
observed on 0.144.6:

| `type` | Carries |
|---|---|
| `session_meta` | `id`, `session_id` (identical UUIDv7 = filename uuid), `cli_version`, `originator`, `source`, `model_provider`, … (one per file, first line) |
| `turn_context` | `turn_id`, `model`, `effort`, `cwd`, sandbox/approval policy (one per turn) |
| `response_item` | the durable conversation items — `message` (roles: developer/user/assistant), `reasoning`, `function_call`(+`_output`), `custom_tool_call`(+`_output`) |
| `event_msg` | the TUI event feed — `user_message`, `agent_message`, `token_count`, `task_started`/`task_complete`, `agent_reasoning`, … |
| `world_state` | operational, no content |

**The answer** is `response_item` where `payload.type == "message"` and
`payload.role == "assistant"`; its text is the `payload.content[]` parts of type
`output_text`, concatenated. (It is *also* echoed as `event_msg`/`agent_message`
— same text — but `response_item` is the canonical, structured, role-tagged
form, so we read that and ignore the event echo to avoid double-counting.)

A single turn's lines, in order (real capture, content elided):

```
turn_context           turn_id=…, model=gpt-5.6-sol
response_item message  role=user       (the prompt)
event_msg   user_message               (echo of the prompt)
event_msg   agent_message              (echo of the answer)
response_item message  role=assistant  (THE ANSWER — output_text)   ← we read this
event_msg   token_count
event_msg   task_complete
```

`developer`-role messages (base instructions, AGENTS.md) and `reasoning` items
are **not** the answer and are ignored for V1.

---

## 3. High-level design

```
 beagle run/watch codex
        │  (launches codex with Beagle's OTel env — unchanged)
        ▼
   codex process ──emits──► OTel codex.* events ──► OtlpReceiver ──► ingestOtel
        │                     (prompt, tool i/o, tokens)              │
        │                                                     creates TURN ROW
        └──writes──► ~/.codex/sessions/**/rollout-*.jsonl      (prompt_key set,
                          │  (full turn incl. assistant answer)   response empty)
                          ▼
                   RolloutTailer  ── for conversation.ids Beagle SAW via OTel ──┐
                     polls the file, extracts (user→assistant) pairs,           │
                     emits a RESPONSE-ONLY OtelCall per answer ─────────────────┘
                          │                                                      ▼
                          └──────────────────────────────────────────►  ingestOtel
                                                                    attachOtelResponse
                                                                  (session_id, prompt_key)
                                                                  → fills the turn row's
                                                                     answer, tokens, model
```

Two properties make this small:

1. **The turn row already exists** — OTel builds it, with alerting, unchanged.
   The tailer only supplies the missing response half.
2. **The stitch path already exists** — `ingestOtel`'s response-only branch
   (`daemon.ts:571`) calls `store.attachOtelResponse(session_id, prompt_key)`.
   A rollout-sourced response is just another response-only `OtelCall`. No new
   store method, no new daemon branch, **no core LOC**.

The only OTel-side change: the Codex mapper must stamp a `prompt_key` on the
user-prompt row so there's something to attach to (§4).

---

## 4. Correlation — the crux

We need two keys, both derivable **independently and identically** from the OTel
side and the rollout side.

### 4.1 Session key: `conversation.id` ⟷ rollout `session_id`

Codex OTel events carry `conversation.id`; the rollout's `session_meta` carries
`session_id` (= the filename uuid). **Confirmed byte-identical live (§8.1)**,
including across `codex resume` (which appends to the same file and keeps the
same id — no fork).

Locating the file for a conversation: glob `rollout-*-<conversation.id>.jsonl`
under the sessions tree. Because resume reuses the same file, the glob suffices;
reading the file's `session_meta.session_id` is a cheap belt-and-suspenders
confirmation, not a requirement.

### 4.2 Turn key: hash of the normalized user-prompt text

Codex OTel has **no** per-turn id (only `conversation.id`) — confirmed against
the live attribute set and the test fixtures. The rollout's `turn_id` can't help
because OTel never emits it. So the per-turn join is derived from the one thing
both sources hold: **the user prompt text.**

```
promptKey = sha256(normalize(userPromptText))            // first N hex chars
sessionId = conversation.id
```

- **OTel side:** `buildCodexCall` for `codex.user_prompt` sets
  `promptId = codexPromptKey(prompt)` (today it sets none). The insert path
  already carries `promptId → prompt_key` (`daemon.ts:627`), so the turn row
  gets the key for free. Tool-result rows keep `promptId` undefined — only the
  prompt row is an attach target.
- **Rollout side:** the tailer pairs each assistant `message` with the nearest
  preceding user `message`, computes the same `codexPromptKey(userText)`, and
  emits a response-only call with that `promptId`.

`attachOtelResponse` then matches `(session_id, prompt_key)` unchanged. Its
existing `ORDER BY ts_request ASC … bytes_resp IS NULL` query already resolves
the only ambiguous case — the *same prompt typed twice in one session* — by
attaching answers to the identical-prompt rows in arrival order. One shared
helper `codexPromptKey(text)` guarantees the two sides compute byte-identical
keys.

### 4.3 Why hash-of-prompt, not ordinal or timestamp

| Strategy | Failure mode | Verdict |
|---|---|---|
| **Prompt-text hash** | texts differ after normalization → **no stitch** (turn keeps prompt+tools; answer absent). Fails *safe*. | **chosen** |
| Turn ordinal (k-th prompt) | OTel and rollout count turns differently (developer msgs, approvals, compaction) → **wrong answer on wrong turn**. Fails *unsafe* (mis-attribution). | rejected |
| Timestamp nearest-after | clock/precision skew between the two sources → occasional mis-pair. Fails *unsafe*. | fallback only |

For a transparency tool, mis-attributing an answer to the wrong prompt is a
correctness violation; a missing answer is a graceful degradation. Hash-of-prompt
is the only strategy whose worst case is "no stitch." The spike (§8.2) confirmed
the two prompt strings are byte-identical, so this is the primary and only join;
**timestamp-nearest-after** is retained only as a future escape hatch if a Codex
version ever diverges the strings.

Normalization (shared helper): trim, collapse internal whitespace runs to single
spaces, NFC. Deliberately conservative — over-normalizing raises collision risk;
under-normalizing raises miss risk. Spike used `" ".join(s.split())` and matched
2/2; NFC added for non-ASCII safety.

---

## 5. The RolloutTailer (lifecycle & scoping)

A per-conversation reader, created lazily, self-retiring.

- **Trigger & authorization (privacy crux).** Beagle reads a rollout file
  **only for a `conversation.id` it observed via its own OTel receiver** — i.e.
  a Codex run Beagle launched with the OTel env. It never enumerates or reads
  Codex sessions Beagle didn't start. OTel activity is both the trigger and the
  authorization to touch that one file. (Reinforced by the fact that a
  Beagle-launched codex is the only one exporting to Beagle's loopback receiver.)
- **Read model.** Offset-tracked tail: keep the last parsed byte offset; on each
  poll, if the file grew, parse only whole newline-terminated lines past the
  offset (a trailing partial line waits for the next poll). Files are small
  (tens of KB typical), so a whole-file re-read with an emitted-set is an
  acceptable fallback if offset tracking proves fiddly.
- **Cadence.** Poll ~1.5 s while the conversation is active — matches the OTel
  batch delay (`OTEL_BLRP_SCHEDULE_DELAY=1000`), so the answer stitches in a
  beat after the turn's OTel batch, the same UX as Claude Mode B cross-batch
  stitching.
- **Retirement.** A tailer self-closes after a grace period with no new rollout
  lines *and* no new OTel activity for its conversation (e.g. 30 s). This needs
  no explicit run-end signal, so it works identically for `beagle run` (one
  foreground session) and `beagle watch` (persistent daemon, many sessions over
  time). Bounded set of live tailers = number of concurrently active Codex
  conversations.
- **Emitted-set.** Dedup already-emitted answers by `(conversation.id,
  promptKey)` so re-reads never double-emit. (Second identical-prompt turns get
  distinct keys only if their prompts differ; identical prompts are handled by
  the attach query's arrival-order rule — the emitted-set is keyed by
  `promptKey + occurrence-index` to keep them distinct.)

### 5.1 Ordering race (prompt row must exist before the answer attaches)

`attachOtelResponse` needs the turn row present when the response arrives. Usual
ordering favors it — the OTel `user_prompt` fires at turn start, the rollout
answer at turn end — but the two come from **independent async sources** (the
loopback OTLP receiver vs a polled file), so "row first" is not guaranteed, and
the margin is thin (OTel batch ~1 s, flush ~1.5 s, poll ~1.5 s). This race is
therefore treated as **expected**, not hypothetical (Phase 1, not 1.5).

Handling, in concert with §6.1(a): a response that fails to attach is **held in
the tailer's pending set and retried on subsequent polls** (bounded — a few
attempts / ~10 s), not inserted as a standalone row. Once the prompt row exists,
a retry attaches it. If it never attaches (prompt row genuinely absent — e.g.
OTel dropped that turn), it is **dropped**, not orphaned. This makes the tailer
idempotent across daemon restarts too: re-emitted answers for already-answered
turns fail the `bytes_resp` guard and drop.

### 5.2 Where the tailer runs, and finding the sessions dir

The tailer must run **daemon-side**: `beagle watch codex` has no per-run CLI
process (the daemon/shim spawns codex), so a CLI-side tailer would silently give
watch-mode users no answers. Daemon-side reuses `ingestOtel` directly. Two
consequences the build must honor:

- **`CODEX_HOME` resolution (as built).** `codexSessionsRoot()` reads
  `process.env.CODEX_HOME` (else `~/.codex`) + `/sessions`. The CLI spreads its
  env into the daemon spawn (`commands.ts`), so a per-run `CODEX_HOME` reaches the
  daemon in the common `beagle run` path, and in watch mode the daemon itself
  spawns codex. A service daemon started with a different env falls back to
  `~/.codex`; if that's wrong the tailer finds no file → answer absent (fail-open,
  top row of §7). *Threading `CODEX_HOME` explicitly through run registration is a
  future hardening; env-inheritance covers the common case and needs no new
  control-socket surface.*
- **Drain on shutdown (the PR #91 invariant) — done.** The tailer's answers go
  through `emit: (calls) => void d.track(d.ingestOtel(calls))`, so `stop()` drains
  them before `store.close()`, and `CodexRolloutWatcher.stop()` (clearing every
  tailer's interval) runs in `Daemon.stop()` before the drain.

**Locate once, then poll that path.** The tailer resolves the file
(`<root>/**/rollout-*-<conversation.id>.jsonl`, newest match) lazily on its first
poll that finds it, then reads that one path. Doing the locate inside the tailer
(rather than the watcher) means a beat-late file is retried on the tailer's own
cadence instead of re-walking the tree on every OTel event.

---

## 6. Data flow into the existing pipeline

The response-only `OtelCall` the tailer emits:

```
{ source:'otel', origin:'codex-rollout',            // NEW discriminator — see (a),(b)
  agent:'codex', provider:'openai',
  convId: <conversation.id>, promptId: <codexPromptKey(userText)>,
  request:  { bodyBytes: <empty>, messages: [] },     // response-only
  response: { text: <answer>, bodyBytes: <answer utf8> },
  model: undefined,  meta: { tsRequest, tsResponse: <rollout line ts> } }  // tokens/model omitted (§8.4)
```

Fed through the **existing** `ingestOtel(calls)` (`daemon.ts:473`). Because
`request.bodyBytes` is empty and `response.text` is set, it takes the
response-only branch, scans the response **for redaction only** (inbound never
alerts), then `attachOtelResponse` fills the turn row's `ts_response`,
`bytes_resp`, response body, and composed summary (`"question" → answer`).
Redact-on-capture applies uniformly — a rollout answer is not a redaction hole.

**Tokens/model: tailer supplies neither (resolved §8.4).** OTel `codex.sse_event`
and the rollout `token_count` carry identical numbers, and OTel already carries
`model`; the tailer omits both so `attachOtelResponse`'s `COALESCE`/`addNullable`
keep the OTel-sourced values. Answer text + `tsResponse` only.

### 6.1 Two REQUIRED deviations from the Claude Mode B path (review findings)

Reusing `ingestOtel` verbatim would be wrong in two ways. Both are why the emit
carries an `origin:'codex-rollout'` discriminator the daemon branch checks:

- **(a) Attach-or-DROP, never insert a standalone row.** Today the response-only
  branch (`daemon.ts:571`) falls through to `insertCall` when `attachOtelResponse`
  returns false, creating a detached answer row. For Claude that's a legitimate
  batch-split partial; for a codex rollout answer it is **harmful** — an answer
  with no question. Two ways it bites: the prompt/answer come from two independent
  async sources (OTel vs file), so the "row exists first" ordering is not
  guaranteed; and on **daemon restart** the tailer re-reads the file and re-emits
  already-answered turns, which the `bytes_resp IS NULL` guard blocks from
  re-attaching → today they would insert as **duplicate orphan rows**. Fix: when
  `origin=='codex-rollout'`, a failed attach **drops** (no insert). Combined with
  §5.1's bounded retry, a legitimately-early answer still lands once its row
  exists; a restart re-emit simply drops.
- **(b) Do NOT index the answer into search — now STRUCTURAL (resolved by PR #92).**
  The adjacent Mode B bug this design flagged (the OTel path indexed request **+
  response**, so a codex/Claude answer read as "sent") was fixed on `main` in PR
  #92: `ingestOtel`'s `searchText` is outbound-only and `attachOtelResponse` no
  longer has a `searchAppend` parameter at all — a stitch never touches the FTS
  index. So this deviation needs no per-rollout code: the answer is inbound and
  simply never indexed, for any stitch. (Earlier drafts passed an empty
  `searchAppend`; that parameter is gone post-merge.)

---

## 7. Failure modes (fail-open — a turn always renders)

| Failure | Behavior |
|---|---|
| Rollout file absent / unreadable / `CODEX_HOME` unknown to daemon (§5.2) | answer stays absent; turn still shows prompt+tools+tokens; badge self-reported. No error to the user. |
| `conversation.id != session_id` (a *future* Codex change; equal today per §8.1) | can't locate the file → answer absent. `session_meta`-scan locate is the escape hatch. Not possible on 0.144.x. |
| Prompt text mismatch (OTel vs rollout) | `promptKey` differs → no stitch → answer absent (safe). Byte-equal today (§8.2); timestamp fallback only if a future version diverges them. |
| Schema drift on a Codex update (renamed `response_item`/`output_text`) | parse defensively (array-guarded, unknown types skipped, like `otlp-map`); answer degrades to absent, never throws. Pinned to observed 0.144.x shape in tests. |
| Attach race / daemon restart re-emit (§5.1, §6.1a) | held & retried, then **dropped** if the prompt row never appears — never a standalone/duplicate row. |
| User disabled rollout logging (`history_mode`/config) | no file → answer absent. Rare; note in `beagle status` reasoning line if detectable. |
| Tailer poll error mid-session | swallowed per-poll; next poll retries; capture may lag, turn works. |

Self-reported-without-the-answer (today's behavior) is the floor this degrades
to. Nothing regresses.

---

## 8. Spike results — RESOLVED (2026-07-20)

Phase 0 ran live against Codex 0.144.6 (interactive TUI, ChatGPT-subscription
login) with its OTel exporter pointed at a loopback catcher and the rollout file
diffed against the captured OTLP bodies. Every §8 question is answered; the
approach is **GO**. Evidence: three driven sessions (two fresh multi-turn, one
resume); raw OTLP dumps + rollout files retained in scratch.

**8.1 — `conversation.id == session_id` — CONFIRMED (GO).** In a clean 2-turn
session, all three were byte-identical:
`OTLP conversation.id == rollout session_meta.session_id == filename uuid ==
019f8171-e92f-72f0-8333-6333cb5a8c0d`. **Resume does NOT fork:** `codex resume
--last` kept the *same* `conversation.id`, and **appended** the resumed turn to
the *same* rollout file (line count 25→41, still exactly one `session_meta`, no
new file). So `rollout-*-<conversation.id>.jsonl` filename-glob locates the file
even across resume; reading `session_meta` is a cheap confirmation, not a
requirement (§4.1 downgraded accordingly).

**8.2 — Prompt-text equality — CONFIRMED (primary join holds).** OTel
`codex.user_prompt.prompt` and the rollout real user `message` text were
**byte-identical**, proven two independent ways: (a) a driver artifact that
dropped the leading "R" (`eply…quokka`) appeared *identically corrupted* in both
sources; (b) a `.../ALPHA111/quit` concatenation likewise appeared identical in
both. Cross-source `sha256(normalize(prompt))[:16]` matched **2/2** on the clean
fresh run and **1/1** on the resume run; the injected `<environment_context>`
user message produced **no** OTel-side key and was correctly left unmatched. The
timestamp-nearest-after fallback (§4.3) is therefore **not needed** — kept only
as a future escape hatch if a Codex version ever diverges the two strings.

**8.3 — Per-turn flush timing — CONFIRMED (near-real-time).** Assistant `message`
lines appeared on disk **1.2–1.8 s after send, while the session was still
open** (measured across four completed turns). The ~1.5 s tailer poll is
validated; no "answers only at exit" fallback required.

**8.4 — Tokens/model ownership — RESOLVED: tailer is ANSWER-ONLY.** OTel
`codex.sse_event` and the rollout `token_count` carried *identical* numbers
(`input=14441, output=9, cached=9984 …`) and OTel already carries `model`
(`gpt-5.6-sol`) on both `user_prompt` and `sse_event`. The existing Codex OTel
mapper already attaches these. So the tailer supplies **only the answer text +
tsResponse** and passes `tokens/model` undefined; `attachOtelResponse`'s
`COALESCE`/`addNullable` then leave the OTel-sourced values intact. Prevents
double-counting.

**8.5 — Resolver convId stability — still a build-time unit-test check.** Not a
live-spike item. `attachOtelResponse` keys on `resolution.sessionId`, so the
resolver must map a given `conversation.id` to the same session id for both the
prompt call and the response-only call. Confirm with a unit test in Phase 1.

**8.6 — Interactive vs `exec` parity — CONFIRMED.** Both spike sessions were
interactive TUI and wrote the same `response_item` / `message` / `role=assistant`
/ `output_text` shape already observed on an `exec` session. Same writer.

### 8.7 — Bonus findings that shape the tailer

- **No turn key in OTel, ever.** The full `codex.user_prompt` attribute set is
  `{app.version, auth_mode, conversation.id, event.name, event.timestamp, model,
  originator, prompt, prompt_length, slug, terminal.type, user.account_id,
  user.email}` — **no** `prompt.id`/`turn_id`/ordinal. Hash-of-prompt is not just
  preferred, it's the *only* content-derivable per-turn join. (Confirms §4.3.)
- **PII is present and must not be read.** `user.email` and `user.account_id`
  ride `codex.user_prompt`; the tailer reads the rollout, not these, but the
  invariant stands: never read PII attributes (the OTel mapper already doesn't).
- **Turn structure for the tailer's pairing.** A turn is delimited by
  `event_msg task_started` / `turn_context` (carries an internal `turn_id`) …
  `event_msg task_complete`. Within it: zero-or-one injected
  `<environment_context>` user message (session start only) + `developer`-role
  base-instruction messages (both ignored), then the real `role=user` prompt,
  then the `role=assistant` answer. The validated pairing: **pair each assistant
  answer with the nearest preceding `role=user` message that does not start with
  `<environment_context>`** — verified correct 2/2 on distinct prompts. Even a
  mis-pair is safe: a wrong prompt hashes to a key no turn row holds → no attach,
  never a wrong attach.

---

## 9. Security & privacy considerations

- **No new secret surface.** The answer is already plaintext on the user's disk;
  Beagle reads what's there. No CA, no key material, no decryption.
- **Scoped reads only.** Beagle opens a rollout file **only** for a
  `conversation.id` it launched and saw via its own OTel receiver (§5). It never
  scans the sessions tree for unrelated Codex work. This is the privacy
  invariant and must be enforced in code, not convention.
- **Read only what's needed.** Parse `session_meta.session_id` (confirm),
  `turn_context`/`task_*` (turn delimiting), and user/assistant `message` text
  (join key + answer). Tokens/model are **not** read (OTel owns them, §8.4).
  **Never** read the rollout's other content — Codex writes `user.email`/account
  ids and full tool transcripts there; the OTel path is the authority for tool i/o.
- **Redaction parity.** The answer flows through the same redact-on-capture pass
  as any Mode B response; it is not exempt because it came from a file.
- **No writes, ever.** Beagle only reads the rollout; it never modifies, rotates,
  or deletes Codex's files.

---

## 10. Cost & footprint

- **Core LOC: zero.** `attachOtelResponse` (core) is reused **unchanged** — the
  two deviations (§6.1) live in the daemon's response-only branch (non-core):
  an `origin=='codex-rollout'` check that (a) drops instead of `insertCall` on
  attach-fail and (b) passes empty `searchAppend`.
- **New code (non-core):** rollout JSONL parser (`src/parsers/codex-rollout.ts`);
  the daemon-side RolloutTailer (poll/offset/retire/pending-retry) + its wiring;
  `promptId` stamp in the Codex mapper; `codexPromptKey` shared helper;
  `CODEX_HOME` threaded through run registration.
- **Reuses:** `ingestOtel`, `attachOtelResponse`, redact-on-capture, the summary
  composer, the inflight/drain machinery — all shipped in PR #91.
- **Deps:** none (Node `fs` + `crypto`, both already in `src/adapters`/parsers).

---

## 11. Phasing

- **Phase 0 — spike (§8.1–8.3). ✅ DONE 2026-07-20.** Live paired capture on
  Codex 0.144.6 confirmed the id join, byte-identical prompt text (2/2 + resume),
  ~1.5 s per-turn flush, OTel-owned tokens, no turn key, and safe resume-append.
  The gate is passed.
- **Phase 1 — tailer + mapper key + the two deviations + tests.** `codexPromptKey`
  helper; Codex mapper stamps `promptId`; `codex-rollout.ts` parser (defensive,
  pinned to 0.144.x); RolloutTailer (locate-once, poll, offset, retire,
  pending-retry, scoped-to-observed-convId); `CODEX_HOME` via run registration;
  the daemon-branch `origin=='codex-rollout'` handling — **(a) attach-or-drop and
  (b) empty searchAppend are Phase 1, not optional** (§6.1). Tests: parser on the
  captured rollout fixture; cross-source `codexPromptKey` match; **attach-race →
  drop-not-orphan**; **restart re-emit → no duplicate**; **`beagle search
  <answer-text>` returns no hit** (guards deviation b); resolver convId stability
  (§8.5); fail-open on missing/garbled file. Pin the live paired-turn result (one
  row, prompt + answer, self-reported badge).
- **Phase 1.5 — optional, genuinely deferrable.** Reasoning-trace capture;
  `beagle status` line when rollout logging is disabled.

Self-reported-without-answer remains the fallback throughout; the badge never
claims wire fidelity for a rollout-sourced answer.
