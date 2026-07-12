# Mode B (subscription-auth capture) — Phase-0 spike exit criteria

**Status: NOT YET VALIDATED against a real Claude Code build.** Mode B is
implemented and unit-tested against synthetic OTLP payloads, but the exact
shape of Claude Code's OpenTelemetry export — and whether its content flags
carry enough for R5 secret scanning — can only be confirmed against the real
client. This document is the checklist that gates trusting Mode B in
production. Until every item is checked, `beagle run claude --telemetry`
should be treated as **best-effort, agent-reported** capture, and the UI badge
("agent-reported") plus the `status` disclosure must say so.

Background: for Claude Code signed in with a Claude.ai subscription, putting a
proxy on the wire is off-limits (Anthropic restricts subscription OAuth to its
official client). Mode B instead sets Claude Code's own vendor-shipped OTel
knobs so its exporter posts a self-report to Beagle's loopback OTLP receiver.
See PRD R2 (Mode B) and design §6.2.

## What Beagle sets (vendor knobs only — the bright line)

`buildOtelEnv()` in `src/parsers/otlp-map.ts` sets, per run:

```
CLAUDE_CODE_ENABLE_TELEMETRY=1
OTEL_LOGS_EXPORTER=otlp
OTEL_EXPORTER_OTLP_PROTOCOL=http/json      # receiver is JSON-only by construction
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:<port>
OTEL_LOG_USER_PROMPTS=1                     # content flags
OTEL_LOG_TOOL_DETAILS=1
OTEL_LOG_TOOL_CONTENT=1
OTEL_BLRP_SCHEDULE_DELAY=1000               # trim batch lag toward ~1s
OTEL_EXPORTER_OTLP_HEADERS=x-beagle-run=<token>
```

No binary patching, no hosts/DNS tricks, no TLS interception. If any of these
env var names has drifted in the current Claude Code, update `buildOtelEnv`;
do **not** substitute a non-vendor mechanism.

## Exit criteria — each must be observed on a real Claude Code build

1. **Env knobs are honored.** With the env above set, Claude Code POSTs to the
   Beagle receiver at `/v1/logs` (or `/v1/traces`). Confirm the receiver
   records exchanges during a real session. Record the actual OTLP path used.

2. **Content completeness for R5 scanning.** Confirm the content flags carry:
   - verbatim user prompts (not truncated / not hashed),
   - tool inputs and tool outputs (where a leaked secret most often appears),
   - the assistant response text.
   Run a session that deliberately includes a known test secret in a tool
   result and confirm `beagle leaks` fires. If any content is redacted or
   truncated by the client, document the gap — that is the honest cost of the
   agent-reported badge, and `status`/docs must state it.

3. **Payload shape.** Record whether GenAI data arrives as **logs**
   (`resourceLogs`) or **spans** (`resourceSpans`), the exact attribute keys
   used for prompt / completion / model / session id / token counts, and the
   value encodings (int64 as JSON string vs number). The mapper already
   handles both containers, both token-name conventions, string-encoded
   int64, and a JSON-array prompt — but confirm the real keys match and add
   any missing ones to `recordToExchange`. **If the client emits BOTH a span
   and a log for the same inference**, the mapper would produce two exchanges
   for one call — decide whether to de-duplicate (e.g. by a shared span/trace
   id) once the real behavior is known. Also record the exact serialization of
   `gen_ai.prompt` for nested content (tool_result blocks): the scanner reads
   the raw prompt string so it catches secrets in any nested field, but
   confirm the client doesn't truncate or hash that content.

4. **Session attribute.** Confirm which attribute carries the conversation /
   session id (currently mapped from `session.id`) so tier-1 session keying
   works and dedup is correct across a multi-turn conversation.

5. **Protocol.** Confirm `http/json` is honored (the receiver rejects
   protobuf with 415 by design). If the client only speaks protobuf for logs,
   that is a blocking finding — decide before shipping whether to accept a
   protobuf decode dependency (violates the zero-dep budget) or drop Mode B to
   spans/another signal.

6. **Batch latency.** Measure the real alert lag with
   `OTEL_BLRP_SCHEDULE_DELAY=1000`. R6's ~1s target holds for wire capture but
   not necessarily Mode B; record the residual and make sure `status`/docs
   state it rather than implying wire-equal timing.

7. **Account safety.** Confirm that setting these env vars does not alter the
   auth/refresh flow or the client fingerprint (nothing goes on the wire
   between Claude Code and Anthropic; login/refresh ride their own untouched
   connection). This is the whole reason Mode B exists — verify it holds.

## What is already covered (no spike needed)

- Receiver: loopback bind, per-daemon-session run token (timing-safe compare),
  JSON-only (protobuf → 415), body-size cap, chunk-safe UTF-8 decode.
- Mapper: `resourceLogs` **and** `resourceSpans`; `input_tokens`/`prompt_tokens`
  and `output_tokens`/`completion_tokens`; int64-as-string; plain-string **and**
  JSON-array prompts; malformed payload → `[]`.
- Pipeline parity: OTel exchanges run the identical scanner → session → alert →
  store path as wire capture, labeled `source='otel'`.

## Ship posture until validated

Per the PRD, V1 ship is gated on each subscription agent having a *classified*
answer (sanctioned / gray / no-clean-path), not on Mode B being perfect.
Current classification for Claude Code Mode B: **implemented, unvalidated** —
ship as opt-in `--telemetry` with the agent-reported badge and this document
linked from the release notes, and complete this checklist before promoting it
to a default or a graduation nudge.
