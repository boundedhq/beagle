# Mode B (subscription-auth capture) — Phase-0 spike results

**Status: VALIDATED against Claude Code 2.1.193 (macOS, 2026-07-13).** Mode B
now captures real Claude Code telemetry end to end — a secret in a prompt
fires `beagle leaks` — with one documented content gap (tool *outputs* are not
exported by the client). It remains **agent-reported** by nature (a
self-report, not wire bytes) and is badged as such. See the per-criterion
results below and the classification at the end.

> Reproduce: point Claude Code's OTel exporter at a dump server with
> `buildOtelEnv`'s knobs and run one `claude -p` session. The exact captured
> payload (PII stripped, a test key injected) is checked in at
> `tests/fixtures/claude-code-otlp.json` and asserted against the mapper in
> `tests/otlp.test.ts`.

Background: for Claude Code signed in with a Claude.ai subscription, putting a
proxy on the wire is off-limits (Anthropic restricts subscription OAuth to its
official client). Mode B instead sets Claude Code's own vendor-shipped OTel
knobs so its exporter posts a self-report to Beagle's loopback OTLP receiver.
See PRD R2 (Mode B) and design §6.2.

## The headline finding

The mapper was originally written against the OpenTelemetry **GenAI semantic
conventions** (`gen_ai.prompt`, `gen_ai.completion`, `gen_ai.usage.*`). Claude
Code **does not emit those.** It emits its own **event schema** under scope
`com.anthropic.claude_code.events`, where one user turn is split across several
log records keyed by `(session.id, prompt.id)`:

| `event.name` | content it carries |
|---|---|
| `user_prompt` | `prompt` (verbatim), `prompt.id`, `session.id`, `prompt_length` |
| `tool_result` | `tool_input` (verbatim), `tool_name`, `*_size_bytes`, `success` — **no result content** |
| `api_request` | `model`, `input_tokens`, `output_tokens`, `cost_usd`, `request_id` |
| `assistant_response` | `response` (verbatim), `model`, `request_id` |

Everything else it emits (`hook_*`, `mcp_server_connection`, `plugin_loaded`,
`tool_decision`, `api_refusal`) is operational noise with no leak surface.

Against real output the **old mapper produced zero exchanges** — Mode B
captured nothing. The mapper is now rewritten (`src/parsers/otlp-map.ts`) to
reassemble the split event stream into one Call per turn: `request.bodyBytes`
(the scanned surface) = the user prompt + every tool input; `response.text` =
the assistant response; tokens summed across `api_request` records.

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

All honored by 2.1.193. No binary patching, no hosts/DNS tricks, no TLS
interception.

## Exit criteria — results

1. **Env knobs are honored — ✅ PASS.** With the env above set, Claude Code
   POSTs to `http://127.0.0.1:<port>/v1/logs`, `content-type:
   application/json`, `x-beagle-run` header present. OTLP path used:
   **`/v1/logs`** (logs, not traces).

2. **Content completeness for R5 scanning — ⚠️ PARTIAL (documented gap).**
   - verbatim user prompts — ✅ present (`user_prompt.prompt`)
   - assistant response text — ✅ present (`assistant_response.response`)
   - tool **inputs** — ✅ present verbatim (`tool_result.tool_input`: bash
     command lines, file paths, write payloads — real leak surfaces)
   - tool **outputs / results** — ❌ **NOT exported.** `tool_result` carries
     only `tool_result_size_bytes`, never the content. A secret that exists
     *only* in a tool's output (e.g. the body of a file the agent `Read`) is
     invisible to Mode B, even with `OTEL_LOG_TOOL_CONTENT=1`.

   End-to-end proof of the parts that ARE covered: a real `beagle run claude
   --telemetry` session with `AKIAZQ3DRSTUVWXY2345` in the prompt fires
   `beagle leaks` → `aws-access-key-id → anthropic`, and `beagle search`
   finds it. **This gap is the honest cost of the agent-reported badge and is
   stated in `status` and the README.**

3. **Payload shape — ✅ recorded.** GenAI data arrives as **logs**
   (`resourceLogs → scopeLogs → logRecords`), scope
   `com.anthropic.claude_code.events` v2.1.193. Keys as tabled above. Token
   ints arrive as JSON **numbers** here (`{"intValue": 4058}`); the mapper
   also accepts the spec's string form. `session.id` on every record. **No
   duplicate span+log** for one inference — logs only — so no cross-container
   dedup is needed. A turn *is* split across records (and can be split across
   POST batches); the mapper correlates by `(session.id, prompt.id)` per
   delivered payload, and the scanner + fingerprint dedup make a batch-split
   turn harmless (all content scanned, no double alert).

4. **Session attribute — ✅ PASS.** `session.id` carries the conversation id;
   `prompt.id` correlates the records of one turn. Tier-1 session keying and
   multi-turn dedup work.

5. **Protocol — ✅ PASS.** `http/json` is honored; the receiver's protobuf
   415 path is never hit in practice.

6. **Batch latency — ✅ measured.** With `OTEL_BLRP_SCHEDULE_DELAY=1000`, the
   terminal `assistant_response` arrived **~0.06 s** after its event
   timestamp (flushed on turn completion); earlier events in a batch waited up
   to **~5 s** for the batch window. Alert lag is therefore batch-bound, not
   wire-instant — **seconds, not the R6 ~1 s wire target.** `status`/docs must
   not imply wire-equal timing for Mode B.

7. **Account safety — ✅ by construction.** The env vars configure only the
   OTel *exporter*; the telemetry is a separate loopback POST. No traffic
   between Claude Code and Anthropic is touched — login/refresh ride their own
   untouched connection, and no CA/DNS/proxy is involved. (Not wire-diffed;
   the mechanism is exporter-only by design, which is the whole reason Mode B
   exists.)

## Also observed

- **PII in every event.** Each record carries `user.email`, `user.id`,
  `user.account_uuid`, `user.account_id`, `organization.id`. Beagle's mapper
  reads only content/token/session attributes and **drops all of these** —
  they never reach the store. (The spike fixture has them stripped too.)

## What is already covered (no spike needed)

- Receiver: loopback bind, per-daemon-session run token (timing-safe compare
  on the `x-beagle-run` header — the real gate), JSON-only (protobuf → 415),
  body-size cap, chunk-safe UTF-8 decode.
- Mapper: `resourceLogs` **and** `resourceSpans` (spans kept as a
  forward-compat fallback), int64-as-number **and** -as-string, plain-string
  **and** JSON-array prompts, malformed payload → `[]`.
- Pipeline parity: OTel Calls run the identical scanner → session → alert →
  store path as wire capture, labeled `source='otel'`.

## Classification

**Sanctioned mechanism, partial fidelity.** Mode B is functional and validated
for Claude Code 2.1.193: it captures prompts, assistant responses, and tool
inputs, and fires real leak alerts on them — using only vendor-shipped OTel
knobs, with the model↔Anthropic connection untouched. The one gap (tool output
content is not exported) and the batch-bound latency are inherent to the
self-report and are disclosed. Ship as `--telemetry` with the **agent-reported**
badge; safe to keep opt-in. Before promoting it to a default or graduation
nudge, re-run this spike against the then-current Claude Code (the event schema
is a client implementation detail and can drift).
