import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Daemon } from "../src/daemon/daemon";
import { controlRequest } from "../src/daemon/control";
import { Store } from "../src/core/store/store";
import { listCalls, listLeakEvents } from "../src/viewer/feed-query";
import type { AlertEvent } from "../src/core/alert/engine";

// Claude Code's real Mode-B export (event schema, verified in the Phase-0
// spike): a turn is a user_prompt + api_request + assistant_response sharing
// session.id/prompt.id. The run token rides the HTTP header, not an attribute.
function otlpBody(_token: string, prompt: string | null, sessionId = "otel-conv-1", response: string | null = "acknowledged") {
  const ev = (name: string, attrs: Record<string, string | number>) => ({
    timeUnixNano: String(Date.now() * 1e6),
    body: { stringValue: `claude_code.${name}` },
    attributes: [
      { key: "event.name", value: { stringValue: name } },
      { key: "session.id", value: { stringValue: sessionId } },
      { key: "prompt.id", value: { stringValue: "prompt-x" } },
      ...Object.entries(attrs).map(([key, value]) =>
        typeof value === "number"
          ? { key, value: { intValue: value } }
          : { key, value: { stringValue: value } },
      ),
    ],
  });
  return {
    resourceLogs: [{
      scopeLogs: [{
        scope: { name: "com.anthropic.claude_code.events" },
        logRecords: [
          ...(prompt === null ? [] : [ev("user_prompt", { prompt })]),
          ev("api_request", { model: "claude-sonnet-5", input_tokens: 50, output_tokens: 4 }),
          ...(response === null ? [] : [ev("assistant_response", { model: "claude-sonnet-5", response })]),
        ],
      }],
    }],
  };
}

// The receiver 200s before the ingest pipeline (scan → insert → alert) runs,
// so a fixed sleep races it under CI load.
// Default stays under bun's 5s per-test timeout, so a real regression surfaces
// as "timed out waiting for <what>" rather than a bare bun timeout.
async function waitFor(cond: () => boolean | Promise<boolean>, what: string, timeoutMs = 4_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await cond())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(10);
  }
}

// Wait until the daemon has fully finished the batch(es) posted so far: the
// receiver's ingest is one tracked promise per batch, so inflight===0 means
// every call in it is scanned, stored and alerted — nothing more is coming.
// Waiting on the alert sink instead would return at the FIRST alert and let a
// spurious second one land after the assertion, silently passing `toBe(1)`.
// `minCalls` guards the start of the race, before ingest has been dispatched.
async function settled(socketPath: string, minCalls = 1): Promise<void> {
  await waitFor(async () => {
    const status = await controlRequest(socketPath, { cmd: "status" });
    const d = status.data as { calls: number; inflight: number };
    return d.calls >= minCalls && d.inflight === 0;
  }, `the daemon to finish ingesting ${minCalls} call(s)`);
}

describe("Mode B end-to-end through the daemon", () => {
  let stateDir: string;
  let daemon: Daemon;
  let alerts: AlertEvent[];
  let otlpPort: number;
  let token: string;

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-modeb-"));
    alerts = [];
    daemon = await Daemon.start({ stateDir, alertSinkForTest: (a) => alerts.push(a), persistent: true });
    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort: number; otlpToken: string };
    otlpPort = data.otlpPort;
    token = data.otlpToken;
  });

  afterEach(async () => {
    await daemon.stop();
  });

  async function post(body: unknown) {
    return fetch(`http://127.0.0.1:${otlpPort}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": token },
      body: JSON.stringify(body),
    });
  }

  test("OTel-reported call is captured, labeled otel, and scanned", async () => {
    const r = await post(otlpBody(token, "please read the readme"));
    expect(r.status).toBe(200);
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const hits = store.searchLiteral("please read the readme");
    expect(hits.length).toBe(1);
    const call = store.getCall(hits[0]!.callId)!;
    expect(call.source).toBe("otel");
    expect(call.model).toBe("claude-sonnet-5");
    expect(call.tokensOut).toBe(4);
    store.close();
  });

  test("Mode B search is OUTBOUND-only: a string only the model said is not a hit", async () => {
    // The same invariant the wire path holds (buildSearchText): `beagle search`
    // answers "was this SENT", so a hit is proof it left the machine. A token
    // that appears ONLY in a Claude Code answer must not be reportable as sent
    // — indexing call.response.text here made model-generated text look
    // outbound, and Mode B is the path where most agent answers arrive.
    await post(otlpBody(token, "what is in the readme?", "otel-conv-dir", "the readme mentions zqxjkvbrwn"));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("zqxjkvbrwn")).toEqual([]); // response-only token: never sent
    const byPrompt = store.searchLiteral("what is in the readme?");
    expect(byPrompt.length).toBe(1); // the prompt was
    // The answer is still captured — withheld from the index, not from the row.
    const call = store.getCall(byPrompt[0]!.callId)!;
    expect(new TextDecoder().decode(call.responseBody!)).toContain("zqxjkvbrwn");
    store.close();
  });

  test("Mode B call persists its display messages for the session transcript", async () => {
    await post(otlpBody(token, "please read the readme"));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("please read the readme")[0]!.callId)!;
    // the self-report's structure survives persistence (schema v3) — this is
    // what the viewer's transcript and detail views render for Mode B rows
    expect(call.displayMessages).toEqual([{ role: "user", content: "please read the readme" }]);
    store.close();
  });

  test("redact-on-capture scrubs display messages too", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    await post(otlpBody(token, "my key AKIAZQ3DRSTUVWXY2345 leaked", "otel-conv-dm", null));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("my key")[0]!.callId)!;
    const dm = JSON.stringify(call.displayMessages);
    expect(dm).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(dm).toContain("[REDACTED:aws-access-key-id:");
    store.close();
  });

  test("redact-on-capture scrubs a JSON-escaped multi-line secret from every derived surface", async () => {
    // A resumed conversation serializes its whole message list into the prompt
    // attribute, so the scanned bytes are JSON: a PEM's newlines are the
    // two-char escape `\n`. The display text is the JSON.parse'd form with REAL
    // newlines, so the scanner's matched value is not a substring of it and a
    // literal-match scrub silently no-ops — the body was masked while the
    // transcript and the search index still held the raw key.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    // Synthetic body, per the fixture convention in scanner/precision tests —
    // what matters is only that it spans a newline, so the scanned (escaped)
    // and displayed (decoded) forms differ.
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAderivedTextRegression\n-----END RSA PRIVATE KEY-----";
    const prompt = JSON.stringify([{ role: "user", content: `deploy with this key:\n${pem}` }]);
    await post(otlpBody(token, prompt, "otel-conv-pem", null));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(1); // the leak still alerts
    const hit = store.searchLiteral("deploy with this key")[0]!;
    const call = store.getCall(hit.callId)!;
    expect(call.redacted).toBe(true);
    const body = new TextDecoder().decode(call.requestBody!);
    expect(body).not.toContain("MIIEowIBAAKCAQEAderivedTextRegression"); // stored body: offset-redacted
    // …and the derived surfaces the hole left raw: the rendered transcript…
    expect(JSON.stringify(call.displayMessages)).not.toContain("MIIEowIBAAKCAQEAderivedTextRegression");
    expect(JSON.stringify(call.displayMessages)).toContain("[REDACTED:private-key:");
    // …and the search index, which would otherwise hand the key back.
    expect(store.searchLiteral("MIIEowIBAAKCAQEAderivedTextRegression")).toEqual([]);
    expect(store.searchLiteral(pem)).toEqual([]);
    store.close();
  });

  // ---- derived-text redaction: the display is not the scanned bytes ----
  //
  // The three below share one root cause and one remedy. The scanner reads the
  // RAW bytes; display_messages, the summary and the Mode B half of searchText
  // render a TRANSFORMED view of them. Where the transform changes more than
  // escaping, no value-scrub keyed off the raw match can reach the result — the
  // derived text has to be scanned on its own and offset-redacted (see
  // Daemon.redactDerived).

  test("a secret MANUFACTURED by joining two content blocks is caught and ALERTS", async () => {
    // The worst of the family, because it is the only one that used to be
    // silent: flattenPromptText joins adjacent content blocks with NOTHING
    // between them, so this key does not exist in the scanned bytes — split
    // across the block boundary, no rule matches — while the transcript,
    // summary and search index all hold it whole. Zero findings, zero leak
    // events, `redacted` false, and `beagle search` handing the key back.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    const prompt = JSON.stringify([{
      role: "user",
      content: [
        { type: "text", text: "here is the key AKIAZQ3DRSTUV" },
        { type: "text", text: "WXY2345 use it" },
      ],
    }]);
    await post(otlpBody(token, prompt, "otel-conv-split", null));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    // It alerts — the whole point. The scanned bytes hold no secret, so this
    // event can only have come from scanning the rendered text.
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.secretType).toBe("aws-access-key-id");
    expect(listLeakEvents(store).length).toBe(1);
    const call = store.getCall(store.searchLiteral("here is the key")[0]!.callId)!;
    expect(call.redacted).toBe(true); // derived text WAS rewritten
    const dm = JSON.stringify(call.displayMessages);
    expect(dm).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(dm).toContain("[REDACTED:aws-access-key-id:");
    expect(call.summary).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    store.close();
  });

  test("a PEM spanning two messages of a serialized list is scrubbed from the transcript", async () => {
    // The matched value in the raw bytes runs BEGIN…END straight through the
    // structural `"},{"role":"user","content":"` between the two messages —
    // text the flattened display drops, so neither the raw form nor its decoded
    // form is a substring of what got stored. The body was offset-redacted and
    // the leak alerted, while the transcript and the index kept the key.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    const prompt = JSON.stringify([
      { role: "user", content: "part one:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsplitAcrossMessages" },
      { role: "user", content: "part two:\nbbb\n-----END RSA PRIVATE KEY-----" },
    ]);
    await post(otlpBody(token, prompt, "otel-conv-span", null));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    // TWO events, deliberately pinned: the body scan's value carries the
    // structural `"},{"role":…` and the transcript's does not, so they are
    // different strings and nothing can key them together — secretKeys collapses
    // escaping and line wrapping, not dropped JSON. One paste therefore alerts
    // twice here. Over-alerting on a leak that already alerts, and it needs a
    // key split across two messages to happen at all; if a future change does
    // manage to relate the two values, update this deliberately.
    expect(listLeakEvents(store).length).toBe(2);
    const call = store.getCall(store.searchLiteral("part one")[0]!.callId)!;
    const dm = JSON.stringify(call.displayMessages);
    expect(dm).not.toContain("MIIEowIBAAKCAQEAsplitAcrossMessages");
    // Both halves lose their share of the span, so neither message is left
    // holding a readable fragment of the key.
    expect(dm).toContain("[REDACTED:private-key:");
    expect(dm).not.toContain("-----END RSA PRIVATE KEY-----");
    expect(store.searchLiteral("MIIEowIBAAKCAQEAsplitAcrossMessages")).toEqual([]);
    store.close();
  });

  test("a secret straddling the transcript's length cap leaves no raw prefix", async () => {
    // A codex tool result is stored as `${tool}: ${output}` clamped to
    // DISPLAY_RESULT_CAP. Clamping in the mapper ran BEFORE the scrub, so a key
    // sitting across the cap was cut in half: the scrub looked for the whole
    // value, found nothing, and the first characters of the key rode into
    // display_messages — in the viewer's transcript, while the body beside it
    // was correctly redacted and the leak fired. The cap now lands after the
    // redaction instead.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    // The display line is `exec_command: ${output}` — a 14-char prefix — so
    // 3976 chars of filler start the key at 3990, putting its first ten
    // characters inside the cap and the rest beyond it. The filler ends in a
    // space because the rule is \b-anchored and would not match mid-word.
    const output = "f".repeat(3976 - 1) + " AKIAZQ3DRSTUVWXY2345 trailing";
    await post({
      resourceLogs: [{
        scopeLogs: [{
          scope: { name: "codex_otel.log_only" },
          logRecords: [{
            timeUnixNano: "0",
            observedTimeUnixNano: String(Date.now() * 1e6),
            attributes: [
              { key: "event.name", value: { stringValue: "codex.tool_result" } },
              { key: "conversation.id", value: { stringValue: "otel-conv-cap" } },
              { key: "call_id", value: { stringValue: "call-cap" } },
              { key: "tool_name", value: { stringValue: "exec_command" } },
              { key: "output", value: { stringValue: output } },
            ],
          }],
        }],
      }],
    });
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(1); // the body scan fires as it always did
    const call = store.getCall(store.searchLiteral("exec_command")[0]!.callId)!;
    const dm = JSON.stringify(call.displayMessages);
    expect(dm).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(dm).not.toContain("AKIAZQ3DRS"); // …nor the prefix the cap used to spare
    expect(dm).toContain("[REDACTED:aws-access-key-id:");
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    // Still capped: the transcript keeps a bounded slice, it just cuts a
    // redacted string now instead of a raw one. The cut runs to the end of the
    // placeholder it landed inside (clampRedacted) rather than leaving a stump,
    // so the length overshoots the cap by that placeholder and no further.
    const content = call.displayMessages![0]!.content;
    expect(content.length).toBeGreaterThan(4000);
    expect(content.length).toBeLessThan(4100);
    expect(content.endsWith("]")).toBe(true);
    store.close();
  });

  test("a leaked secret in an OTel-reported prompt fires the same alert", async () => {
    await post(otlpBody(token, "the key is AKIAZQ3DRSTUVWXY2345"));
    await settled(daemon.socketPath);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.secretType).toBe("aws-access-key-id");
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(1);
    store.close();
  });

  test("one batch carrying two turns fires one alert per turn", async () => {
    // The agent batches its export, so a single POST can carry several turns —
    // ingestOtel awaits the scanner per call and yields between them. Nothing
    // pins the fixtures above to one turn each, so pin the multi-turn shape
    // here: it is what makes their exact `toBe(1)` counts meaningful.
    const ev = (sid: string, prompt: string) => ({
      timeUnixNano: String(Date.now() * 1e6),
      body: { stringValue: "claude_code.user_prompt" },
      attributes: [
        { key: "event.name", value: { stringValue: "user_prompt" } },
        { key: "session.id", value: { stringValue: sid } },
        { key: "prompt.id", value: { stringValue: `p-${sid}` } },
        { key: "prompt", value: { stringValue: prompt } },
      ],
    });
    await post({ resourceLogs: [{ scopeLogs: [{
      scope: { name: "com.anthropic.claude_code.events" },
      logRecords: [
        ev("otel-two-a", "first key AKIAZQ3DRSTUVWXY2345 here"),
        ev("otel-two-b", "second key AKIAZQ3DRSTUVWXY6789 here"),
      ],
    }] }] });
    await settled(daemon.socketPath, 2);
    expect(alerts.length).toBe(2);
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(2); // distinct secrets — neither deduped away
    store.close();
  });

  test("redact-on-capture scrubs Mode B body, search text, and summary", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    // No assistant_response in the batch: the summary falls back to the raw
    // prompt line — exactly where the secret sits.
    await post(otlpBody(token, "my key AKIAZQ3DRSTUVWXY2345 leaked", "otel-conv-r", null));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    // the leak event still exists (audit value kept)...
    expect(listLeakEvents(store).length).toBe(1);
    // ...but the raw secret is gone from the body, the index, and the summary
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    const hit = store.searchLiteral("my key")[0]!;
    const call = store.getCall(hit.callId)!;
    expect(call.redacted).toBe(true);
    const body = new TextDecoder().decode(call.requestBody!);
    expect(body).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(body).toContain("[REDACTED:aws-access-key-id:");
    expect(call.summary).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(call.summary).toContain("[REDACTED:aws-access-key-id:");
    store.close();
  });

  // connection-string's secretGroup captures the password ALONE, so both of
  // these are FOUR-char findings — under redactValuesInText's 8-char floor. The
  // body is spliced by span and the summary used to re-derive from the raw text
  // and scrub it by value, which for a value this short is a no-op. One test
  // per half, because the two read different parts of the derived scan.
  test("a short Mode B secret in the prompt never reaches the stored summary", async () => {
    // response null: the summary falls back to the prompt line itself.
    await post(otlpBody(token, "connect with postgres://svc:pw12@db.internal/app", "otel-conv-short-out", null));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("connect with")[0]!.callId)!;
    expect(call.summary).not.toContain("pw12");
    expect(call.summary).toContain("[REDACTED:connection-string:");
    expect(call.summary).toContain("connect with"); // the line itself survived
    store.close();
  });

  test("a short Mode B secret in the response never reaches the stored summary", async () => {
    await post(otlpBody(token, "otel reply probe", "otel-conv-short-in", "use postgres://svc:zq77@db.internal/app now"));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const call = store.getCall(store.searchLiteral("otel reply probe")[0]!.callId)!;
    expect(call.summary).not.toContain("zq77");
    expect(call.summary).toContain("[REDACTED:connection-string:");
    // The question half is untouched — this scrubs a secret, not the line.
    expect(call.summary).toContain("otel reply probe");
    store.close();
  });

  test("a response arriving in a later OTLP batch rejoins its turn row (cross-batch stitch)", async () => {
    // The real interactive pattern (verified live against Claude Code 2.1.193):
    // the prompt flushes in its own batch ~1s after Enter; the answer lands in
    // another batch ~18s later. One turn must be ONE row — not a question with
    // no answer plus a detached answer the feed can't line up.
    await post(otlpBody(token, "how does memory work?", "otel-conv-stitch", null));
    await settled(daemon.socketPath);
    await post(otlpBody(token, null, "otel-conv-stitch", "memory works like this"));
    // The stitch adds no new call row, and it deliberately leaves the search
    // index alone (outbound-only), so poll the summary — the composed
    // `"question" → answer` is the observable that only a stitch produces.
    await waitFor(() => {
      const s = Store.openReadOnly(stateDir);
      try {
        return listCalls(s, 50).some((c) => (c.summary ?? "").includes("→"));
      } finally {
        s.close();
      }
    }, "the response to be stitched into the store");
    const store = Store.openReadOnly(stateDir);
    const byPrompt = store.searchLiteral("how does memory work")[0]!;
    const call = store.getCall(byPrompt.callId)!;
    // The answer reached the row… but never the index (search is outbound-only).
    expect(new TextDecoder().decode(call.responseBody!)).toContain("memory works like this");
    expect(store.searchLiteral("memory works like this")).toEqual([]);
    expect(call.model).toBe("claude-sonnet-5");
    expect(call.tokensIn).toBe(100); // 50 (prompt batch) + 50 (response batch)
    expect(call.tokensOut).toBe(8);
    // …and it stayed ONE row: no detached response-only exchange was created.
    expect(listCalls(store, 50).length).toBe(1);
    store.close();
  });

  test("a response batch carrying a tool input does NOT stitch — it keeps its own row AND alerts", async () => {
    // The stitch branch skips alertEngine.process, so it must only ever take
    // partials with nothing outbound. Here the response shares its batch with a
    // tool_result whose input holds a secret: stitching it would silently drop
    // that leak. It must stay its own row and fire the alert. (Verified live:
    // Claude Code really does co-batch tool_result with the answer.)
    const withTool = {
      resourceLogs: [{ scopeLogs: [{ scope: { name: "com.anthropic.claude_code.events" }, logRecords: [
        {
          timeUnixNano: String(Date.now() * 1e6),
          attributes: [
            { key: "event.name", value: { stringValue: "tool_result" } },
            { key: "session.id", value: { stringValue: "otel-conv-tooled" } },
            { key: "prompt.id", value: { stringValue: "prompt-x" } },
            { key: "tool_name", value: { stringValue: "Bash" } },
            { key: "tool_input", value: { stringValue: '{"command":"deploy --key AKIAZQ3DRSTUVWXY2345"}' } },
          ],
        },
        {
          timeUnixNano: String(Date.now() * 1e6),
          attributes: [
            { key: "event.name", value: { stringValue: "assistant_response" } },
            { key: "session.id", value: { stringValue: "otel-conv-tooled" } },
            { key: "prompt.id", value: { stringValue: "prompt-x" } },
            { key: "response", value: { stringValue: "deployed it" } },
          ],
        },
      ] }] }],
    };
    await post(otlpBody(token, "deploy the app", "otel-conv-tooled", null));
    await settled(daemon.socketPath, 1);
    await post(withTool);
    await settled(daemon.socketPath, 2);
    const store = Store.openReadOnly(stateDir);
    // two rows: the question, and the tool+answer partial that could not stitch
    expect(listCalls(store, 50).length).toBe(2);
    // and the secret in the TOOL INPUT still alerted — the whole point
    expect(alerts.some((a) => a.secretType === "aws-access-key-id")).toBe(true);
    // the input is searchable, and so is the tool NAME: a Claude Code turn
    // reports the name as its own attribute, outside the scanned body the
    // index is built from, but it rode the real outbound request.
    expect(store.searchLiteral("deploy --key").length).toBe(1);
    expect(store.searchLiteral("Bash").length).toBe(1);
    store.close();
  });

  test("a stitched summary is built from SCRUBBED text, never the raw response", async () => {
    // The composed `"question" → answer` summary must reuse the already-scrubbed
    // summary, not re-derive from call.response.text — doing the latter would
    // reinstate a secret the redaction pass had removed, in the one field the
    // feed shows by default.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    await post(otlpBody(token, "what is the key?", "otel-conv-redact-stitch", null));
    await settled(daemon.socketPath);
    await post(otlpBody(token, null, "otel-conv-redact-stitch", "the key is AKIAZQ3DRSTUVWXY2345"));
    await waitFor(async () => {
      const s = Store.openReadOnly(stateDir);
      try {
        return listCalls(s, 50).some((c) => (c.summary ?? "").includes("→"));
      } finally {
        s.close();
      }
    }, "the response to be stitched in");
    const store = Store.openReadOnly(stateDir);
    const row = listCalls(store, 50).find((c) => (c.summary ?? "").includes("→"))!;
    expect(row.summary).toContain("what is the key?"); // the question half survived
    expect(row.summary).not.toContain("AKIAZQ3DRSTUVWXY2345"); // the secret did not
    expect(row.summary).toContain("[REDACTED:aws-access-key-id:");
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    store.close();
  });

  test("redact-on-capture scrubs a secret echoed in a response-only batch", async () => {
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    // The prompt that leaked the key rode an earlier batch; this batch carries
    // only the assistant's echo — no request-side scan surface at all.
    await post(otlpBody(token, null, "otel-conv-echo", "your key is AKIAZQ3DRSTUVWXY2345"));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
    // Located by row, not by search: this batch sent nothing, so it is indexed
    // under nothing — its content is response-side only.
    const rows = listCalls(store, 50);
    expect(rows.length).toBe(1); // pin the row this assertion is about
    const call = store.getCall(rows[0]!.id)!;
    expect(call.redacted).toBe(true);
    expect(new TextDecoder().decode(call.responseBody!)).toContain("[REDACTED:aws-access-key-id:");
    expect(call.summary).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(call.summary).toContain("[REDACTED:aws-access-key-id:");
    // Inbound content is redacted but never alerts — the outbound leak fired
    // with the batch that carried the prompt.
    expect(alerts.length).toBe(0);
    store.close();
  });

  test("an incomplete Mode B scan withholds body, summary, and search text", async () => {
    // A 0ms scan deadline fires before the worker can respond: every scan
    // reports incomplete, the fail-safe path.
    const dir2 = mkdtempSync(join(tmpdir(), "beagle-modeb-inc-"));
    const d2 = await Daemon.start({ stateDir: dir2, persistent: true, scanDeadlineMs: 0, alertSinkForTest: () => {} });
    try {
      const status = await controlRequest(d2.socketPath, { cmd: "status" });
      const data = status.data as { otlpPort: number; otlpToken: string };
      await controlRequest(d2.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
      await fetch(`http://127.0.0.1:${data.otlpPort}/v1/logs`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-beagle-run": data.otlpToken },
        body: JSON.stringify(otlpBody(data.otlpToken, "unverified AKIAZQ3DRSTUVWXY2345")),
      });
      await settled(d2.socketPath);
      const store = Store.openReadOnly(dir2);
      expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]);
      expect(store.searchLiteral("unverified")).toEqual([]); // search index withheld too
      const ex = listCalls(store, 10)[0]!;
      expect(ex.scanState).toBe("incomplete");
      expect(ex.summary).toBe("[REDACTION INCOMPLETE: content withheld]");
      const full = store.getCall(ex.id)!;
      expect(new TextDecoder().decode(full.requestBody!)).toContain("[REDACTION INCOMPLETE");
      store.close();
    } finally {
      await d2.stop();
    }
  });

  test("wrong OTLP token is rejected, nothing captured", async () => {
    const r = await fetch(`http://127.0.0.1:${otlpPort}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": "wrong" },
      body: JSON.stringify(otlpBody("wrong", "should not be stored")),
    });
    expect(r.status).toBe(401);
    // No wait: the token gate 401s before the body is even read, so no ingest
    // was ever dispatched — there is nothing asynchronous to settle.
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("should not be stored")).toEqual([]);
    store.close();
  });
});

describe("Mode B tool-output capture (PostToolUse hook)", () => {
  let stateDir: string;
  let daemon: import("../src/daemon/daemon").Daemon;
  let alerts: import("../src/core/alert/engine").AlertEvent[];
  let otlpPort: number;
  let token: string;

  beforeEach(async () => {
    const { mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { Daemon } = await import("../src/daemon/daemon");
    stateDir = mkdtempSync(join(tmpdir(), "beagle-hook-"));
    alerts = [];
    daemon = await Daemon.start({ stateDir, alertSinkForTest: (a) => alerts.push(a), persistent: true });
    const status = await (await import("../src/daemon/control")).controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort: number; otlpToken: string };
    otlpPort = data.otlpPort;
    token = data.otlpToken;
  });
  afterEach(async () => { await daemon.stop(); });

  test("a secret in a TOOL OUTPUT (cat .env) fires an alert — the Mode B gap, closed", async () => {
    // This is exactly what the OTel export can't see: the secret is only in the
    // tool's RESULT, never in the prompt or the command.
    const hook = { session_id: "sess-x", tool_name: "Bash",
      tool_input: { command: "cat secrets.env" },
      tool_response: "AWS_SECRET=AKIAZQ3DRSTUVWXY2345\n" };
    const r = await fetch(`http://127.0.0.1:${otlpPort}/v1/hook`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": token },
      body: JSON.stringify(hook),
    });
    expect(r.status).toBe(200);
    await settled(daemon.socketPath);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.secretType).toBe("aws-access-key-id");
    // The COMMAND is searchable too. A hook payload's display message is built
    // from the response alone (`${toolName}: ${toolResponse}`), so while the
    // index came from the display messages the input — the most outbound thing
    // a tool row carries — was scanned but unfindable.
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("cat secrets.env").length).toBe(1);
    store.close();
  });
});

// Codex on a ChatGPT login can't be wire-proxied; --telemetry captures it via
// Codex's own OTel export (codex.* schema, scope codex_otel.log_only). Unlike
// Claude Code, that export carries tool OUTPUT inline — no hook needed.
function codexBody(name: string, attrs: Record<string, string>) {
  return {
    resourceLogs: [{
      scopeLogs: [{
        scope: { name: "codex_otel.log_only" },
        logRecords: [{
          timeUnixNano: String(Date.now() * 1e6),
          attributes: [
            { key: "event.name", value: { stringValue: name } },
            { key: "conversation.id", value: { stringValue: "codex-conv-1" } },
            ...Object.entries(attrs).map(([key, value]) => ({ key, value: { stringValue: value } })),
          ],
        }],
      }],
    }],
  };
}

describe("Codex Mode B end-to-end through the daemon", () => {
  let stateDir: string;
  let daemon: Daemon;
  let alerts: AlertEvent[];
  let otlpPort: number;
  let token: string;

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-codex-"));
    alerts = [];
    daemon = await Daemon.start({ stateDir, alertSinkForTest: (a) => alerts.push(a), persistent: true });
    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort: number; otlpToken: string };
    otlpPort = data.otlpPort;
    token = data.otlpToken;
  });
  afterEach(async () => { await daemon.stop(); });

  const post = (body: unknown) =>
    fetch(`http://127.0.0.1:${otlpPort}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": token },
      body: JSON.stringify(body),
    });

  test("a codex prompt is captured, labeled codex/openai, and scanned", async () => {
    const r = await post(codexBody("codex.user_prompt", { prompt: "refactor the parser", model: "gpt-5.6" }));
    expect(r.status).toBe(200);
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    const hits = store.searchLiteral("refactor the parser");
    expect(hits.length).toBe(1);
    const call = store.getCall(hits[0]!.callId)!;
    expect(call.source).toBe("otel");
    expect(call.agent).toBe("codex");
    expect(call.provider).toBe("openai");
    store.close();
  });

  test("a secret in a codex PROMPT fires the leak alert", async () => {
    await post(codexBody("codex.user_prompt", { prompt: "ship it with AKIAZQ3DRSTUVWXY2345" }));
    await settled(daemon.socketPath);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.secretType).toBe("aws-access-key-id");
  });

  test("a secret in a codex TOOL OUTPUT (cat key.txt) fires the leak alert — no hook needed", async () => {
    // Codex exports the tool result inline, so the secret is visible in Mode B
    // without the PostToolUse hook Claude Code requires for the same coverage.
    await post(codexBody("codex.tool_result", {
      tool_name: "exec_command",
      arguments: '{"cmd":"cat key.txt"}',
      output: "token = AKIAZQ3DRSTUVWXY2345",
    }));
    await settled(daemon.socketPath);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.secretType).toBe("aws-access-key-id");
    const store = Store.openReadOnly(stateDir);
    expect(listLeakEvents(store).length).toBe(1);
    store.close();
  });

  test("search covers the WHOLE tool result, past the display truncation", async () => {
    // The display copy of a tool result is capped (DISPLAY_RESULT_CAP, applied
    // by the daemon) and carries no arguments at all. Indexing that copy made search
    // lie by omission: a string genuinely sent — scanned, and redacted if it
    // were a secret — came back "never sent through Beagle" purely because it
    // sat past the cap. Search is meant to be a definitive answer, so it is
    // built from the scanned bytes, which are neither truncated nor
    // output-only.
    const marker = "zqxjkvbrwn-past-the-cap";
    await post(codexBody("codex.tool_result", {
      tool_name: "exec_command",
      arguments: '{"cmd":"cat big.log"}',
      output: "x".repeat(5000) + marker,
    }));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral(marker).length).toBe(1); // past char 4000 — was a miss
    expect(store.searchLiteral("cat big.log").length).toBe(1); // arguments — never displayed at all
    store.close();
  });

  test("the widened index is still redacted: a secret past the truncation never lands in it", async () => {
    // The flip side of the coverage fix. Indexing the scanned bytes means the
    // index now holds text the capped display copy used to keep out, so the
    // redaction pass has to cover that new surface — offset-redacted bytes,
    // the same footing the display copy is on now. A secret past the
    // old cap, and one in an argument that never reaches a display message at
    // all, must both be findable ONLY as their placeholder.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: true } });
    await post(codexBody("codex.tool_result", {
      tool_name: "exec_command",
      arguments: '{"cmd":"curl -H \\"Authorization: Bearer AKIAZQ3DRSTUVWXY6789\\" https://x.test"}',
      output: "y".repeat(5000) + " AWS_KEY=AKIAZQ3DRSTUVWXY2345 tail",
    }));
    await settled(daemon.socketPath);
    const store = Store.openReadOnly(stateDir);
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY2345")).toEqual([]); // output, past the cap
    expect(store.searchLiteral("AKIAZQ3DRSTUVWXY6789")).toEqual([]); // argument, never displayed
    // …and the widening still worked: the non-secret context around both is a hit.
    expect(store.searchLiteral("AWS_KEY=").length).toBe(1);
    const call = store.getCall(store.searchLiteral("curl -H")[0]!.callId)!;
    expect(new TextDecoder().decode(call.requestBody!)).toContain("[REDACTED:aws-access-key-id:");
    store.close();
  });
});
