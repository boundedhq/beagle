import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { appendFileSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Daemon } from "../src/daemon/daemon";
import { controlRequest } from "../src/daemon/control";
import { Store } from "../src/core/store/store";
import { listCalls } from "../src/viewer/feed-query";
import { buildSessionTurns } from "../src/viewer/session-view";
import { codexPromptKey } from "../src/parsers/codex-rollout";

// A codex.user_prompt OTLP body — the shape the mapper self-labels as codex
// (event.name starts with "codex."). timeUnixNano=0 with the real time in
// observedTimeUnixNano mirrors codex 0.144.x (otlp-map recordNano). `tsMs`
// backdates the record where a test needs the turn row to predate its answer
// by a realistic gap (the store refuses attaching an answer to a NEWER row).
function codexPrompt(convId: string, prompt: string, tsMs = Date.now()) {
  return {
    resourceLogs: [{ scopeLogs: [{ scope: { name: "codex_otel.log_only" }, logRecords: [{
      timeUnixNano: "0",
      observedTimeUnixNano: String(tsMs * 1e6),
      attributes: [
        { key: "event.name", value: { stringValue: "codex.user_prompt" } },
        { key: "conversation.id", value: { stringValue: convId } },
        { key: "prompt", value: { stringValue: prompt } },
        { key: "model", value: { stringValue: "gpt-5.6-sol" } },
      ],
    }] }] }],
  };
}

const msg = (role: string, text: string) => ({ type: "message", role, content: [{ type: "output_text", text }] });

// A codex.tool_result OTLP body — how a tool execution reaches the daemon
// live, independent of (and usually before) the rollout's record of it.
function codexToolResult(convId: string, callId: string, args: string, output: string, tsMs = Date.now()) {
  return {
    resourceLogs: [{ scopeLogs: [{ scope: { name: "codex_otel.log_only" }, logRecords: [{
      timeUnixNano: "0",
      observedTimeUnixNano: String(tsMs * 1e6),
      attributes: [
        { key: "event.name", value: { stringValue: "codex.tool_result" } },
        { key: "conversation.id", value: { stringValue: convId } },
        { key: "call_id", value: { stringValue: callId } },
        { key: "tool_name", value: { stringValue: "exec_command" } },
        { key: "arguments", value: { stringValue: args } },
        { key: "output", value: { stringValue: output } },
      ],
    }] }] }],
  };
}
// Line timestamps default to NOW, as in a live session: the stale-attach bound
// compares them to the turn rows' OTel record times, so a fixed date here would
// make every stitch look stale once the wall clock passed it.
const jline = (type: string, payload: unknown, tsMs: number) => JSON.stringify({ timestamp: new Date(tsMs).toISOString(), type, payload });
function rolloutTurn(prompt: string, answer: string, tsMs = Date.now()): string {
  return [
    jline("turn_context", { turn_id: "t", model: "gpt-5.6-sol" }, tsMs),
    jline("response_item", msg("user", prompt), tsMs),
    jline("response_item", msg("assistant", answer), tsMs),
  ].join("\n") + "\n";
}

// Write a session's rollout file where locateRollout will find it (filename ends
// -<convId>.jsonl, under a date-partitioned dir).
function rolloutPath(root: string, convId: string): string {
  return join(root, "2026", "07", "20", `rollout-2026-07-20T21-32-34-${convId}.jsonl`);
}
function writeRollout(root: string, convId: string, content: string): void {
  mkdirSync(join(root, "2026", "07", "20"), { recursive: true });
  writeFileSync(rolloutPath(root, convId), content);
}

async function waitFor(cond: () => boolean | Promise<boolean>, what: string, timeoutMs = 4000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await cond())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(20);
  }
}
// Wait until every dispatched ingest batch has drained (one tracked promise per
// batch); rollout re-emits only ever drop, so they never add rows.
async function settled(socketPath: string, minCalls = 1): Promise<void> {
  await waitFor(async () => {
    const status = await controlRequest(socketPath, { cmd: "status" });
    const d = status.data as { calls: number; inflight: number };
    return d.calls >= minCalls && d.inflight === 0;
  }, `the daemon to finish ingesting ${minCalls} call(s)`);
}

describe("Codex rollout response capture end-to-end", () => {
  let stateDir: string;
  let codexRoot: string;
  let daemon: Daemon;
  let otlpPort: number;
  let token: string;

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-codexroll-"));
    codexRoot = mkdtempSync(join(tmpdir(), "beagle-codexhome-"));
    daemon = await Daemon.start({ stateDir, persistent: true, codexRolloutRootForTest: codexRoot });
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
  function readStore<T>(fn: (s: Store) => T): T {
    const s = Store.openReadOnly(stateDir);
    try {
      return fn(s);
    } finally {
      s.close();
    }
  }

  test("the rollout answer is stitched onto the OTel turn row (one row)", async () => {
    const conv = "conv-happy";
    const prompt = "Reply with exactly this token and nothing else: ALPHA111";
    writeRollout(codexRoot, conv, rolloutTurn(prompt, "ALPHA111"));
    await post(codexPrompt(conv, prompt));

    // The tailer locates the file, emits the answer, and the daemon attaches it.
    await waitFor(
      () => readStore((s) => {
        const hit = s.searchLiteral("ALPHA111 nothing")[0] ?? s.searchLiteral(prompt)[0];
        if (!hit) return false;
        const call = s.getCall(hit.callId);
        return !!call?.responseBody && new TextDecoder().decode(call.responseBody).includes("ALPHA111");
      }),
      "the rollout answer to attach to the turn row",
    );

    readStore((s) => {
      const promptHit = s.searchLiteral(prompt)[0]!;
      const call = s.getCall(promptHit.callId)!;
      expect(new TextDecoder().decode(call.responseBody!)).toBe("ALPHA111");
      expect(call.promptKey).toBe(codexPromptKey(prompt));
      // It stayed ONE row — no orphan answer, no duplicate from retry re-emits.
      expect(listCalls(s, 50).length).toBe(1);
    });
  });

  test("the answer is NOT in the outbound search index (would read as 'sent')", async () => {
    const conv = "conv-search";
    const prompt = "please summarize the CANARY_UNIQUE_PROMPT file";
    const answer = "ZEBRA_UNIQUE_ANSWER_TOKEN";
    writeRollout(codexRoot, conv, rolloutTurn(prompt, answer));
    await post(codexPrompt(conv, prompt));

    await waitFor(
      () => readStore((s) => {
        const hit = s.searchLiteral("CANARY_UNIQUE_PROMPT")[0];
        const call = hit && s.getCall(hit.callId);
        return !!call?.responseBody && new TextDecoder().decode(call.responseBody).includes(answer);
      }),
      "the answer to be stitched",
    );

    readStore((s) => {
      // Prompt (outbound) IS searchable; the model's answer (inbound) is NOT —
      // otherwise `beagle search` would report the reply as exfiltrated.
      expect(s.searchLiteral("CANARY_UNIQUE_PROMPT").length).toBe(1);
      expect(s.searchLiteral(answer).length).toBe(0);
    });
  });

  test("a turn's later messages still land: preamble attaches, final answer replaces it", async () => {
    // The live-session bug: codex narrates (preamble → tools → real answer) and
    // only the preamble survived — the final answer hit the double-attach guard
    // and, being attach-or-drop, vanished. The grown merged answer must replace
    // the shorter view on the same turn row.
    const conv = "conv-grow";
    const prompt = "how does codex memory work?";
    const preamble = "I’m using the docs skill; checking guidance first.";
    const finalAnswer = "Codex has three memory-like layers: context, local memories, AGENTS.md.";
    writeRollout(codexRoot, conv, rolloutTurn(prompt, preamble));
    await post(codexPrompt(conv, prompt));

    // Wait for the preamble to attach (the first, short view of the answer)…
    await waitFor(
      () => readStore((s) => {
        const hit = s.searchLiteral(prompt)[0];
        const call = hit && s.getCall(hit.callId);
        return !!call?.responseBody && new TextDecoder().decode(call.responseBody).includes("docs skill");
      }),
      "the preamble to attach",
    );
    // …then the real answer flushes to the SAME turn in the rollout.
    appendFileSync(rolloutPath(codexRoot, conv), jline("response_item", msg("assistant", finalAnswer), Date.now()) + "\n");

    await waitFor(
      () => readStore((s) => {
        const call = s.getCall(s.searchLiteral(prompt)[0]!.callId);
        return !!call?.responseBody && new TextDecoder().decode(call.responseBody).includes("three memory-like layers");
      }),
      "the final answer to replace the preamble view",
    );

    readStore((s) => {
      const call = s.getCall(s.searchLiteral(prompt)[0]!.callId)!;
      expect(new TextDecoder().decode(call.responseBody!)).toBe(`${preamble}\n\n${finalAnswer}`);
      expect(listCalls(s, 50).length).toBe(1); // still one row — grown, not duplicated
      expect(s.searchLiteral("memory-like layers").length).toBe(0); // inbound stays out of search
      // The feed line follows the body. Observed in real traffic: the row held
      // the full answer while its summary still advertised the preamble, so
      // the turn read as unanswered at a glance.
      expect(call.summary).toBe(`"${prompt}" → ${finalAnswer}`);
      expect(call.summary).not.toContain("docs skill");
    });
  });
  test("each stitch pushes 'call-updated' to an open viewer — and silent re-emits stay silent", async () => {
    // Guards the daemon->viewer->app.js contract for stitches. The answer lands
    // on a row that is ALREADY on screen, so it must arrive as "call-updated"
    // (app.js refetches that row) and never as "call" (app.js prepends those —
    // the turn would show up twice). Pushing NOTHING was the bug: a live
    // dashboard sat on the question until some unrelated call happened by.
    //
    // Growth is the case that makes it visible, so it's the case under test:
    // the preamble attaches, the real answer replaces it seconds later, and
    // both writes must push. The tailer also re-emits an UNCHANGED answer every
    // poll of its retry window; those must stay silent, or every open tab
    // refetches the feed, the transcript and the open detail pane on a timer.
    const conv = "conv-sse";
    const prompt = "does the open dashboard see this answer?";
    const preamble = "Let me check the docs first.";
    const finalAnswer = "It does — the row refreshes in place.";
    const ui = await controlRequest(daemon.socketPath, { cmd: "ui" });
    const url = new URL((ui.data as { url: string }).url);
    const sess = await fetch(`${url.origin}/api/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ boot: url.searchParams.get("boot") }),
    });
    const cred = ((await sess.json()) as { credential: string }).credential;
    // Subscribe BEFORE driving traffic so the pushes can't be missed. Frames
    // are split and parsed exactly as app.js does, so this exercises the shape
    // the dashboard actually consumes, not just the substring.
    const stream = await fetch(`${url.origin}/api/stream`, { headers: { "x-beagle-token": cred } });
    const reader = stream.body!.getReader();
    const events: Array<{ ev: string; data: { id?: string; sessionId?: string } }> = [];
    const pump = (async () => {
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i: number;
        while ((i = buf.indexOf("\n\n")) !== -1) {
          const frame = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const ev = /^event: (.*)$/m.exec(frame)?.[1];
          const data = /^data: (.*)$/m.exec(frame)?.[1];
          if (ev && data) events.push({ ev, data: JSON.parse(data) });
        }
      }
    })();
    const updates = () => events.filter((e) => e.ev === "call-updated");

    try {
      writeRollout(codexRoot, conv, rolloutTurn(prompt, preamble));
      await post(codexPrompt(conv, prompt));
      await waitFor(() => updates().length >= 1, "the preamble stitch to push a frame");

      // The turn's real answer flushes to the same rollout turn.
      appendFileSync(rolloutPath(codexRoot, conv), jline("response_item", msg("assistant", finalAnswer), Date.now()) + "\n");
      await waitFor(() => updates().length >= 2, "the grown answer to push its own frame", 8000);

      // Every frame names the row that changed, so a tab refreshes what it
      // already shows instead of appending a second copy of the turn.
      const row = readStore((s) => s.getCall(s.searchLiteral(prompt)[0]!.callId)!);
      expect(new TextDecoder().decode(row.responseBody!)).toBe(`${preamble}\n\n${finalAnswer}`);
      for (const u of updates()) {
        expect(u.data.id).toBe(row.id);
        expect(u.data.sessionId).toBe(row.sessionId);
      }
      // The answer never arrived as a "call": only the prompt row is a new row.
      expect(events.filter((e) => e.ev === "call").length).toBe(1);
      expect(readStore((s) => listCalls(s, 50).length)).toBe(1);

      // Now the quiet part. Several polls pass inside the retry window with the
      // answer unchanged: those re-emits are still "handled" by the store (they
      // must never re-insert) but they wrote nothing, so the frame count must
      // not move. Without the changed flag this climbs once per poll forever.
      const settledCount = updates().length;
      await Bun.sleep(4500); // ~3 polls at the default 1500ms cadence
      expect(updates().length).toBe(settledCount);
    } finally {
      await reader.cancel().catch(() => {});
      await pump.catch(() => {});
    }
  }, 25_000);

  test("a secret in the final answer never reaches the feed line, with capture redaction OFF", async () => {
    // The rule: stored bodies may keep raw text when the user turns capture
    // redaction off, but the ALWAYS-visible summary scrubs regardless. Nothing
    // else covers that for a rollout-stitched answer, where the summary text
    // arrives from the rollout file rather than a scanned request.
    //
    // Honest about what this does NOT prove. It does not discriminate how the
    // headline gets scrubbed: buildSummary is handed `derived.values` and
    // scrubs by VALUE, so feeding it a RAW headline still yields a scrubbed
    // line (mutation-verified, both config states). The pre-scrubbed
    // `derived.inbound[0]` is therefore belt-and-braces over that backstop —
    // deliberate, but no test here can tell the two apart, and pretending
    // otherwise would leave a false sense of coverage for the next reader.
    await controlRequest(daemon.socketPath, { cmd: "set-config", args: { redactOnCapture: false } });
    const conv = "conv-secret";
    const prompt = "what did that config file say?";
    const leaked = "It contained AKIAZQ3DRSTUVWXY2345 — rotate it.";
    writeRollout(codexRoot, conv, rolloutTurn(prompt, "Let me open the file."));
    await post(codexPrompt(conv, prompt));
    await waitFor(
      () => readStore((s) => !!s.getCall(s.searchLiteral(prompt)[0]?.callId ?? "")?.responseBody),
      "the preamble to attach",
    );
    appendFileSync(rolloutPath(codexRoot, conv), jline("response_item", msg("assistant", leaked), Date.now()) + "\n");
    await waitFor(
      () => readStore((s) => (s.getCall(s.searchLiteral(prompt)[0]!.callId)!.summary ?? "").includes("rotate it")),
      "the final answer to reach the summary",
    );

    readStore((s) => {
      const summary = s.getCall(s.searchLiteral(prompt)[0]!.callId)!.summary!;
      expect(summary).toContain("[REDACTED:aws-access-key-id:");
      expect(summary).not.toContain("AKIAZQ3DRSTUVWXY2345");
    });
  }, 15_000);

  test("rollout links sequence live tool rows into Pi-like calls; feed rows stay visible", async () => {
    // The full shape: the prompt and the tool execution arrive LIVE over OTLP
    // (scanned/alerted in real time, untouched by this feature); the rollout
    // then supplies the answer (stitched, shipped earlier) and the call_id →
    // turn links (turn_link) that let the viewer regroup the loose tool rows.
    const conv = "conv-fold";
    const prompt = "list the repo files";
    const t0 = Date.now();
    writeRollout(codexRoot, conv, [
      jline("turn_context", { turn_id: "t", model: "gpt-5.6-sol" }, t0 - 4000),
      jline("response_item", msg("user", prompt), t0 - 4000),
      jline("response_item", { type: "custom_tool_call", call_id: "call-f1", name: "exec", input: '{"cmd":"ls"}' }, t0 - 3000),
      jline("response_item", { type: "custom_tool_call_output", call_id: "call-f1", output: [{ type: "input_text", text: "README.md" }] }, t0 - 2000),
      jline("response_item", msg("assistant", "One file: README.md"), t0 - 1000),
    ].join("\n") + "\n");
    await post(codexPrompt(conv, prompt, t0 - 5000));
    await post(codexToolResult(conv, "call-f1", '{"cmd":"ls"}', "README.md", t0 - 3000));
    // codex double-reports each execution: the inner event carries an internal
    // id the rollout never names — no link can exist, so it must sequence by TIME.
    await post(codexToolResult(conv, "exec-3f6b1255-inner", '{"cmd":"ls"}', "README.md (inner view)", t0 - 2900));

    // The answer stitches and the links land (order between them is free).
    await waitFor(
      () => readStore((s) => {
        const hit = s.searchLiteral(prompt)[0];
        const call = hit && s.getCall(hit.callId);
        if (!call?.responseBody?.byteLength) return false;
        return s.queryAll(`SELECT 1 FROM turn_link WHERE link_key='call:call-f1'`).length === 1;
      }),
      "the answer to stitch and the links to land",
    );

    readStore((s) => {
      const promptRow = s.getCall(s.searchLiteral(prompt)[0]!.callId)!;
      const toolRow = s.getCall(s.searchLiteral("README.md")[0]!.callId)!;
      // The tool row is intact and live-captured — its summary reads the command…
      expect(toolRow.summary).toBe("ran `ls` → README.md");
      expect(toolRow.promptKey).toBeUndefined(); // never an attach target
      // …the transcript uses Pi-like boundaries: response asks for a tool,
      // the next request carries its result. The link-less inner twin follows
      // its harness sibling by time, and the final answer lands last.
      const view = buildSessionTurns(s, promptRow.sessionId);
      expect(view.turns.length).toBe(3);
      expect(view.turns[0]!.id).toBe(promptRow.id);
      expect(view.turns[0]!.messages.map((m) => m.kind ?? "text")).toEqual(["text"]);
      expect(view.turns[0]!.responseCalls).toHaveLength(1);
      expect(view.turns[1]!.messages.map((m) => m.kind)).toEqual(["result"]);
      expect(view.turns[1]!.messages[0]!.sourceId).toBe(toolRow.id);
      expect(view.turns[1]!.responseCalls).toHaveLength(1);
      expect(view.turns[2]!.messages.map((m) => m.kind)).toEqual(["result"]);
      expect(view.turns[2]!.messages[0]!.sourceId).not.toBe(toolRow.id);
      expect(view.turns[2]!.responseText).toBe("One file: README.md");
      // …and every raw capture remains in the feed after the rollout update.
      const ids = listCalls(s, 20).map((r) => r.id);
      expect(ids).toContain(promptRow.id);
      expect(ids).toContain(toolRow.id);
      expect(ids.length).toBe(3);
    });
  }, 15_000);

  test("a failing link write never costs the ANSWER stitch — links and answers share a batch", async () => {
    // Pins the batch-level invariant, not one code path: links and answers
    // ride one tailer emit, and the answer must attach no matter what the
    // link write does. Today two things independently protect it — the tailer
    // emits answers before links, AND the daemon catches link-write errors —
    // and this holds whichever of the two a future change removes.
    (daemon as unknown as { store: { linkTurns: () => void } }).store.linkTurns = () => {
      throw new Error("disk full");
    };
    const conv = "conv-linkfail";
    const prompt = "does the answer survive a link failure?";
    const t0 = Date.now();
    writeRollout(codexRoot, conv, [
      jline("response_item", msg("user", prompt), t0 - 3000),
      jline("response_item", { type: "custom_tool_call", call_id: "call-lf", name: "exec", input: '{"cmd":"true"}' }, t0 - 2000),
      jline("response_item", msg("assistant", "IT SURVIVES"), t0 - 1000),
    ].join("\n") + "\n");
    await post(codexPrompt(conv, prompt, t0 - 4000));
    await waitFor(
      () => readStore((s) => {
        const hit = s.searchLiteral(prompt)[0];
        const call = hit && s.getCall(hit.callId);
        return !!call?.responseBody && new TextDecoder().decode(call.responseBody).includes("IT SURVIVES");
      }),
      "the answer to stitch despite the link write throwing",
    );
    readStore((s) => {
      expect(s.queryAll(`SELECT 1 FROM turn_link`)).toEqual([]); // links lost, and only links
      expect(listCalls(s, 50).length).toBe(1);
    });
  }, 15_000);

  test("an answer whose prompt has no turn row is DROPPED, not orphaned", async () => {
    const conv = "conv-drop";
    // The rollout's prompt differs from the OTel prompt, so the answer's key
    // matches no stored row — it must drop, never insert a standalone row.
    writeRollout(codexRoot, conv, rolloutTurn("a totally different question", "ORPHAN_ANSWER_XYZ"));
    await post(codexPrompt(conv, "the real question that was sent"));

    await settled(daemon.socketPath); // prompt row stored + current ingests drained
    // Give the tailer's immediate poll (emit → attach-miss → drop) time to run.
    await waitFor(() => readStore((s) => s.searchLiteral("the real question").length === 1), "the prompt row");

    readStore((s) => {
      expect(listCalls(s, 50).length).toBe(1); // only the prompt row — no orphan answer
      expect(s.searchLiteral("ORPHAN_ANSWER_XYZ").length).toBe(0);
      const call = s.getCall(s.searchLiteral("the real question")[0]!.callId)!;
      expect(call.responseBody === null || call.responseBody.byteLength === 0).toBe(true);
    });
  });
});

// The stale-attach bound, end to end: the same prompt text submitted twice
// yields two rows with ONE prompt_key, and the tailer re-emits answers (retry
// window; whole-file re-read on a recreated tailer). Without the bound, a
// re-emitted turn-1 answer claimed turn 2's fresh response-less row, and the
// real turn-2 answer then hit the bytes_resp guard and was dropped forever.
describe("Codex rollout duplicate-prompt staleness", () => {
  let stateDir: string;
  let codexRoot: string;
  let daemon: Daemon | null = null;
  let otlpPort = 0;
  let token = "";

  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), "beagle-codexdup-"));
    codexRoot = mkdtempSync(join(tmpdir(), "beagle-codexdup-home-"));
  });
  afterEach(async () => {
    await daemon?.stop();
    daemon = null;
  });

  // Per-test timing: these tests compress the tailer clocks differently (fast
  // polls everywhere; a short retire only where retirement is the subject).
  async function startDaemon(timing: { pollMs?: number; retryWindowMs?: number; retireMs?: number }) {
    daemon = await Daemon.start({ stateDir, persistent: true, codexRolloutRootForTest: codexRoot, codexRolloutTimingForTest: timing });
    const status = await controlRequest(daemon.socketPath, { cmd: "status" });
    const data = status.data as { otlpPort: number; otlpToken: string };
    otlpPort = data.otlpPort;
    token = data.otlpToken;
  }
  async function post(body: unknown) {
    return fetch(`http://127.0.0.1:${otlpPort}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-beagle-run": token },
      body: JSON.stringify(body),
    });
  }
  function readStore<T>(fn: (s: Store) => T): T {
    const s = Store.openReadOnly(stateDir);
    try {
      return fn(s);
    } finally {
      s.close();
    }
  }
  // Every row in ts order with its decoded answer — identical-prompt rows are
  // indistinguishable by search, so assertions here go by position.
  function turnRows(): Array<{ id: string; ts: number; text: string }> {
    return readStore((s) =>
      s.queryAll<{ id: string; ts: number; resp: Uint8Array | null }>(
        `SELECT e.id AS id, e.ts_request AS ts, p.response_body AS resp
         FROM exchanges e LEFT JOIN payloads p ON p.exchange_id = e.id
         ORDER BY e.ts_request ASC, e.id ASC`,
      ).map((r) => ({ id: r.id, ts: r.ts, text: r.resp ? new TextDecoder().decode(r.resp) : "" })),
    );
  }

  test("a re-emitted answer never claims a newer identical-prompt row; the real answer still lands", async () => {
    await startDaemon({ pollMs: 100 });
    const conv = "conv-dup";
    const prompt = "continue";
    const t0 = Date.now();
    // Turn 1 as production writes it: the OTel prompt row predates its rollout
    // answer (the answer line lands when the turn completes, seconds later).
    writeRollout(codexRoot, conv, rolloutTurn(prompt, "ANSWER_ONE", t0 - 8000));
    await post(codexPrompt(conv, prompt, t0 - 10_000));
    await waitFor(() => turnRows().some((r) => r.text === "ANSWER_ONE"), "turn 1 to stitch");

    // The user re-types the same prompt while turn 1's answer is still inside
    // the tailer's retry window — a fresh response-less row, same prompt_key.
    await post(codexPrompt(conv, prompt));
    await settled(daemon!.socketPath, 2);
    await Bun.sleep(400); // several polls: ANSWER_ONE re-emits fire, and must refuse the new row
    expect(turnRows()[1]!.text).toBe(""); // turn 2 still awaits ITS answer

    // Turn 2 completes: the real answer must land on turn 2's row (before the
    // fix it was dropped — the row already held the stale ANSWER_ONE).
    appendFileSync(rolloutPath(codexRoot, conv), rolloutTurn(prompt, "ANSWER_TWO"));
    await waitFor(() => turnRows()[1]?.text === "ANSWER_TWO", "turn 2's real answer to stitch");
    expect(turnRows().map((r) => r.text)).toEqual(["ANSWER_ONE", "ANSWER_TWO"]);
    expect(readStore((s) => listCalls(s, 50).length)).toBe(2); // re-emits inserted nothing
  }, 15_000);

  test("a recreated tailer's historical re-emits attach nowhere; the new turn still stitches", async () => {
    // retryWindowMs FAR below the retirement sleep is load-bearing: turn 1's
    // retry re-emits are long expired by the time the duplicate prompt lands,
    // so any ANSWER_ONE re-emit after it can only come from a RECREATED tailer
    // re-reading the file — the flavor this test exists to pin. Relaxing the
    // window quietly turns this back into the retry-window test above.
    await startDaemon({ pollMs: 100, retryWindowMs: 300, retireMs: 2000 });
    const conv = "conv-retire";
    const prompt = "continue";
    const t0 = Date.now();
    writeRollout(codexRoot, conv, rolloutTurn(prompt, "ANSWER_ONE", t0 - 8000));
    await post(codexPrompt(conv, prompt, t0 - 10_000));
    await waitFor(() => turnRows().some((r) => r.text === "ANSWER_ONE"), "turn 1 to stitch");

    // No rollout growth and no OTel activity past the grace period: retired.
    await Bun.sleep(3000);

    // The same prompt text again. Its OTel activity recreates the tailer, which
    // re-reads the WHOLE file and re-emits every historical answer with a fresh
    // first-seen — the new turn's row must survive that.
    await post(codexPrompt(conv, prompt));
    await settled(daemon!.socketPath, 2);
    await Bun.sleep(400);
    expect(turnRows()[1]!.text).toBe(""); // the historical ANSWER_ONE re-emit dropped

    appendFileSync(rolloutPath(codexRoot, conv), rolloutTurn(prompt, "ANSWER_TWO"));
    await waitFor(() => turnRows()[1]?.text === "ANSWER_TWO", "turn 2's answer to stitch");
    expect(turnRows().map((r) => r.text)).toEqual(["ANSWER_ONE", "ANSWER_TWO"]);
    expect(readStore((s) => listCalls(s, 50).length)).toBe(2); // dedup left no orphan rows
  }, 15_000);

  test("a recreated tailer still back-fills a turn whose answer landed after retirement", async () => {
    await startDaemon({ pollMs: 100, retryWindowMs: 300, retireMs: 2000 });
    const conv = "conv-backfill";
    const q1 = "what is the plan?";
    await post(codexPrompt(conv, q1));
    await settled(daemon!.socketPath, 1);
    await Bun.sleep(3000); // no rollout file at all: the tailer locates nothing and retires

    // The answer reaches disk only after retirement (a generation that outlived
    // the idle window). It postdates its turn row, so the bound allows it.
    writeRollout(codexRoot, conv, rolloutTurn(q1, "LATE_ANSWER"));
    // Fresh activity on the conversation recreates the tailer, which reads the
    // file and back-fills the older turn's row.
    await post(codexPrompt(conv, "and now?"));
    await waitFor(() => turnRows()[0]?.text === "LATE_ANSWER", "the late answer to back-fill");
    expect(readStore((s) => listCalls(s, 50).length)).toBe(2);
  }, 15_000);
});
