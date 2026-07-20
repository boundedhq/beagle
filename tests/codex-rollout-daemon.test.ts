import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Daemon } from "../src/daemon/daemon";
import { controlRequest } from "../src/daemon/control";
import { Store } from "../src/core/store/store";
import { listCalls } from "../src/viewer/feed-query";
import { codexPromptKey } from "../src/parsers/codex-rollout";

// A codex.user_prompt OTLP body — the shape the mapper self-labels as codex
// (event.name starts with "codex."). timeUnixNano=0 with the real time in
// observedTimeUnixNano mirrors codex 0.144.x (otlp-map recordNano).
function codexPrompt(convId: string, prompt: string) {
  return {
    resourceLogs: [{ scopeLogs: [{ scope: { name: "codex_otel.log_only" }, logRecords: [{
      timeUnixNano: "0",
      observedTimeUnixNano: String(Date.now() * 1e6),
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
const jline = (type: string, payload: unknown) => JSON.stringify({ timestamp: "2026-07-20T21:32:45.500Z", type, payload });
function rolloutTurn(prompt: string, answer: string): string {
  return [
    jline("turn_context", { turn_id: "t", model: "gpt-5.6-sol" }),
    jline("response_item", msg("user", prompt)),
    jline("response_item", msg("assistant", answer)),
  ].join("\n") + "\n";
}

// Write a session's rollout file where locateRollout will find it (filename ends
// -<convId>.jsonl, under a date-partitioned dir).
function writeRollout(root: string, convId: string, content: string): void {
  const dir = join(root, "2026", "07", "20");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `rollout-2026-07-20T21-32-34-${convId}.jsonl`), content);
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
