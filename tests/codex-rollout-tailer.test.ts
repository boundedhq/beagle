import { afterEach, describe, expect, test } from "bun:test";
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CodexRolloutTailer, CodexRolloutWatcher } from "../src/adapters/codex-rollout-tailer";
import { codexPromptKey } from "../src/parsers/codex-rollout";
import type { OtelCall } from "../src/parsers/otlp-map";

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "beagle-rollout-"));
  tmpDirs.push(d);
  return d;
}

const msg = (role: string, text: string) => ({ type: "message", role, content: [{ type: "output_text", text }] });
const jline = (type: string, payload: unknown, ts = "2026-07-20T21:00:00.000Z") => JSON.stringify({ timestamp: ts, type, payload });
function turn(prompt: string, answer: string): string {
  return [
    jline("turn_context", { turn_id: "t", model: "gpt-5.6-sol" }),
    jline("response_item", msg("user", prompt)),
    jline("response_item", msg("assistant", answer)),
  ].join("\n");
}
const PA = "Reply with exactly this token and nothing else: ALPHA111";
const PB = "Reply with exactly this token and nothing else: BRAVO222";

describe("CodexRolloutTailer", () => {
  test("emits a response-only, codex-rollout call per answer", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    writeFileSync(file, turn(PA, "ALPHA111") + "\n");
    const out: OtelCall[] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: file, emit: (c) => out.push(...c), now: () => 1000 });
    t.poll();
    expect(out).toHaveLength(1);
    const c = out[0]!;
    expect(c.origin).toBe("codex-rollout");
    expect(c.source).toBe("otel");
    expect(c.agent).toBe("codex");
    expect(c.convId).toBe("conv1");
    expect(c.promptId).toBe(codexPromptKey(PA));
    expect(c.response.text).toBe("ALPHA111");
    expect(c.request.bodyBytes.byteLength).toBe(0); // response-only
  });

  test("re-emits within the retry window (race recovery), not after", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    writeFileSync(file, turn(PA, "ALPHA111") + "\n");
    let clock = 1000;
    const out: OtelCall[][] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: file, emit: (c) => out.push(c), now: () => clock, retryWindowMs: 5000 });
    t.poll(); // t=1000, first emit
    clock = 3000; // within window
    t.poll();
    expect(out.at(-1)!.map((c) => c.response.text)).toEqual(["ALPHA111"]); // re-emitted for retry
    const emitsBefore = out.length;
    clock = 7000; // past the 5000 window
    t.poll();
    expect(out.length).toBe(emitsBefore); // nothing emitted — no longer re-emitted
  });

  test("emits a newly-appended turn, without re-emitting a settled one", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    writeFileSync(file, turn(PA, "ALPHA111") + "\n");
    let clock = 1000;
    const out: OtelCall[][] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: file, emit: (c) => out.push(c), now: () => clock, retryWindowMs: 5000 });
    t.poll();
    clock = 8000; // ALPHA now past its retry window
    appendFileSync(file, "\n" + turn(PB, "BRAVO222"));
    t.poll();
    expect(out.at(-1)!.map((c) => c.response.text)).toEqual(["BRAVO222"]);
  });

  test("retires after the grace period with no change or activity", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    writeFileSync(file, turn(PA, "ALPHA111") + "\n");
    let clock = 1000;
    let retired = false;
    const t = new CodexRolloutTailer({
      convId: "conv1", filePath: file, emit: () => {}, now: () => clock, retireMs: 30000, onRetire: () => { retired = true; },
    });
    t.poll();
    expect(retired).toBe(false);
    clock = 1000 + 31000;
    t.poll();
    expect(retired).toBe(true);
  });

  test("a missing/unreadable file never throws", () => {
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: "/no/such/rollout.jsonl", emit: () => { throw new Error("should not emit"); }, now: () => 1000 });
    expect(() => t.poll()).not.toThrow();
  });

  test("locates a rollout that only appears AFTER the tailer starts", () => {
    const root = tmp();
    const out: OtelCall[] = [];
    let clock = 1000;
    const t = new CodexRolloutTailer({ convId: "conv-late", sessionsRoot: root, emit: (c) => out.push(...c), now: () => clock });
    t.poll(); // file not there yet — locate finds nothing, nothing emitted
    expect(out).toHaveLength(0);
    mkdirSync(join(root, "2026", "07", "20"), { recursive: true });
    writeFileSync(join(root, "2026", "07", "20", "rollout-2026-07-20T21-00-00-conv-late.jsonl"), turn(PA, "ALPHA111") + "\n");
    clock = 2000;
    t.poll(); // now the tailer locates it and emits
    expect(out.map((c) => c.response.text)).toEqual(["ALPHA111"]);
  });
});

describe("CodexRolloutWatcher", () => {
  test("locates the rollout by conversation id and emits its answers", () => {
    const root = tmp();
    mkdirSync(join(root, "2026", "07", "20"), { recursive: true });
    writeFileSync(join(root, "2026", "07", "20", "rollout-2026-07-20T21-00-00-conv-abc.jsonl"), turn(PA, "ALPHA111") + "\n");
    const out: OtelCall[] = [];
    const w = new CodexRolloutWatcher({ emit: (c) => out.push(...c), sessionsRoot: root, now: () => 1000 });
    w.onActivity("conv-abc");
    expect(out.map((c) => c.response.text)).toContain("ALPHA111");
    w.stop();
  });

  test("an unknown conversation (no file) emits nothing and does not throw", () => {
    const root = tmp();
    const out: OtelCall[] = [];
    const w = new CodexRolloutWatcher({ emit: (c) => out.push(...c), sessionsRoot: root, now: () => 1000 });
    expect(() => w.onActivity("nope")).not.toThrow(); // tailer created, locates nothing, will retire
    expect(out).toHaveLength(0);
    w.stop();
  });

  test("onActivity after stop() is a no-op (no interval outlives shutdown)", () => {
    const root = tmp();
    mkdirSync(join(root, "2026", "07", "20"), { recursive: true });
    writeFileSync(join(root, "2026", "07", "20", "rollout-2026-07-20T21-00-00-conv-late.jsonl"), turn(PA, "ALPHA111") + "\n");
    const out: OtelCall[] = [];
    const w = new CodexRolloutWatcher({ emit: (c) => out.push(...c), sessionsRoot: root, now: () => 1000 });
    w.stop();
    w.onActivity("conv-late"); // a late-draining ingest must not spawn a tailer now
    expect(out).toHaveLength(0);
  });
});
