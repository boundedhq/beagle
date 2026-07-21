import { afterEach, describe, expect, test } from "bun:test";
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
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
const PC = "Reply with exactly this token and nothing else: CHARLIE3";

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

  test("an emitted answer carries its rollout line's own timestamp", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    writeFileSync(file, turn(PA, "ALPHA111") + "\n");
    const out: OtelCall[] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: file, emit: (c) => out.push(...c), now: () => 1000 });
    t.poll();
    // The line time, not the poll clock — the store's stale-attach bound
    // compares this against turn-row times, so it must reflect when the
    // answer was actually produced.
    expect(out[0]!.meta.tsResponse).toBe(Date.parse("2026-07-20T21:00:00.000Z"));
  });

  // No `timestamp` field on the lines: the parser leaves tsMs undefined.
  const bare = (role: string, text: string) => JSON.stringify({ type: "response_item", payload: msg(role, text) });

  test("a timestamp-less answer is stamped with the file's write time, frozen across re-emits", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    writeFileSync(file, [bare("user", PA), bare("assistant", "ALPHA111")].join("\n") + "\n");
    const mtime = Math.floor(statSync(file).mtimeMs);
    let clock = 1000;
    const out: OtelCall[] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: file, emit: (c) => out.push(...c), now: () => clock, retryWindowMs: 5000 });
    t.poll();
    expect(out.at(-1)!.meta.tsResponse).toBe(mtime);
    clock = 3000;
    t.poll(); // re-emit within the retry window
    // Still the discovery-time stamp. A live clock here would make every
    // re-emit look freshly produced, letting a stale answer pass the store's
    // stale-attach bound and claim a newer identical-prompt turn's row.
    expect(out.at(-1)!.meta.tsResponse).toBe(mtime);
  });

  test("a recreated tailer stamps timestamp-less answers with the file's age, not its own clock", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    writeFileSync(file, [bare("user", PA), bare("assistant", "ALPHA111")].join("\n") + "\n");
    const mtime = Math.floor(statSync(file).mtimeMs);
    // A fresh instance over an OLD file — the retire→recreate flow. Its first
    // poll is "now" however old the answers are, so stamping the poll clock
    // would make every historical answer look freshly produced and reopen the
    // duplicate-prompt race for timestamp-less lines. The file's mtime is old
    // at recreation, keeping them refusable — while a genuinely late answer
    // (back-fill) still carries the late write time it needs to attach.
    const clock = mtime + 60_000;
    const out: OtelCall[] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: file, emit: (c) => out.push(...c), now: () => clock });
    t.poll();
    expect(out.at(-1)!.meta.tsResponse).toBe(mtime);
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

  test("a stray non-date entry can't stop the walk short of the live date tree", () => {
    const root = tmp();
    // A stale copy under a non-date dir that reverse-lex order visits FIRST
    // ("stray" > "2026"). Pruning on the global best bound this copy with the
    // real tree still unseen; only a digit-named (date) match may prune.
    mkdirSync(join(root, "stray"), { recursive: true });
    const copy = join(root, "stray", "rollout-old-conv1.jsonl");
    writeFileSync(copy, turn(PA, "STALE9999") + "\n");
    utimesSync(copy, new Date(2000000), new Date(2000000)); // backdated: must also lose the mtime tiebreak
    mkdirSync(join(root, "2026", "07", "20"), { recursive: true });
    writeFileSync(join(root, "2026", "07", "20", "rollout-2026-07-20T21-00-00-conv1.jsonl"), turn(PA, "ALPHA111") + "\n");
    const out: OtelCall[] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", sessionsRoot: root, emit: (c) => out.push(...c), now: () => 1000 });
    t.poll();
    expect(out.map((c) => c.response.text)).toEqual(["ALPHA111"]);
  });

  test("stat-failure rebinds are bounded: a delete/recreate flap can't walk and re-read forever", () => {
    const root = tmp();
    const day = join(root, "2026", "07", "20");
    mkdirSync(day, { recursive: true });
    const path1 = join(day, "rollout-2026-07-20T21-00-00-conv1.jsonl");
    writeFileSync(path1, turn(PA, "ALPHA111") + "\n");
    let clock = 1000;
    const out: OtelCall[][] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", sessionsRoot: root, emit: (c) => out.push(c), now: () => clock, retryWindowMs: 0 });
    t.poll();
    expect(out.flat().map((c) => c.response.text)).toEqual(["ALPHA111"]);
    // Eight delete/recreate cycles: each spends one budgeted rebind (unbind on
    // the stat failure, re-locate and re-read on the next poll — all settled
    // content, so nothing re-emits).
    for (let i = 0; i < 8; i++) {
      rmSync(path1);
      clock += 1500; t.noteActivity(); t.poll();
      writeFileSync(path1, turn(PA, "ALPHA111") + "\n");
      clock += 1500; t.noteActivity(); t.poll();
    }
    expect(out).toHaveLength(1);
    // The ninth deletion is past the budget: the dead binding is KEPT, so a
    // resume-style file at a NEW path is not picked up — the accepted cost;
    // retirement + renewed activity later rebuilds the tailer fresh.
    rmSync(path1);
    clock += 1500; t.noteActivity(); t.poll();
    writeFileSync(join(day, "rollout-2026-07-20T22-00-00-conv1.jsonl"), turn(PA, "ALPHA111") + "\n" + turn(PB, "BRAVO222") + "\n");
    clock += 1500; t.noteActivity(); t.poll();
    expect(out).toHaveLength(1); // BRAVO not captured — no more rebinds
  });

  test("locate retries are bounded: a rollout that never appears stops being searched", () => {
    const root = tmp();
    const out: OtelCall[] = [];
    let retired = false;
    let clock = 1000;
    const t = new CodexRolloutTailer({
      convId: "conv1", sessionsRoot: root, emit: (c) => out.push(...c), now: () => clock, onRetire: () => { retired = true; },
    });
    // An active conversation whose rollout never appears (different CODEX_HOME,
    // history off): OTel activity keeps arriving, so unbounded this re-walked
    // the tree every poll for the life of the session.
    for (let i = 0; i < 20; i++) {
      clock += 40000; // beyond any backoff gate, so each poll may spend an attempt
      t.noteActivity();
      t.poll();
    }
    // The file showing up only after the budget is spent is the accepted cost —
    // it is not picked up…
    mkdirSync(join(root, "2026", "07", "20"), { recursive: true });
    writeFileSync(join(root, "2026", "07", "20", "rollout-2026-07-20T21-00-00-conv1.jsonl"), turn(PA, "ALPHA111") + "\n");
    clock += 40000;
    t.noteActivity();
    t.poll();
    expect(out).toHaveLength(0);
    expect(retired).toBe(false); // …but activity kept the (now no-op) tailer alive
    clock += 121000; // conversation goes idle — normal retirement takes over
    t.poll();
    expect(retired).toBe(true);
  });

  test("file shrink/rewrite: new content at a reused slot still emits, settled content stays settled", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    writeFileSync(file, turn(PA, "ALPHA111") + "\n" + turn(PB, "BRAVO222") + "\n");
    let clock = 1000;
    const out: OtelCall[][] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: file, emit: (c) => out.push(c), now: () => clock, retryWindowMs: 0 });
    t.poll();
    expect(out.flat().map((c) => c.response.text)).toEqual(["ALPHA111", "BRAVO222"]);
    // The file is rewritten shorter, keeping only the first turn: re-parsed
    // content that was already emitted must not re-emit…
    clock = 8000;
    writeFileSync(file, turn(PA, "ALPHA111") + "\n");
    t.poll();
    expect(out).toHaveLength(1);
    // …while a NEW answer landing at BRAVO's old array index must emit. Keying
    // firstSeen by index alone left this slot "already seen" — never emitted.
    clock = 9000;
    appendFileSync(file, turn(PC, "CHARLIE3") + "\n");
    t.poll();
    expect(out).toHaveLength(2);
    expect(out.at(-1)!.map((c) => c.response.text)).toEqual(["CHARLIE3"]);
  });

  test("a stat failure drops the binding: codex resume's fresh file is re-located", () => {
    const root = tmp();
    const day = join(root, "2026", "07", "20");
    mkdirSync(day, { recursive: true });
    writeFileSync(join(day, "rollout-2026-07-20T21-00-00-conv1.jsonl"), turn(PA, "ALPHA111") + "\n");
    let clock = 1000;
    const out: OtelCall[][] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", sessionsRoot: root, emit: (c) => out.push(c), now: () => clock, retryWindowMs: 0 });
    t.poll();
    expect(out.flat().map((c) => c.response.text)).toEqual(["ALPHA111"]);
    // `codex resume` replaces the rollout with a NEW file for the same
    // conversation, replaying the old turn and appending the new one. The old
    // binding just aged toward retirement; it must drop and re-locate instead.
    rmSync(join(day, "rollout-2026-07-20T21-00-00-conv1.jsonl"));
    writeFileSync(join(day, "rollout-2026-07-20T22-00-00-conv1.jsonl"), turn(PA, "ALPHA111") + "\n" + turn(PB, "BRAVO222") + "\n");
    clock = 8000;
    t.poll(); // stat fails — binding dropped, nothing emitted this poll
    expect(out).toHaveLength(1);
    clock = 9500;
    t.poll(); // re-located: the replayed turn is settled, the new one emits
    expect(out.at(-1)!.map((c) => c.response.text)).toEqual(["BRAVO222"]);
  });

  test("a partial JSON line at EOF completes on the next poll, UTF-8 intact", () => {
    const dir = tmp();
    const file = join(dir, "rollout-x-conv1.jsonl");
    const answer = "BRAVÖ22Ö";
    const lines = turn(PB, answer).split("\n");
    const last = Buffer.from(lines[2]!, "utf8");
    const cut = last.indexOf(0xc3) + 1; // split INSIDE the two-byte Ö
    writeFileSync(file, turn(PA, "ALPHA111") + "\n" + lines[0] + "\n" + lines[1] + "\n");
    appendFileSync(file, last.subarray(0, cut));
    let clock = 1000;
    const out: OtelCall[][] = [];
    const t = new CodexRolloutTailer({ convId: "conv1", filePath: file, emit: (c) => out.push(c), now: () => clock, retryWindowMs: 0 });
    t.poll(); // the half-written line must neither emit nor poison the parse
    expect(out.flat().map((c) => c.response.text)).toEqual(["ALPHA111"]);
    appendFileSync(file, last.subarray(cut));
    appendFileSync(file, "\n");
    clock = 2000;
    t.poll(); // the carried bytes complete the line — the answer arrives whole
    expect(out.at(-1)!.map((c) => c.response.text)).toEqual([answer]);
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

  test("retire → recreate on renewed activity re-emits the file's answers", async () => {
    const root = tmp();
    mkdirSync(join(root, "2026", "07", "20"), { recursive: true });
    writeFileSync(join(root, "2026", "07", "20", "rollout-2026-07-20T21-00-00-conv1.jsonl"), turn(PA, "ALPHA111") + "\n");
    let clock = 1000;
    const out: OtelCall[][] = [];
    const w = new CodexRolloutWatcher({ emit: (c) => out.push(c), sessionsRoot: root, pollMs: 10, now: () => clock });
    w.onActivity("conv1"); // creates the tailer; its immediate poll emits
    expect(out.flat().map((c) => c.response.text)).toEqual(["ALPHA111"]);
    // No file change and no activity past the retire grace: the next interval
    // tick retires the tailer and the watcher forgets the conversation.
    clock = 500000;
    await new Promise((r) => setTimeout(r, 250));
    const emitsWhileRetired = out.length;
    // Renewed activity must CREATE a fresh tailer, not noteActivity a dead one.
    // Its immediate poll re-reads the file and re-emits the historical answer
    // (a missed answer from the retired window recovers here; the daemon's
    // attach is idempotent, so an already-attached one simply drops).
    w.onActivity("conv1");
    expect(out).toHaveLength(emitsWhileRetired + 1);
    expect(out.at(-1)!.map((c) => c.response.text)).toEqual(["ALPHA111"]);
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
