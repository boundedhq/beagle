import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AlertEngine, type AlertEvent } from "../src/core/alert/engine";
import type { Finding } from "../src/core/scanner/engine";
import { Store } from "../src/core/store/store";
import { listLeakEvents } from "../src/viewer/feed-query";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    detector: "aws-access-key-id",
    secretType: "aws-access-key-id",
    severity: "high",
    tier: "structured",
    start: 10,
    end: 30,
    fingerprint: "fp-abc",
    destinationOwnKey: false,
    ...overrides,
  };
}

const callMeta = (over: Partial<{ id: string; sessionId: string; agent: string; provider: string; model: string }> = {}) => ({
  id: "01JZXKQ8WVXH5N4T2M9R7C3DEF",
  sessionId: "sess-1",
  agent: "claude-code",
  provider: "anthropic",
  model: "claude-sonnet-5",
  ...over,
});

describe("AlertEngine", () => {
  let store: Store;
  let alerts: AlertEvent[];
  let engine: AlertEngine;

  beforeEach(() => {
    store = Store.open(mkdtempSync(join(tmpdir(), "beagle-alert-")));
    alerts = [];
    engine = new AlertEngine(store, (a) => alerts.push(a));
  });

  test("first structured finding alerts once; re-sends update silently", () => {
    engine.process(callMeta(), [finding()]);
    engine.process(callMeta({ id: "01JZXKQ8WVXH5N4T2M9R7C3DFF" }), [finding()]);
    engine.process(callMeta({ id: "01JZXKQ8WVXH5N4T2M9R7C3DGG" }), [finding()]);
    expect(alerts.length).toBe(1);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]?.occurrences).toBe(3);
  });

  test("same fingerprint in a new session re-alerts, styled seen-before", () => {
    engine.process(callMeta(), [finding()]);
    engine.process(callMeta({ sessionId: "sess-2" }), [finding()]);
    expect(alerts.length).toBe(2);
    expect(alerts[0]?.seenBefore).toBe(false);
    expect(alerts[1]?.seenBefore).toBe(true);
  });

  test("possible tier records the event but never alerts", () => {
    engine.process(callMeta(), [finding({ tier: "possible", secretType: "generic-api-key" })]);
    expect(alerts.length).toBe(0);
    const events = listLeakEvents(store);
    expect(events.length).toBe(1);
    expect(events[0]?.confidenceTier).toBe("possible");
  });

  test("alert copy names type, agent, destination, states data already sent, includes id prefix", () => {
    engine.process(callMeta(), [finding()]);
    const a = alerts[0]!;
    expect(a.title).toContain("aws-access-key-id");
    expect(a.body).toContain("claude-code");
    expect(a.body).toContain("anthropic/claude-sonnet-5");
    expect(a.body.toLowerCase()).toContain("already been sent");
    // 12-char prefix: same-millisecond ULIDs share their first 8 chars
    expect(a.body).toContain("beagle show 01JZXKQ8WVXH");
  });

  test("destination's own key alerts with the annotation", () => {
    engine.process(callMeta(), [finding({ destinationOwnKey: true })]);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.body.toLowerCase()).toContain("this destination's own");
  });

  test("mid-session model switch does not re-alert (dedup keys on provider)", () => {
    engine.process(callMeta({ model: "claude-opus-4-8" }), [finding()]);
    engine.process(
      callMeta({ id: "01JZXKQ8WVXH5N4T2M9R7C3DHH", model: "claude-sonnet-5" }),
      [finding()],
    );
    expect(alerts.length).toBe(1);
  });

  test("two distinct secrets in one call fire two alerts", () => {
    engine.process(callMeta(), [
      finding(),
      finding({ fingerprint: "fp-other", secretType: "github-pat", detector: "github-pat" }),
    ]);
    expect(alerts.length).toBe(2);
  });
});
