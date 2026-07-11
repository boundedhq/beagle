import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AlertEngine, type AlertEvent } from "../src/core/alert/engine";
import type { Finding } from "../src/core/scanner/engine";
import { Store } from "../src/core/store/store";

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

const exchangeMeta = (over: Partial<{ id: string; sessionId: string; agent: string; provider: string; model: string }> = {}) => ({
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
    engine.process(exchangeMeta(), [finding()]);
    engine.process(exchangeMeta({ id: "01JZXKQ8WVXH5N4T2M9R7C3DFF" }), [finding()]);
    engine.process(exchangeMeta({ id: "01JZXKQ8WVXH5N4T2M9R7C3DGG" }), [finding()]);
    expect(alerts.length).toBe(1);
    const events = store.listLeakEvents();
    expect(events.length).toBe(1);
    expect(events[0]?.occurrences).toBe(3);
  });

  test("same fingerprint in a new session re-alerts, styled seen-before", () => {
    engine.process(exchangeMeta(), [finding()]);
    engine.process(exchangeMeta({ sessionId: "sess-2" }), [finding()]);
    expect(alerts.length).toBe(2);
    expect(alerts[0]?.seenBefore).toBe(false);
    expect(alerts[1]?.seenBefore).toBe(true);
  });

  test("possible tier records the event but never alerts", () => {
    engine.process(exchangeMeta(), [finding({ tier: "possible", secretType: "generic-api-key" })]);
    expect(alerts.length).toBe(0);
    const events = store.listLeakEvents();
    expect(events.length).toBe(1);
    expect(events[0]?.confidenceTier).toBe("possible");
  });

  test("alert copy names type, agent, destination, states data already sent, includes id prefix", () => {
    engine.process(exchangeMeta(), [finding()]);
    const a = alerts[0]!;
    expect(a.title).toContain("aws-access-key-id");
    expect(a.body).toContain("claude-code");
    expect(a.body).toContain("anthropic/claude-sonnet-5");
    expect(a.body.toLowerCase()).toContain("already been sent");
    expect(a.body).toContain("beagle show 01JZXKQ8");
  });

  test("destination's own key alerts with the annotation", () => {
    engine.process(exchangeMeta(), [finding({ destinationOwnKey: true })]);
    expect(alerts.length).toBe(1);
    expect(alerts[0]!.body.toLowerCase()).toContain("this destination's own");
  });

  test("two distinct secrets in one exchange fire two alerts", () => {
    engine.process(exchangeMeta(), [
      finding(),
      finding({ fingerprint: "fp-other", secretType: "github-pat", detector: "github-pat" }),
    ]);
    expect(alerts.length).toBe(2);
  });
});
