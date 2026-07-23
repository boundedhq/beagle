import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AlertEngine, type AlertEvent } from "../src/core/alert/engine";
import { buildAlertMessage, providerName, secretName } from "../src/notifier/alert-copy";
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

  test("a non-secret identifier creates no leak event or alert", () => {
    engine.process(callMeta(), [finding({ severity: "low", alert: false })]);
    expect(alerts).toEqual([]);
    expect(listLeakEvents(store)).toEqual([]);
  });

  test("the event carries the structured facts; wording is built downstream", () => {
    engine.process(callMeta(), [finding()]);
    const a = alerts[0]!;
    expect(a.secretType).toBe("aws-access-key-id");
    expect(a.agent).toBe("claude-code");
    expect(a.provider).toBe("anthropic");
    expect(a.model).toBe("claude-sonnet-5");
    expect(a.destinationOwnKey).toBe(false);
    expect(a.callId).toBe("01JZXKQ8WVXH5N4T2M9R7C3DEF");
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

// The human wording (non-core). Copy rules: lead with "Beagle" (macOS shows
// osascript notifications under Script Editor's identity — the text must say
// who is talking), plain words for what leaked and where, honest about the
// data having left, exactly one next step.
describe("buildAlertMessage", () => {
  const event = (over: Partial<AlertEvent> = {}): AlertEvent => ({
    eventId: "evt-1",
    callId: "01JZXKQ8WVXH5N4T2M9R7C3DEF",
    seenBefore: false,
    secretType: "aws-access-key-id",
    agent: "claude-code",
    provider: "anthropic",
    model: "claude-sonnet-5",
    destinationOwnKey: false,
    ...over,
  });

  test("three lines, each with one job: short branded title, specifics, plain body", () => {
    const msg = buildAlertMessage(event());
    // the title must survive macOS's ~35-char banner truncation
    expect(msg.title).toBe("Beagle — secret sent to Anthropic");
    expect(msg.title.length).toBeLessThanOrEqual(35);
    expect(msg.subtitle).toBe("AWS access key");
    expect(msg.body).toBe('Already sent by your claude-code agent.\nRun "beagle ui" for details.');
    // the next step lands on its own line
    expect(msg.body.split("\n").at(-1)).toBe('Run "beagle ui" for details.');
  });

  test("no lecture, no jargon: the body drops the observes-not-blocks line and the model", () => {
    const { body } = buildAlertMessage(event());
    expect(body).not.toContain("block");
    expect(body).not.toContain("claude-sonnet-5");
    expect(body).not.toContain("left your machine");
  });

  test("a repeat leak says 'again' in the title", () => {
    expect(buildAlertMessage(event({ seenBefore: true })).title)
      .toBe("Beagle — secret sent to Anthropic again");
  });

  test("the destination's own key gets the plain-words note", () => {
    const { body } = buildAlertMessage(event({ destinationOwnKey: true }));
    expect(body).toContain("Anthropic's own API key");
  });

  test("unknown provider and secret types degrade to readable fallbacks", () => {
    const msg = buildAlertMessage(
      event({ provider: "sol-inc", secretType: "sol-signing-token" }),
    );
    expect(msg.title).toBe("Beagle — secret sent to sol-inc");
    expect(msg.subtitle).toBe("sol signing token");
  });

  test("missing agent still reads as a sentence", () => {
    const { body } = buildAlertMessage(event({ agent: undefined }));
    expect(body).toBe('Already sent by an agent.\nRun "beagle ui" for details.');
  });

  test("name helpers: known mappings and fallbacks", () => {
    expect(providerName("openai")).toBe("OpenAI");
    expect(providerName("acme")).toBe("acme");
    expect(secretName("github-pat")).toBe("GitHub personal access token");
    expect(secretName("weird-new-token")).toBe("weird new token");
  });
});
