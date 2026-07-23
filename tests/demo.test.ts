import { describe, expect, test } from "bun:test";
import {
  cmdDemo, generateDemoCanary, startDemoMock, type DemoMock,
} from "../src/cli/demo";
import { compileRules, scan } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";
import { buildDemoAlertMessage } from "../src/notifier/alert-copy";
import rulesRaw from "../rules/beagle-rules.json" with { type: "text" };
import type { AlertEvent } from "../src/core/alert/engine";
import { BEAGLE_VERSION } from "../src/core/version";

const rules = compileRules(
  loadRuleFile(rulesRaw as unknown as string),
  new Uint8Array(32).fill(7),
);

describe("persisted local demo", () => {
  test("the generated fake value is AWS-shaped and fires the production structured rule", () => {
    const canary = generateDemoCanary(new Uint8Array(Array.from({ length: 16 }, (_, i) => i)));
    expect(canary).toMatch(/^AKIA[A-Z0-9]{16}$/);
    expect(canary.toLowerCase()).not.toMatch(/example|sample|placeholder|dummy|xxxxxx|changeme/);

    const report = scan(
      new TextEncoder().encode(`AWS_ACCESS_KEY_ID=${canary}`),
      {},
      rules,
    );
    expect(report.findings.some(
      (finding) => finding.tier === "structured" && finding.secretType === "aws-access-key-id",
    )).toBe(true);
  });

  test("mock serves a Read tool call followed by an answer on IPv4 loopback", async () => {
    const mock = await startDemoMock();
    try {
      const first = await fetch(`http://127.0.0.1:${mock.port}/v1/messages`, { method: "POST" });
      expect(first.headers.get("content-type")).toContain("text/event-stream");
      const toolCall = await first.text();
      expect(toolCall).toContain('"type":"tool_use"');
      expect(toolCall).toContain('"name":"Read"');
      expect(toolCall).toContain('/tmp/beagle-canary/.env');
      expect(toolCall).toContain('"stop_reason":"tool_use"');

      const second = await fetch(`http://127.0.0.1:${mock.port}/v1/messages`, { method: "POST" });
      const answer = await second.text();
      expect(answer).toContain("I found an AWS access key ID in the project’s .env file");
      expect(answer).toContain("Avoid pasting credentials into chats or logs");
    } finally {
      await mock.close();
    }
  });

  test("success uses daemon persistence, opens the session, and prints cleanup", async () => {
    const calls: string[] = [];
    let stdout = "";
    let stderr = "";
    const mock: DemoMock = { port: 1234, close: async () => { calls.push("close"); } };
    const daemon = {
      pid: 1,
      proxyPort: 4321,
      socketPath: "/tmp/demo.sock",
      runningVersion: BEAGLE_VERSION,
    };

    const exitCode = await cmdDemo("/tmp/beagle-demo-test", {
      generateCanary: () => generateDemoCanary(new Uint8Array(16).fill(9)),
      startMock: async () => { calls.push("mock"); return mock; },
      ensureDaemon: async () => { calls.push("daemon"); return daemon; },
      exchange: async (_daemon, usedMock, _canary, runId) => {
        expect(usedMock).toBe(mock);
        expect(runId.startsWith("demo-")).toBe(true);
        calls.push("exchange");
      },
      waitForLeak: async () => { calls.push("persist"); return { sessionId: "session-demo" }; },
      openUi: async (_stateDir, sessionId) => {
        expect(sessionId).toBe("session-demo");
        calls.push("ui");
        return "dashboard: http://127.0.0.1/demo";
      },
      out: (text) => { stdout += text; },
      err: (text) => { stderr += text; },
    });

    expect(exitCode).toBe(0);
    expect(stderr).toBe("");
    expect(calls).toEqual(["mock", "daemon", "exchange", "persist", "ui", "close"]);
    expect(stdout).toContain("normal daemon path");
    expect(stdout).toContain("reading it from a local .env file");
    expect(stdout).toContain("[demo] badge");
    expect(stdout).toContain("dashboard: http://127.0.0.1/demo");
    expect(stdout).toContain("nothing left this machine");
    expect(stdout).toContain("beagle demo --clean");
  });

  test("a mock bind failure prevents daemon contact and exchange", async () => {
    let daemonCalls = 0;
    let exchangeCalls = 0;
    let stderr = "";

    const exitCode = await cmdDemo("/tmp/beagle-demo-test", {
      startMock: async (): Promise<DemoMock> => { throw new Error("loopback bind failed"); },
      ensureDaemon: async () => { daemonCalls++; return null; },
      exchange: async () => { exchangeCalls++; },
      out: () => {},
      err: (text) => { stderr += text; },
    });

    expect(exitCode).toBe(1);
    expect(daemonCalls).toBe(0);
    expect(exchangeCalls).toBe(0);
    expect(stderr).toContain("failed safely");
    expect(stderr).toContain("No request was sent to a model provider");
  });

  test("an older running daemon is refused because it cannot render an honest drill", async () => {
    let exchangeCalls = 0;
    let stderr = "";
    const mock: DemoMock = { port: 1234, close: async () => {} };

    const exitCode = await cmdDemo("/tmp/beagle-demo-test", {
      startMock: async () => mock,
      ensureDaemon: async () => ({
        pid: 42,
        proxyPort: 4321,
        socketPath: "/tmp/demo.sock",
        runningVersion: "0.0.1",
      }),
      exchange: async () => { exchangeCalls++; },
      out: () => {},
      err: (text) => { stderr += text; },
    });

    expect(exitCode).toBe(1);
    expect(exchangeCalls).toBe(0);
    expect(stderr).toContain("running daemon is v0.0.1");
    expect(stderr).toContain("restart it before the drill");
  });

  test("demo notification copy never implies a real provider leak", () => {
    const message = buildDemoAlertMessage({ secretType: "aws-access-key-id" } as AlertEvent);
    expect(message.title).toContain("Beagle [demo]");
    expect(message.body).toContain("Drill only");
    expect(message.body).toContain("loopback mock");
    expect(message.body).not.toContain("Already sent");
  });
});
