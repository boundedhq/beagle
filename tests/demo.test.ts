import { describe, expect, test } from "bun:test";
import { cmdDemo, demoAlertMessage, generateDemoCanary, type DemoMock } from "../src/cli/demo";
import { compileRules, scan, type Finding } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";
import rulesRaw from "../rules/beagle-rules.json" with { type: "text" };
import type { AlertMessage } from "../src/notifier/notifier";

const rules = compileRules(
  loadRuleFile(rulesRaw as unknown as string),
  new Uint8Array(32).fill(7),
);

describe("stateless local demo", () => {
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

  test("runs the real proxy + worker scanner, alerts, and retains no demo event", async () => {
    const canary = generateDemoCanary(new Uint8Array(16).fill(9));
    const notices: AlertMessage[] = [];
    let stdout = "";
    let stderr = "";

    const exitCode = await cmdDemo({
      generateCanary: () => canary,
      notify: (message) => notices.push(message),
      out: (text) => { stdout += text; },
      err: (text) => { stderr += text; },
    });

    expect(exitCode).toBe(0);
    expect(stderr).toBe("");
    expect(notices).toHaveLength(1);
    expect(notices[0]?.title).toContain("Beagle demo");
    expect(notices[0]?.subtitle).toBe("AWS access key");
    expect(notices[0]?.body).toContain("loopback mock");
    expect(notices[0]?.body).not.toContain("beagle ui");
    expect(stdout).toContain("real proxy and scanner");
    expect(stdout).toContain("Nothing left this machine");
    expect(stdout).toContain("nothing was retained");
    expect(stdout).not.toContain(canary);
  });

  test("a mock bind failure prevents the exchange and notification", async () => {
    let exchangeCalls = 0;
    let notifyCalls = 0;
    let stderr = "";
    const unusedFinding = {} as Finding;

    const exitCode = await cmdDemo({
      startMock: async (): Promise<DemoMock> => { throw new Error("loopback bind failed"); },
      exchange: async () => { exchangeCalls++; return unusedFinding; },
      notify: () => { notifyCalls++; },
      out: () => {},
      err: (text) => { stderr += text; },
    });

    expect(exitCode).toBe(1);
    expect(exchangeCalls).toBe(0);
    expect(notifyCalls).toBe(0);
    expect(stderr).toContain("failed safely");
    expect(stderr).toContain("No request was sent to a model provider");
  });

  test("demo notification copy does not imply a real leak or saved dashboard row", () => {
    const message = demoAlertMessage({ secretType: "aws-access-key-id" } as Finding);
    expect(message.body).toContain("Drill only");
    expect(message.body).toContain("nothing was retained");
    expect(message.body).not.toContain("Already sent");
    expect(message.body).not.toContain("beagle ui");
  });
});
