import { afterAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { ScanHost } from "../src/adapters/scan-host";

const HMAC_KEY = new Uint8Array(32).fill(7);
const RULES_JSON = readFileSync("rules/beagle-rules.json", "utf8");

describe("ScanHost (worker-hosted scanner)", () => {
  const host = new ScanHost({
    rulesJson: RULES_JSON,
    hmacKey: HMAC_KEY,
    deadlineMs: 500,
  });

  afterAll(() => host.close());

  test("returns findings from the worker", async () => {
    const r = await host.scan(new TextEncoder().encode('key="AKIAZQ3DRSTUVWXY2345"'), {});
    expect(r.state).toBe("ok");
    expect(r.findings.length).toBe(1);
    expect(r.findings[0]?.secretType).toBe("aws-access-key-id");
  });

  test("deadline breach terminates the worker and reports incomplete, then recovers", async () => {
    const evil = new ScanHost({
      rulesJson: RULES_JSON,
      hmacKey: HMAC_KEY,
      deadlineMs: 300,
      extraRulesForTest: [{
        id: "redos-test",
        description: "pathological",
        regex: "(a+)+$",
        keywords: ["aaaa"],
        secretGroup: 0,
        severity: "low",
        tier: "possible",
      }],
    });
    const evilBody = "a".repeat(40) + "b"; // catastrophic backtracking on (a+)+$
    const r = await evil.scan(new TextEncoder().encode(evilBody), {});
    expect(r.state).toBe("incomplete"); // fail-safe: never a silent "clean"

    // respawned worker still serves subsequent scans
    const r2 = await evil.scan(new TextEncoder().encode('key="AKIAZQ3DRSTUVWXY2345"'), {});
    expect(r2.state).toBe("ok");
    expect(r2.findings.length).toBe(1);
    evil.close();
  }, 15_000);
});
