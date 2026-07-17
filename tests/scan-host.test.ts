import { afterAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { ScanHost, dropIdentityFieldNoise } from "../src/adapters/scan-host";

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

// Protocol identity fields are expected entropy, not credentials — the
// generic detector fires on them only because the field NAME contains its
// context keyword ("prompt_cache_KEY"). Real detectors must keep firing.
describe("dropIdentityFieldNoise (protocol identity fields)", () => {
  const host = new ScanHost({ rulesJson: RULES_JSON, hmacKey: HMAC_KEY, deadlineMs: 500 });
  afterAll(() => host.close());
  const enc = (s: string) => new TextEncoder().encode(s);

  test("opencode's prompt_cache_key no longer reads as a generic api key", async () => {
    // The exact shape from a real opencode /responses request.
    const bytes = enc('{"model":"gpt-5","input":[],"prompt_cache_key":"ses_092219142ffe1QxlfF0u9eAL0B","store":false}');
    const raw = await host.scan(bytes, {});
    // the false positive is real: the generic detector fires on the raw scan…
    expect(raw.findings.some((f) => f.secretType === "generic-api-key" && f.tier === "possible")).toBe(true);
    // …and the filter drops exactly that
    expect(dropIdentityFieldNoise(bytes, raw.findings)).toEqual([]);
  });

  test("a REAL secret pasted into an identity field still flags (structured tier)", async () => {
    const bytes = enc('{"prompt_cache_key":"AKIAZQ3DRSTUVWXY2345"}');
    const kept = dropIdentityFieldNoise(bytes, (await host.scan(bytes, {})).findings);
    expect(kept.some((f) => f.secretType === "aws-access-key-id")).toBe(true);
  });

  test("the same entropy string in message CONTENT still flags", async () => {
    const bytes = enc('{"input":[{"role":"user","content":"my api key: ses_092219142ffe1QxlfF0u9eAL0B"}]}');
    const kept = dropIdentityFieldNoise(bytes, (await host.scan(bytes, {})).findings);
    expect(kept.some((f) => f.tier === "possible")).toBe(true);
  });

  test("no identity fields in the body → findings pass through untouched", async () => {
    const bytes = enc('key="AKIAZQ3DRSTUVWXY2345"');
    const findings = (await host.scan(bytes, {})).findings;
    expect(dropIdentityFieldNoise(bytes, findings)).toEqual(findings);
  });

  test("keyword-free field shapes ('user', 'session_id') never suppress — only prompt_cache_key does", async () => {
    // The generic rule can't anchor on names like "user" or "session_id"
    // (no keyword), so suppressing them would never prevent a false positive —
    // it would only swallow real findings in pasted content shaped like them.
    // A secret pasted into the top-level OpenAI "user" field: the old
    // six-field list would have suppressed this finding outright.
    const bytes = enc('{"model":"gpt-5","user":"password: kJ9x2mQ8vLp4nR7wZs3TqB6yD","input":[]}');
    const raw = await host.scan(bytes, {});
    expect(raw.findings.some((f) => f.tier === "possible")).toBe(true); // the finding exists…
    expect(dropIdentityFieldNoise(bytes, raw.findings)).toEqual(raw.findings); // …and survives
  });
});
