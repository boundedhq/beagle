import { describe, expect, test } from "bun:test";
import { compileRules, scan, shannonEntropy, luhnValid } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HMAC_KEY = new Uint8Array(32).fill(7);
const rules = compileRules(
  loadRuleFile(readFileSync("rules/beagle-rules.json", "utf8")),
  HMAC_KEY,
);

function scanText(text: string, authValue?: string) {
  return scan(new TextEncoder().encode(text), { authValue }, rules);
}

describe("structured detectors (loud tier)", () => {
  test("AWS access key id", () => {
    const f = scanText('config = { key: "AKIAZQ3DRSTUVWXY2345" }');
    expect(f.length).toBe(1);
    expect(f[0]?.secretType).toBe("aws-access-key-id");
    expect(f[0]?.tier).toBe("structured");
    expect(f[0]?.severity).toBe("high");
  });

  test("GitHub PAT", () => {
    const f = scanText("export GH_TOKEN=ghp_A7hK9mP2qR5tW8xZ1cV4bN6jL3gF0dSe2aYb");
    expect(f.some((x) => x.secretType === "github-pat")).toBe(true);
  });

  test("Anthropic and OpenAI keys are distinguished", () => {
    const f = scanText(
      'a="sk-ant-api03-Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm" b="sk-Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0MmLl2Kk3Jj4H"',
    );
    const types = f.map((x) => x.secretType);
    expect(types).toContain("anthropic-api-key");
    expect(types).toContain("openai-api-key");
  });

  test("PEM private key block", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----";
    const f = scanText(`file contents:\n${pem}`);
    expect(f.some((x) => x.secretType === "private-key")).toBe(true);
    expect(f.find((x) => x.secretType === "private-key")?.tier).toBe("structured");
  });

  test("connection string password", () => {
    const f = scanText("DATABASE_URL=postgres://admin:hunter2secret@db.internal:5432/prod");
    const hit = f.find((x) => x.secretType === "connection-string");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("high");
  });

  test("credit card validated by Luhn", () => {
    const valid = scanText("card number: 4111111111111111");
    expect(valid.some((x) => x.secretType === "credit-card")).toBe(true);
    const invalid = scanText("card number: 4111111111111112"); // fails Luhn
    expect(invalid.some((x) => x.secretType === "credit-card")).toBe(false);
  });
});

describe("tiering & precision", () => {
  test("generic high-entropy secret is possible tier, never structured", () => {
    const f = scanText('api_key = "zQ3k9XvT2mWp8RfYhN4cLdJ6bGa1sE5u"');
    const generic = f.find((x) => x.secretType === "generic-api-key");
    expect(generic).toBeDefined();
    expect(generic?.tier).toBe("possible");
  });

  test("low-entropy generic match is gated out", () => {
    const f = scanText('api_key = "aaaaaaaaaaaaaaaaaaaaaaaa"');
    expect(f.find((x) => x.secretType === "generic-api-key")).toBeUndefined();
  });

  test("keyword prescan: no keyword, rule never fires", () => {
    // aws-secret-key requires an aws-ish keyword nearby; bare base64 must not fire it
    const f = scanText('x = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY0"');
    expect(f.find((x) => x.secretType === "aws-secret-access-key")).toBeUndefined();
  });

  test("aws-secret-key fires with keyword context", () => {
    const f = scanText('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYZZZZZKEY42"');
    expect(f.find((x) => x.secretType === "aws-secret-access-key")).toBeDefined();
  });

  test("EXAMPLE-style placeholder values are allowlisted", () => {
    const f = scanText('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"');
    expect(f.find((x) => x.secretType === "aws-secret-access-key")).toBeUndefined();
  });
});

describe("auth exception (R5)", () => {
  test("destination's own key in the body is annotated, still found", () => {
    const key = "sk-ant-api03-Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm";
    const f = scanText(`{"messages":[{"content":"my key is ${key}"}]}`, key);
    const hit = f.find((x) => x.secretType === "anthropic-api-key");
    expect(hit).toBeDefined();
    expect(hit?.destinationOwnKey).toBe(true);
  });

  test("a different credential is not annotated", () => {
    const f = scanText(
      '{"content":"sk-ant-api03-Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm"}',
      "sk-ant-api03-DIFFERENTKEYDIFFERENTKEYDIFF",
    );
    expect(f[0]?.destinationOwnKey).toBe(false);
  });
});

describe("fingerprinting", () => {
  test("same secret same fingerprint; different secret different; key-dependent", () => {
    const a1 = scanText('k="AKIAZQ3DRSTUVWXY2345"')[0]!;
    const a2 = scanText('other context "AKIAZQ3DRSTUVWXY2345" more')[0]!;
    const b = scanText('k="AKIAZQ3DRSTUVWXY6789"')[0]!;
    expect(a1.fingerprint).toBe(a2.fingerprint);
    expect(a1.fingerprint).not.toBe(b.fingerprint);

    const otherKeyRules = compileRules(
      loadRuleFile(readFileSync("rules/beagle-rules.json", "utf8")),
      new Uint8Array(32).fill(9),
    );
    const c = scan(new TextEncoder().encode('k="AKIAZQ3DRSTUVWXY2345"'), {}, otherKeyRules)[0]!;
    expect(c.fingerprint).not.toBe(a1.fingerprint);
  });

  test("fingerprint normalizes surrounding quotes/whitespace", () => {
    const a = scanText('key: "AKIAZQ3DRSTUVWXY2345"')[0]!;
    const b = scanText("key:  AKIAZQ3DRSTUVWXY2345 ")[0]!;
    expect(a.fingerprint).toBe(b.fingerprint);
  });
});

describe("case sensitivity (precision)", () => {
  test("lowercase AKIA lookalike is not flagged by the structured rule", () => {
    const f = scanText('x = "akiazq3drstuvwxy2345"');
    expect(f.find((x) => x.secretType === "aws-access-key-id")).toBeUndefined();
  });

  test("uppercase env-var style still matches the case-insensitive rules", () => {
    const f = scanText('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYZZZZZKEY42"');
    expect(f.find((x) => x.secretType === "aws-secret-access-key")).toBeDefined();
  });
});

describe("fingerprint whitespace stability", () => {
  test("re-wrapped PEM block fingerprints identically", () => {
    const body = "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn";
    const pem1 = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`;
    const pem2 = `-----BEGIN RSA PRIVATE KEY-----\n${body.slice(0, 16)}\n${body.slice(16)}\n-----END RSA PRIVATE KEY-----`;
    const f1 = scanText(pem1).find((x) => x.secretType === "private-key")!;
    const f2 = scanText(pem2).find((x) => x.secretType === "private-key")!;
    expect(f1.fingerprint).toBe(f2.fingerprint);
  });
});

describe("rule file integrity", () => {
  test("loader rejects a tampered rule file when a pin is given", () => {
    const raw = readFileSync("rules/beagle-rules.json", "utf8");
    const pin = readFileSync("rules/beagle-rules.sha256", "utf8").trim();
    expect(() => loadRuleFile(raw, pin)).not.toThrow();
    expect(() => loadRuleFile(raw + " ", pin)).toThrow(/integrity|hash/i);
  });
});

describe("helpers", () => {
  test("shannon entropy", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("zQ3k9XvT2mWp8RfY")).toBeGreaterThan(3.5);
  });
  test("luhn", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("4111111111111112")).toBe(false);
  });
});

describe("performance budget (R5/R9)", () => {
  test("1 MB body scans under 100 ms", () => {
    const chunk = 'const data = {"messages":[{"role":"user","content":"regular text with key and token words"}]};\n';
    let body = "";
    while (body.length < 1 << 20) body += chunk;
    const bytes = new TextEncoder().encode(body);
    const start = performance.now();
    scan(bytes, {}, rules);
    const ms = performance.now() - start;
    expect(ms).toBeLessThan(100);
  });
});
