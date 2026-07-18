// Adversarial corpus regression (R5): every case pins an explicit verdict —
// caught (with the exact detector), clean (decoys must stay silent at every
// tier), or out-of-scope (a documented product decision, asserted so a rule
// change that starts covering it surfaces here and gets promoted to caught).
// Corpus adapted from leakproof (Apache-2.0); see the fixture's _notice.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { compileRules, scan } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";

const rules = compileRules(
  loadRuleFile(readFileSync("rules/beagle-rules.json", "utf8")),
  new Uint8Array(32).fill(5),
);

function scanText(text: string) {
  return scan(new TextEncoder().encode(text), {}, rules);
}

interface CorpusCase {
  id: string;
  kind: "leak" | "decoy";
  text: string;
  detectors: string[];
  outcome: "caught" | "clean" | "out-of-scope";
}

const corpus: { cases: CorpusCase[] } = JSON.parse(
  readFileSync("tests/fixtures/leakproof-corpus.json", "utf8"),
);

describe("leakproof adversarial corpus", () => {
  for (const c of corpus.cases) {
    test(`${c.outcome}: ${c.id}`, () => {
      const findings = scanText(c.text);
      const found = [...new Set(findings.map((f) => f.detector))];
      if (c.outcome === "caught") {
        for (const d of c.detectors) expect(found).toContain(d);
        // No loud co-fires: a structured detector this case doesn't expect is
        // a false-positive regression hiding behind a real catch.
        const extras = findings.filter((f) => f.tier === "structured" && !c.detectors.includes(f.detector));
        expect(extras).toEqual([]);
      } else {
        // clean AND out-of-scope: zero findings at any tier. If a new rule
        // starts catching an out-of-scope case, this fails on purpose —
        // update the fixture to promote the case rather than let it drift.
        expect(found).toEqual([]);
      }
    });
  }
});

describe("new vendor token rules", () => {
  const CASES: Array<[string, string]> = [
    ["gitlab-pat", "remote: glpat-AbCd3fGh1jKlMn0pQrSt"],
    ["npm-token", "//registry.npmjs.org/:_authToken=npm_Ab3dEf6hIj9lMn2pQr5tUv8xYz1Bc4De7Fg0"],
    ["pypi-token", "password = pypi-AgEIcHlwaS5vcmcCJDkwNzYtZGVhZC1iZWVmLTEyMzQtNTY3ODlhYmNkZWYwAAIqWzM"],
    ["sendgrid-key", "SENDGRID=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"],
    ["huggingface-token", "login(token='hf_Ab3dEf6hIj9lMn2pQr5tUv8xYz1Bc4De7F')"],
    ["twilio-api-key", "TWILIO_SID=SK3f9c1e8b7d62049f5e1c0a8b4d7e2f6c"],
    ["digitalocean-token", "doctl auth init -t dop_v1_3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5e3f9c1e8b7d62049f5e1c0a8b"],
    ["square-token", "SQUARE_ACCESS=sq0atp-Ab3dEf6hIj9lMn2pQr5tUv"],
    ["shopify-token", "X-Shopify-Access-Token: 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"],
    ["postman-key", "PMAK-Ab3dEf6hIj9lMn2pQr5tUv8x-Ab3dEf6hIj9lMn2pQr5tUv8xYz1Bc4De7F"],
    ["linear-key", "LINEAR_API_KEY=lin_api_Ab3dEf6hIj9lMn2pQr5tUv8xYz1Bc4De7Fg0Hi3J"],
    ["mailgun-key", "mailgun key-3f9c1e8b7d62049f5e1c0a8b4d7e2f6c"],
    ["telegram-bot-token", "bot 123456789:AAbCdEfGhIjKlMnOpQrStUvWxYz012345-8"],
    ["azure-storage-key", "AccountKey=Ab3dEf6hIj9lMn2pQr5tUv8xYz1Bc4De7Fg0Hi3Jk6Lm9No2Pq5Rs8Tu1Vw4Xy7ZAb3dEf6hIj9lMn2pQr5tUv=="],
    ["slack-webhook", "SLACK_HOOK=https://hooks.slack.com/services/T00000000/B11111111/aZ09bY18cX27dW36eV45fU54"],
    ["github-pat", "token: github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"],
  ];
  for (const [detector, text] of CASES) {
    test(detector, () => {
      const f = scanText(text);
      expect(f.map((x) => x.detector)).toContain(detector);
      expect(f.find((x) => x.detector === detector)?.tier).toBe("structured");
    });
  }
});

describe("quiet-tier fallbacks", () => {
  test("40-char AWS-secret-shaped token in prose (no anchor)", () => {
    const f = scanText("the staging secret is wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn ok?");
    const hit = f.find((x) => x.detector === "aws-secret-shape");
    expect(hit).toBeDefined();
    expect(hit?.tier).toBe("possible");
  });

  test("40-hex git sha does NOT trip the shape rule (entropy gate)", () => {
    const f = scanText("commit a3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5 pushed");
    expect(f).toEqual([]);
  });

  test("41+ char runs do not match (exact-length precision)", () => {
    const f = scanText("blob wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0BnX more");
    expect(f.some((x) => x.detector === "aws-secret-shape")).toBe(false);
  });

  test("base64-wrapped AKIA key: decoded and re-scanned", () => {
    const f = scanText("config_blob = 'QUtJQTJFMEE4RjNCOUMxRDdLNFA='");
    const hit = f.find((x) => x.detector === "base64-wrapped-secret");
    expect(hit).toBeDefined();
    expect(hit?.tier).toBe("possible");
  });

  test("base64 of innocent text stays silent", () => {
    // "hello world, this is a plain sentence."
    const f = scanText("data = 'aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBwbGFpbiBzZW50ZW5jZS4='");
    expect(f).toEqual([]);
  });

  test("random base64 junk stays silent", () => {
    const f = scanText("img = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAA='");
    expect(f).toEqual([]);
  });
});

describe("precision fixes", () => {
  test("credit card without the word 'card' nearby (cvc anchors the prescan)", () => {
    const f = scanText("charge.create(number='5500005555555559', exp='04/27', cvc='913')");
    expect(f.some((x) => x.detector === "credit-card")).toBe(true);
  });

  test("Luhn-valid ms epoch next to 'number' stays silent (no card keyword)", () => {
    const f = scanText('{"type":"number","created_at":1721234567899,"note":"retry the request"}');
    expect(f.some((x) => x.detector === "credit-card")).toBe(false);
  });

  test("vendor test keys (sk_test_) no longer trip the generic rule", () => {
    const f = scanText("STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc  # test mode only");
    expect(f).toEqual([]);
  });

  test("key--prefixed md5 without mailgun context stays silent", () => {
    const f = scanText("cache key-5f4dcc3b5aa765d61d8327deb882cf99 expired, refetching");
    expect(f).toEqual([]);
  });

  test("epoch:hash pair is not a telegram token (:AA prefix required)", () => {
    const f = scanText("row 1626890000:aB3dEf6hIj9lMn2pQr5tUv8xYz1Bc4De7Fg");
    expect(f.some((x) => x.detector === "telegram-bot-token")).toBe(false);
  });

  test("VAR=secret: '=' is a valid leading delimiter for the shape rule", () => {
    const f = scanText("S3_SAK=wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn");
    expect(f.some((x) => x.detector === "aws-secret-shape")).toBe(true);
  });

  test("VAR=base64: '=' is a valid leading delimiter for the base64 rule", () => {
    const f = scanText("BLOB=QUtJQTJFMEE4RjNCOUMxRDdLNFA=");
    expect(f.some((x) => x.detector === "base64-wrapped-secret")).toBe(true);
  });

  test("finding span covers exactly the secret, not the consumed delimiter", () => {
    const text = "x = 'wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn' ok";
    const f = scanText(text).find((x) => x.detector === "aws-secret-shape");
    expect(f).toBeDefined();
    expect(text.slice(f!.start, f!.end)).toBe("wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn");
  });
});
