// Adversarial corpus regression (R5): every case pins an explicit verdict —
// caught (with the exact detector), suppressed (recognized internally but
// never reported as a leak), clean (decoys stay silent at every tier), or
// out-of-scope (a documented product decision, asserted so a rule change that
// starts covering it surfaces here and gets promoted to caught).
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
  return scan(new TextEncoder().encode(text), {}, rules).findings;
}

interface CorpusCase {
  id: string;
  kind: "leak" | "decoy";
  text: string;
  detectors: string[];
  outcome: "caught" | "suppressed" | "clean" | "out-of-scope";
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
      } else if (c.outcome === "suppressed") {
        for (const d of c.detectors) expect(found).toContain(d);
        expect(findings.filter((f) => f.alert !== false)).toEqual([]);
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

describe("vendor identifiers that are not secrets", () => {
  test("Twilio API Key SID is not flagged, across delimiter spellings", () => {
    const sid = "SK3f9c1e8b7d62049f5e1c0a8b4d7e2f6c"; // SK + 32 lowercase hex
    // Each string places the SID where the generic rule WOULD fire without the
    // exclusion (keyword within 1-5 separator chars of the value) — verified by
    // mutation: with the exclusion removed, every one of these produces a
    // generic-api-key finding, so each genuinely exercises the guard.
    for (const text of [
      `TWILIO_API_KEY=${sid}`,
      JSON.stringify({ api_key: sid }), // JSON: api_key":"<sid>
      `2026-01-02 provisioned twilio key=${sid}`, // log line
      // '=' donation: the greedy key-separator class shares '=' with the value
      // class and can push one into the value by backtracking; the guard's =*
      // prefix must still suppress these (regression pin for that bypass).
      `key =${sid}`,
      `key:=${sid}`,
      `key==${sid}`,
    ]) {
      expect(scanText(text)).toEqual([]);
    }
  });

  test("the Twilio SID exclusion does not suppress neighboring generic shapes", () => {
    const sid = "SK3f9c1e8b7d62049f5e1c0a8b4d7e2f6c";
    for (const value of [
      `${sid}A`, // SID + trailing char: no longer the whole-value SID shape
      sid.toLowerCase(), // lowercase 'sk' prefix: not a Twilio SID
      "SK" + sid.slice(2).toUpperCase(), // SK + UPPER hex: outside the real (lowercase) SID space
    ]) {
      expect(scanText(`api_key=${value}`).some((f) => f.detector === "generic-api-key")).toBe(true);
    }
  });
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

  // The exact-length defense above holds only for STANDARD base64. In base64url
  // '-' and '_' are VALUE characters, but they are not in the rule's
  // [A-Za-z0-9/+] class, so they used to read as delimiters and cut one long
  // blob into a stream of 40-char candidates. Found in live traffic: an OpenAI
  // `encrypted_content` reasoning payload — provider ciphertext the client
  // resends every turn — reported 7 "AWS secrets" across 165 request bodies,
  // each a mid-blob slice bounded by '-' or '_'.
  test("a 40-char window inside a base64url blob does NOT match (the encrypted_content FP)", () => {
    // 40 valid base64 chars with a base64url value char on each side: the exact
    // shape a long `-`/`_`-bearing blob presents over and over.
    const window = "wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn";
    for (const [before, after] of [["-", "_"], ["_", "_"], ["-", "-"], ["_", "-"]]) {
      const f = scanText(`eyJhbGc${before}${window}${after}Qk1FRA`);
      expect(f.some((x) => x.detector === "aws-secret-shape")).toBe(false);
    }
  });

  test("a real key is still found when a normal delimiter bounds it", () => {
    // The counterpart the fix must not break: quote, '=', whitespace and line
    // end all still delimit. Guards against over-tightening into silence.
    const key = "wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn";
    for (const text of [`secret is ${key} ok`, `S3_SAK=${key}`, `"${key}"`, `${key}`, `sig=${key}&t=1`]) {
      expect(scanText(text).some((x) => x.detector === "aws-secret-shape")).toBe(true);
    }
  });

  test("a real key ABUTTING '-'/'_' is deliberately given up by THIS rule", () => {
    // Not a benign non-match — a genuine key, missed on purpose. Pinning the
    // accepted tradeoff so relaxing the delimiter classes back can't pass
    // silently. It is not a shape keys are written in, and the keyword-bearing
    // forms are covered elsewhere: the SAME key under an AWS keyword still
    // alerts, at the higher structured tier, via aws-secret-access-key.
    const key = "wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn";
    for (const text of [`KEY_${key}`, `${key}_v2`, `id-${key}`, `${key}-old`]) {
      expect(scanText(text).some((x) => x.detector === "aws-secret-shape")).toBe(false);
    }
    // …but the same bytes in a keyworded context are NOT lost — the structured
    // rule catches what the anchor-free shape rule steps back from.
    const kept = scanText(`AWS_SECRET_ACCESS_KEY=${key}`);
    expect(kept.some((x) => x.detector === "aws-secret-access-key" && x.tier === "structured")).toBe(true);
  });

  test("base64-wrapped AWS secret access key: decoded and re-scanned", () => {
    const f = scanText("config_blob = 'QVdTX1NFQ1JFVF9BQ0NFU1NfS0VZPXdKYTFyWFV0bkYzTUk0SzdNREVOR2JQeFJmOUNZWjhxTG0yVnQwQm4='");
    const hit = f.find((x) => x.detector === "base64-wrapped-secret");
    expect(hit).toBeDefined();
    expect(hit?.tier).toBe("possible");
  });

  test("base64-wrapped documentation key is suppressed like the plaintext one", () => {
    // base64("AKIAIOSFODNN7EXAMPLE") — the direct rule drops it on the
    // "example" stopword; the decode probe must apply the same gate.
    const f = scanText("blob = 'QUtJQUlPU0ZPRE5ON0VYQU1QTEU='");
    expect(f.some((x) => x.detector === "base64-wrapped-secret")).toBe(false);
  });

  test("a real wrapped secret is still found after many benign base64 blobs", () => {
    // Probe budget is a deadline backstop, not a detection cap: a genuine
    // wrapped secret must survive a wall of benign high-entropy base64.
    const noise = Array.from({ length: 2000 }, (_, i) =>
      `"t":"${Buffer.from(`benign-token-${i}-xyz`).toString("base64")}"`).join(",");
    const f = scanText(`{${noise},"real":"QVdTX1NFQ1JFVF9BQ0NFU1NfS0VZPXdKYTFyWFV0bkYzTUk0SzdNREVOR2JQeFJmOUNZWjhxTG0yVnQwQm4="}`);
    expect(f.some((x) => x.detector === "base64-wrapped-secret")).toBe(true);
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

  // The structured rule's twin of the shape rule's hex gate above. Its keyword
  // window ([a-zA-Z_ ]{0,20}) bounds this only by accident of phrasing, so
  // before entropy 4.0 every one of these was a high-severity alert on a
  // digest. Each fires at 3.0, and the third adds an UPPERCASE digest — same
  // 16-symbol ceiling, and this rule is case-insensitive. These go fully
  // silent because no generic keyword precedes the digest; for the shapes
  // where one does, see the downgrade test below.
  test("40-hex digest near an 'aws' keyword is not a structured leak", () => {
    for (const text of [
      "aws deploy commit a3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5",
      "aws build sha 3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5e",
      "aws commit A3F9C1E8B7D62049F5E1C0A8B4D7E2F6C9A1B3D5",
    ]) {
      expect(scanText(text)).toEqual([]);
    }
  });

  // Recall guard, and the reason this rule sits at 4.0 rather than borrowing
  // aws-secret-shape's 4.5. Both fixtures are real base64-of-30-random-bytes
  // keys drawn from the ~1.8% tail that lands between the two gates (4.396 and
  // 4.446) — they pass here and would be silently MISSED at 4.5, so they pin
  // the floor against a future FP being "fixed" by cranking the gate up to the
  // sibling's value. Deliberately not the wJalr… key every other suite uses:
  // at 4.71 it clears both gates and would pin nothing.
  test("a real AWS secret key still trips the structured tier after the hex gate", () => {
    for (const text of [
      "aws_secret_access_key: FHMoLafZBokrItqNbuBFuxaMxrL0Cru2fNSo0Ixm",
      "AWS_SECRET_ACCESS_KEY=uU52LWLuUdCm1EbfHbg+suqJXujmLA2+ZffsxzU2",
    ]) {
      const hit = scanText(text).find((x) => x.detector === "aws-secret-access-key");
      expect(hit).toBeDefined();
      expect(hit?.tier).toBe("structured");
    }
  });

  // The one behavior change beyond silencing the FP. Where a generic keyword
  // (key/secret/token) also precedes the digest, suppressOverlaps had been
  // hiding generic-api-key behind the structured hit, so dropping the loud
  // finding reveals it: these move structured/high -> possible/medium rather
  // than going silent. A downgrade, not a new FP. The second case is the
  // quoted .env shape this rule widened its separator for; the third is the
  // hyphenated GitHub Actions spelling the -key anchor newly reaches, which
  // made a digest pasted there a high-severity alert. Pinned so neither the
  // tier nor the silence can drift back.
  test("digest after a generic keyword downgrades to the quiet tier, not silence", () => {
    for (const text of [
      "secret_access_key: 199ff3573afbe988e42a1e9d9ff95fd8334dd6aa",
      'aws_secret_access_key = "a3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5"',
      "aws-secret-access-key: a3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5",
    ]) {
      const f = scanText(text);
      expect(f.some((x) => x.tier === "structured")).toBe(false);
      expect(f.find((x) => x.detector === "generic-api-key")?.tier).toBe("possible");
    }
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
    const f = scanText("BLOB=QVdTX1NFQ1JFVF9BQ0NFU1NfS0VZPXdKYTFyWFV0bkYzTUk0SzdNREVOR2JQeFJmOUNZWjhxTG0yVnQwQm4=");
    expect(f.some((x) => x.detector === "base64-wrapped-secret")).toBe(true);
  });

  test("finding span covers exactly the secret, not the consumed delimiter", () => {
    const text = "x = 'wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn' ok";
    const f = scanText(text).find((x) => x.detector === "aws-secret-shape");
    expect(f).toBeDefined();
    expect(text.slice(f!.start, f!.end)).toBe("wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn");
  });
});
