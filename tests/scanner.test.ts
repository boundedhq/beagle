import { describe, expect, test } from "bun:test";
import { compileRules, scan, shannonEntropy, luhnValid, maskJsonEscapes, fingerprint } from "../src/core/scanner/engine";
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

describe("fingerprint stability across wrapping and wire encoding", () => {
  const BODY = "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn";
  const pem = (body: string) =>
    `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`;
  const fpOf = (text: string) =>
    scanText(text).find((x) => x.secretType === "private-key")!.fingerprint;

  test("re-wrapped PEM block fingerprints identically", () => {
    expect(fpOf(pem(BODY))).toBe(fpOf(pem(`${BODY.slice(0, 16)}\n${BODY.slice(16)}`)));
  });

  test("JSON-encoded PEM fingerprints identically to one with real newlines", () => {
    // A body is scanned as raw bytes, so the JSON copy carries its newlines as
    // the two characters \ + n — neither is whitespace, so a /\s+/-only strip
    // hashes them and the one key dedups as two.
    expect(fpOf(JSON.stringify({ content: pem(BODY) }))).toBe(fpOf(`file:\n${pem(BODY)}`));
  });

  test("a slash-escaping JSON encoder fingerprints identically too", () => {
    // maskJsonEscapes() leaves `\/` alone by design, so this case is the reason
    // fingerprint() decodes rather than reusing the mask.
    const withSlash = pem("MIIEowIBAAKCAQEA0Z3/VS5JJcds3xfn");
    expect(fpOf(JSON.stringify({ c: withSlash }).replace(/\//g, "\\/"))).toBe(fpOf(withSlash));
  });

  test("\\uXXXX-escaped newlines fingerprint identically", () => {
    expect(fpOf(JSON.stringify({ c: pem(BODY) }).replace(/\\n/g, "\\u000a"))).toBe(fpOf(pem(BODY)));
  });

  test("CRLF line endings fingerprint identically", () => {
    expect(fpOf(JSON.stringify({ c: pem(BODY) }).replace(/\\n/g, "\\r\\n"))).toBe(fpOf(pem(BODY)));
  });

  test("distinct PEM bodies stay distinct", () => {
    expect(fpOf(JSON.stringify({ c: pem(BODY) }))).not.toBe(fpOf(pem(BODY.replace("0Z3", "0Z4"))));
  });

  test("an escaped backslash does not decode into the escape after it", () => {
    // `\\n` is a literal backslash then n, NOT a newline — true only because the
    // single left-to-right pass consumes `\\` whole. A refactor that collapsed
    // `\\` before decoding `\n` would merge these two distinct values onto one
    // fingerprint, and R6 would stop alerting on the second.
    expect(fingerprint("a\\\\nb", HMAC_KEY)).not.toBe(fingerprint("a\nb", HMAC_KEY));
  });

  test("lone surrogates do not collapse distinct secrets onto one fingerprint", () => {
    // Decoded, every lone surrogate UTF-8-encodes to U+FFFD; if they collapsed,
    // the second secret would dedup as the first and never alert.
    const fps = ["\\ud800", "\\udfff", "\\ud900"].map((s) => fingerprint(`ab${s}cd`, HMAC_KEY));
    expect(new Set(fps).size).toBe(3);
    // A non-surrogate escape still decodes.
    expect(fingerprint("ab\\u0041cd", HMAC_KEY)).toBe(fingerprint("abAcd", HMAC_KEY));
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

// Regression: bodies are scanned as raw bytes, so a secret pasted at the start
// of a line is preceded by the two-char escape `\n`, whose `n` is a word char.
// A leading `\b` found no boundary there and the secret went undetected —
// no alert, no redaction, raw in the store.
describe("JSON-escape-prefixed secrets (leading-boundary regression)", () => {
  const BS = String.fromCharCode(92); // a real backslash, as it appears in raw JSON
  const FAMILIES: Array<[string, string]> = [
    ["aws-access-key-id", "AKIAZQ3DRSTUVWXY2345"],
    ["github-pat", "ghp_A7hK9mP2qR5tW8xZ1cV4bN6jL3gF0dSe2aYb"],
    ["slack-token", "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"],
    ["openai-api-key", "sk-Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0MmLl2Kk3Jj4H"],
    ["stripe-live-key", "sk_live_Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp"],
    ["google-api-key", "AIzaSyD9Zx8Yw7Vu6Tt5Ss4Rr3Qq2Pp1Oo0Nn9M"],
    ["npm-token", "npm_Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0MmLl2K"],
  ];

  for (const [detector, secret] of FAMILIES) {
    test(`${detector} is found after an escape, not just after real whitespace`, () => {
      // Control: the shapes are detected when a real separator precedes them.
      expect(scanText(`here is the key ${secret}`).some((f) => f.secretType === detector)).toBe(true);
      expect(scanText(`here is the key\n${secret}`).some((f) => f.secretType === detector)).toBe(true);
      // The regression: escapes whose final char is a word char.
      for (const esc of ["n", "t", "r", "b", "f"]) {
        const f = scanText(`here is the key${BS}${esc}${secret}`);
        expect(f.some((x) => x.secretType === detector)).toBe(true);
      }
      // \r\n, and the \uXXXX form some encoders emit for control chars.
      expect(scanText(`key${BS}r${BS}n${secret}`).some((f) => f.secretType === detector)).toBe(true);
      expect(scanText(`key${BS}u000a${secret}`).some((f) => f.secretType === detector)).toBe(true);
    });
  }

  test("a realistic JSON-encoded prompt body is scanned", () => {
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const body = JSON.stringify([
      { role: "user", content: `deploy with this:\n${secret}\nthanks` },
    ]);
    const f = scanText(body);
    expect(f.some((x) => x.secretType === "aws-access-key-id")).toBe(true);
  });

  test("the span covers the secret only, so redaction stays exact", () => {
    // The escape must not be swallowed into the finding: spans index the raw
    // bytes, and eating the `n` of `\n` would corrupt the stored JSON.
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const body = JSON.stringify([{ role: "user", content: `key:\n${secret}\ndone` }]);
    const f = scanText(body).find((x) => x.secretType === "aws-access-key-id");
    expect(f).toBeDefined();
    expect(body.slice(f!.start, f!.end)).toBe(secret);
  });

  test("a trailing escape still closes the match", () => {
    // An escape *starts* with a backslash, so the trailing boundary was never
    // broken — pin that, since only the leading anchor was widened.
    const f = scanText(`key ${"AKIAZQ3DRSTUVWXY2345"}${BS}nthanks`);
    expect(f.some((x) => x.secretType === "aws-access-key-id")).toBe(true);
  });

  test("widening does not weaken the boundary for real word characters", () => {
    // The anchor must still reject a secret glued to preceding word chars, or
    // the fix would trade a miss for a false-positive class.
    for (const prefix of ["FOO", "x", "9", "_"]) {
      const f = scanText(`${prefix}AKIAZQ3DRSTUVWXY2345`);
      expect(f.some((x) => x.secretType === "aws-access-key-id")).toBe(false);
    }
  });

  test("masking does not shorten a run into a bounded-length rule's window", () => {
    // The real FP surface of masking, which the word-char test above does NOT
    // cover: `aws-secret-shape` wants exactly 40 chars and
    // `base64-wrapped-secret` at most 256, so blanking a character could drop
    // an over-long run into range. Masking always eats from a run's HEAD (the
    // blanked span starts at a backslash, already a delimiter), so an interior
    // character can never be removed and a run can never be split in two.
    const run41 = "kR8vQ2mZ7xL4pN9wT3yB6cF1jH5sD0gA8eU2iO4tX"; // 41 chars, high entropy
    expect(run41.length).toBe(41);
    // Interior escape: the run is already delimited by the backslash itself,
    // so neither view invents a 40-char window here.
    expect(scanText(`note ${run41.slice(0, 20)}${BS}n${run41.slice(20)} end`)
      .some((f) => f.secretType === "aws-secret-shape")).toBe(false);
    // And a genuinely 41-char run stays out of the window from either view.
    expect(scanText(`note ${run41} end`).some((f) => f.secretType === "aws-secret-shape")).toBe(false);
  });

  test("a backslash that is NOT a JSON escape is left alone", () => {
    // Regression: masking `\A` as though it were an escape would blank the
    // key's own first character and turn a detection into a miss. Only the
    // escapes JSON defines may be masked.
    const K = "AKIAZQ3DRSTUVWXY2345";
    for (const text of [`C:${BS}creds${BS}${K}`, `cred=${BS}${K}`, `match ${BS}${K}`]) {
      expect(maskJsonEscapes(text)).toBe(text); // untouched
      expect(scanText(text).some((f) => f.secretType === "aws-access-key-id")).toBe(true);
    }
  });

  test("a literal backslash cannot hide a secret whose head is an escape letter", () => {
    // Masking alone could not tell `\r` in `C:\creds\redis://…` from a real
    // escape, and blanked the `r` — so the HIGH-severity connection-string rule
    // missed it. Scanning the raw view too is what closes this; `npm_` (n) and
    // `redis` (r) are the structured rules whose secret starts with an escape
    // letter, and connection-string's password group accepts backslashes so it
    // can also lose a character MID-value.
    const NPM = "npm_Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0MmLl2K";
    const has = (t: string, d: string) => scanText(t).some((f) => f.secretType === d);
    expect(has(`C:${BS}creds${BS}${NPM}`, "npm-token")).toBe(true);
    expect(has(`C:${BS}${BS}creds${BS}${BS}${NPM}`, "npm-token")).toBe(true); // JSON form
    expect(has(`${BS}redis://user:hunter2secret@h/0`, "connection-string")).toBe(true);
    expect(has(`C:${BS}creds${BS}redis://user:hunter2secret@db:6379/0`, "connection-string")).toBe(true);
    expect(has(`mongodb://u:ab${BS}ncd@host/db`, "connection-string")).toBe(true); // mid-value
    expect(has(`C:${BS}creds${BS}AKIAZQ3DRSTUVWXY2345`, "aws-access-key-id")).toBe(true);
  });

  test("the union does not double-report a secret both views agree on", () => {
    // Every finding is reported once, or the store and the alert engine would
    // see phantom duplicates on any body carrying an escape.
    const body = JSON.stringify({ role: "user", content: `key:\nAKIAZQ3DRSTUVWXY2345\n` });
    expect(scanText(body).filter((f) => f.secretType === "aws-access-key-id").length).toBe(1);
  });

  test("escape-prefixed decoys stay silent at every tier", () => {
    // The FP side of the trade. Masking adds boundaries, which widens what the
    // quiet entropy rules can see — every clean/out-of-scope corpus case must
    // still produce nothing once it follows an escape.
    const corpus: { cases: Array<{ text: string; outcome: string }> } = JSON.parse(
      readFileSync("tests/fixtures/leakproof-corpus.json", "utf8"),
    );
    const decoys = corpus.cases.filter((c) => c.outcome !== "caught");
    expect(decoys.length).toBeGreaterThan(0); // guard against a vacuous pass
    for (const c of decoys) {
      expect(scanText(JSON.stringify({ role: "user", content: `see below:\n${c.text}` }))).toEqual([]);
    }
  });

  test("masking only ever blanks whole escapes to spaces, in place", () => {
    // The whole design rests on this: spans index the raw bytes that
    // redact-on-capture and the store slice. Length alone is too weak an
    // assertion (an identity function passes it), so also require that every
    // position either kept its character or became a space.
    for (const s of [
      String.raw`a\nb`, String.raw`Ax`, String.raw`\t\r\n`, String.raw`a\\nb`,
      String.raw`q\"quoted\"`, "no escapes at all", String.raw`\\`,
      String.raw`Ax`, String.raw`\uZZZZ`, String.raw`\u12`,
      "dangling" + BS, // a lone trailing backslash must not throw or resize
    ]) {
      const m = maskJsonEscapes(s);
      expect(m.length).toBe(s.length);
      for (let i = 0; i < s.length; i++) {
        expect(m[i] === s[i] || m[i] === " ").toBe(true);
      }
    }
  });

  test("offsets stay exact across multi-byte and astral characters", () => {
    // Offsets are UTF-16 indices; a surrogate pair or a 3-byte character before
    // the secret must not shift the span redaction slices out.
    const K = "AKIAZQ3DRSTUVWXY2345";
    for (const lead of ["日本語のテキスト", "emoji 🙈🙉 here", "mixed 日本 🙈 text"]) {
      const body = JSON.stringify({ role: "user", content: `${lead}:\n${K}\ndone` });
      const f = scanText(body).find((x) => x.secretType === "aws-access-key-id");
      expect(f).toBeDefined();
      expect(body.slice(f!.start, f!.end)).toBe(K);
    }
  });

  test("masking blanks only word-tailed escapes, and tokenizes left to right", () => {
    expect(maskJsonEscapes(String.raw`key\nAKIA`)).toBe("key  AKIA");
    expect(maskJsonEscapes(`key${BS}u000aAKIA`)).toBe("key" + " ".repeat(6) + "AKIA");
    // `\"` and `\\` already end in a non-word char — left intact so the stored
    // JSON keeps its shape.
    expect(maskJsonEscapes(String.raw`key\"AKIA`)).toBe(String.raw`key\"AKIA`);
    // In `\\n` the `n` is literal text, not an escape: consuming `\\` first
    // keeps it suppressing the boundary.
    expect(maskJsonEscapes(String.raw`key\\nAKIA`)).toBe(String.raw`key\\nAKIA`);
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
