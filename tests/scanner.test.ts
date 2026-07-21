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

describe("capture-group spans", () => {
  // The span must cover the group the rule actually captured, at the offsets it
  // really matched. Searching the match for the group's TEXT instead silently
  // picks the first identical occurrence — and a connection string whose
  // password equals its username is an ordinary dev-config shape, so the span
  // landed on the username and redaction spliced that, leaving the password in
  // the stored body. Short passwords escaped the echo-scrub's 8-char floor too,
  // so they survived end to end.
  test("a password identical to the username spans the PASSWORD", () => {
    for (const [body, user, pass] of [
      ["MONGO_URL=mongodb://root:root@db.internal:27017/app", "root", "root"],
      ["REDIS_URL=redis://admin:admin@cache:6379/0", "admin", "admin"],
    ] as const) {
      const hit = scanText(body).find((f) => f.secretType === "connection-string")!;
      expect(hit).toBeDefined();
      expect(body.slice(hit.start, hit.end)).toBe(pass);
      // The span sits after the colon that separates user from password.
      expect(body.lastIndexOf(`${user}:`, hit.start)).toBeLessThan(hit.start);
      expect(body[hit.start - 1]).toBe(":");
      expect(body[hit.end]).toBe("@");
    }
  });

  test("distinct username and password still span the password", () => {
    const body = "postgres://appuser:s3cretpw@db:5432/app";
    const hit = scanText(body).find((f) => f.secretType === "connection-string")!;
    expect(body.slice(hit.start, hit.end)).toBe("s3cretpw");
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
    //
    // The escape and the secret must be in DIFFERENT places. If the escape
    // immediately precedes the key, the raw view doesn't match it at all (that
    // is the bug this suite is about), only one view contributes, and the dedup
    // is never exercised — the test would pass with the dedup deleted. Here the
    // escape forces the second pass while both views match the key, so removing
    // the dedup really does report 2.
    const body = String.raw`{"content":"first line\nhere is the key AKIAZQ3DRSTUVWXY2345 done"}`;
    expect(maskJsonEscapes(body)).not.toBe(body); // the second pass actually runs
    expect(scanText(body).filter((f) => f.secretType === "aws-access-key-id").length).toBe(1);
  });

  test("escape-prefixed decoys stay silent at every tier", () => {
    // The FP side of the trade. Masking adds boundaries, which widens what the
    // quiet entropy rules can see — every clean/out-of-scope corpus case must
    // still produce nothing once it follows an escape.
    //
    // Run at BOTH nesting depths. Depth 2 is not redundant: blanking `\"` is
    // what newly exposes these rules to the interior of a tool-call argument
    // string, and there the quotes around every decoy become separators too.
    const corpus: { cases: Array<{ text: string; outcome: string }> } = JSON.parse(
      readFileSync("tests/fixtures/leakproof-corpus.json", "utf8"),
    );
    const decoys = corpus.cases.filter((c) => c.outcome !== "caught");
    expect(decoys.length).toBeGreaterThan(0); // guard against a vacuous pass
    for (const c of decoys) {
      const depth1 = JSON.stringify({ role: "user", content: `see below:\n${c.text}` });
      expect(scanText(depth1)).toEqual([]);
      expect(scanText(`{"arguments":${JSON.stringify(depth1)}}`)).toEqual([]);
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

  // The prebuilt blank table covers runs up to 32; past that the mask falls back
  // to building one. That boundary fails SILENTLY if the fallback is ever
  // dropped — the mask would return a short string and every span offset after
  // it would shift — so pin both sides of it explicitly.
  test("length is preserved for backslash runs past the prebuilt table", () => {
    for (const n of [1, 2, 16, 31, 32, 33, 64, 200]) {
      const s = `x${"\\".repeat(n)}ny`;
      expect(maskJsonEscapes(s).length).toBe(s.length);
    }
    // A run of 40 followed by an escape char blanks to exactly 41 spaces.
    expect(maskJsonEscapes(`x${"\\".repeat(40)}ny`)).toBe(`x${" ".repeat(41)}y`);
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

  test("masking consumes a whole backslash run, at any escape depth", () => {
    expect(maskJsonEscapes(String.raw`key\nAKIA`)).toBe("key  AKIA");
    expect(maskJsonEscapes(`key${BS}u000aAKIA`)).toBe("key" + " ".repeat(6) + "AKIA");
    // Depth 2+: the run is consumed ATOMICALLY, so `\\n` — a newline inside a
    // tool-call argument string — blanks to three spaces. Reading `\\` as one
    // escaped backslash and the `n` after it as literal text is the
    // single-encoding reading; it is what missed secrets nested in tool calls,
    // and it is why this assertion is the reverse of what it once was.
    expect(maskJsonEscapes(String.raw`key\\nAKIA`)).toBe("key   AKIA");
    expect(maskJsonEscapes(String.raw`key\\\\nAKIA`)).toBe("key     AKIA");
    // `\"` is blanked too: at depth 2 a field reads `\"key\":\"…` and no rule's
    // separator class contains a backslash, so keyword-adjacency rules missed.
    expect(maskJsonEscapes(String.raw`key\"AKIA`)).toBe("key  AKIA");
    // A run with no escape char after it is literal text at every depth.
    expect(maskJsonEscapes(String.raw`C:\creds`)).toBe(String.raw`C:\creds`);
    expect(maskJsonEscapes(String.raw`a\\c`)).toBe(String.raw`a\\c`);
  });
});

// Depth 2+ shapes: a secret nested inside a tool-call arguments STRING. Each
// case states the WIRE bytes, because that — not the decoded value — is what
// the rules see; `String.raw` keeps that honest.
describe("secrets nested in tool-call arguments (R5)", () => {
  const AWS_KEY = "AKIAZQ3DRSTUVWXY2345";
  const FILE = `# prod creds\n${AWS_KEY}\n`; // real newlines: what the agent writes

  // Each extra layer serializes the body so far into a STRING field, exactly as
  // a tool call carries its arguments. Derived with JSON.stringify rather than
  // hand-written escapes — counting backslashes by hand got the depth wrong
  // here once already, and the whole point is which depth is under test.
  const nest = (payload: string, depth: number) => {
    let body = `{"content":${JSON.stringify(payload)}}`; // depth 1
    for (let i = 1; i < depth; i++) body = `{"arguments":${JSON.stringify(body)}}`;
    return body;
  };

  // Pin the wire shape the rest of the block relies on: the backslash run before
  // the secret doubles with each layer. If this drifts, every test below is
  // testing something other than what it says.
  test("nesting depth shows up as the backslash run before the secret", () => {
    for (const [depth, run] of [[1, 1], [2, 2], [3, 4]] as const) {
      const body = nest(FILE, depth);
      const before = body.slice(0, body.indexOf(AWS_KEY));
      expect(before.endsWith("\\".repeat(run) + "n")).toBe(true);
      expect(before.endsWith("\\".repeat(run + 1) + "n")).toBe(false); // exactly that many
    }
  });

  // Depth 2 is the shape this block exists for: OpenAI-style tool calls put
  // their arguments in a JSON *string* inside the request JSON, so a newline in
  // a file the agent writes arrives as THREE chars, `\` `\` `n`. Anthropic's
  // streaming input_json_delta nests identically. The scanner is envelope-blind,
  // so both run the same assertions — they are here to document that these two
  // real vendor shapes reduce to one case, not because they exercise two paths.
  const ENVELOPES: Array<[string, string]> = [
    ["openai tool_calls[].function.arguments",
      `{"model":"gpt-4o","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"write_file","arguments":${JSON.stringify(nest(FILE, 1))}}}]}]}`],
    ["anthropic input_json_delta.partial_json",
      `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":${JSON.stringify(nest(FILE, 1))}}}`],
  ];
  for (const [name, body] of ENVELOPES) {
    test(`double-encoded: ${name}`, () => {
      expect(body).toContain(String.raw`creds\\n` + AWS_KEY); // three chars, not one newline
      const f = scanText(body);
      expect(f.map((x) => x.secretType)).toContain("aws-access-key-id");
      // The span must index the RAW bytes, or redact-on-capture splices the
      // wrong range and the stored body keeps the secret.
      const hit = f.find((x) => x.secretType === "aws-access-key-id")!;
      expect(body.slice(hit.start, hit.end)).toBe(AWS_KEY);
    });
  }

  // Anthropic's tool_use carries `input` as a nested JSON OBJECT, not a string,
  // so it is only single-encoded and was already caught before this change.
  // Kept as documentation of the vendor difference — it is why the two providers
  // needed different fixtures — NOT as a regression test for this fix.
  test("anthropic tool_use.input is a nested object, so only single-encoded", () => {
    const body = String.raw`{"content":[{"type":"tool_use","id":"toolu_1","name":"write_file","input":{"path":".env","content":"# prod creds\n${AWS_KEY}\n"}}]}`;
    expect(body).toContain(String.raw`creds\n` + AWS_KEY); // one backslash, not two
    expect(scanText(body).map((f) => f.secretType)).toContain("aws-access-key-id");
  });

  // Nesting is not capped at two: a sub-agent relaying a tool call adds a layer.
  test("triple-encoded", () => {
    const body = nest(FILE, 3);
    expect(body).toContain("\\".repeat(4) + "n" + AWS_KEY);
    expect(scanText(body).map((f) => f.secretType)).toContain("aws-access-key-id");
  });

  // Keyword-adjacency rules match a keyword, a short run of separator chars,
  // then the value. Double encoding turns `":"` into `\":\"`, and backslash is
  // in no rule's separator class, so these rules missed too.
  test("double-encoded: keyword-adjacency rules match across escaped quotes", () => {
    const secret = "Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm";
    const body = `{"tool_calls":[{"function":{"name":"configure","arguments":${JSON.stringify(`{"api_key":"${secret}"}`)}}}]}`;
    const f = scanText(body);
    expect(f.map((x) => x.secretType)).toContain("generic-api-key");
    const hit = f.find((x) => x.secretType === "generic-api-key")!;
    // Capture must stop at the escaped quote, not swallow it — the stored JSON
    // is corrupted if a redaction splices out the delimiter too.
    expect(body.slice(hit.start, hit.end)).toBe(secret);
  });

  // The limit of the above, pinned so it is a known boundary rather than a
  // surprise. Masking is depth-agnostic, but these rules allow at most 5
  // separator chars, and every layer DOUBLES the backslashes in `":"`: 3 chars
  // at depth 1, 5 at depth 2, 9 at depth 3 (2^d + 1). So they reach depth 2 and
  // stop. `\b`-anchored rules need only one separator and keep working at any
  // depth — see the triple-encoded test above. Widening the quantifier would be
  // a rules-data change, not an engine one.
  test("keyword-adjacency rules reach depth 2, and no further", () => {
    const secret = "Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm";
    const at = (depth: number) => {
      let body = `{"api_key":"${secret}"}`; // depth 1
      for (let i = 1; i < depth; i++) body = `{"arguments":${JSON.stringify(body)}}`;
      return body;
    };
    // The separator really is the thing that grows.
    expect([1, 2, 3].map((d) => {
      const b = at(d);
      return b.slice(b.indexOf("api_key") + 7, b.indexOf(secret)).length;
    })).toEqual([3, 5, 9]);
    expect([1, 2, 3].map((d) =>
      scanText(at(d)).some((f) => f.secretType === "generic-api-key"),
    )).toEqual([true, true, false]);
  });

  // The same ceiling, reached one layer earlier by whitespace. A PRETTY-PRINTED
  // config file spends one separator char on the space after the colon, so at
  // depth 2 it needs 6 and gets none — while the compact form of the very same
  // file is caught. Worth pinning precisely because it is not obvious: "agent
  // writes a config file" is this PR's own motivating story, and it works or
  // not depending on how the agent formatted the JSON. Fixing it means widening
  // the rule's quantifier in beagle-rules.json (which re-pins its sha256 and
  // widens the quiet tier's FP surface), so it is a data decision, not this one.
  test("a pretty-printed config file loses keyword-adjacency one depth sooner", () => {
    const secret = "Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm";
    const pretty = `{\n  "api_key": "${secret}"\n}`;
    const found = (b: string) => scanText(b).some((f) => f.secretType === "generic-api-key");
    expect(found(pretty)).toBe(true); // depth 1: 4 separator chars, still inside
    expect(found(`{"arguments":${JSON.stringify(pretty)}}`)).toBe(false); // depth 2: 6, over
    // ...while the compact spelling of the same file survives that depth.
    expect(found(`{"arguments":${JSON.stringify(`{"api_key":"${secret}"}`)}}`)).toBe(true);
  });

  // The dedup guarantee R6 leans on: one secret is one fingerprint however deeply
  // the client encoded it, or every tool call re-alerts on a key already seen.
  test("a fixed-alphabet secret fingerprints identically at every depth", () => {
    const fp = (body: string) =>
      scanText(body).find((f) => f.secretType === "aws-access-key-id")!.fingerprint;
    const plain = fp(`key ${AWS_KEY} done`);
    for (const depth of [1, 2, 3]) expect(fp(nest(FILE, depth))).toBe(plain);
  });

  // ...and the documented cost of that, so it stays documented. A capture that
  // can itself contain a backslash (private-key, connection-string) still splits:
  // fingerprint() decodes ONE level, deliberately, because decoding to a fixpoint
  // risks merging secrets that really did differ. A re-alert, never a miss.
  test("a capture that can hold a backslash still splits across depth", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----";
    const fp = (body: string) =>
      scanText(body).find((f) => f.secretType === "private-key")?.fingerprint;
    expect(fp(pem)).toBe(fp(nest(pem, 1))); // depth 1 matches plaintext
    expect(fp(nest(pem, 2))).toBeDefined(); // still detected...
    expect(fp(nest(pem, 2))).not.toBe(fp(pem)); // ...but under a second fingerprint
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
