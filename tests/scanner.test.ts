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

// The post-keyword window is [a-zA-Z_ ] with no hyphen, so after
// secret[_-]?access matched "secret-access" the trailing "-key" could not be
// crossed and the canonical GitHub Actions spelling only ever reached the
// quiet tier — recorded, but AlertEngine.process fires on "structured" alone,
// so the user was never told. The fix is an optional literal "-key"; the
// negatives below pin WHICH formulation, because the looser shapes that also
// fix the positives cost measured precision (see the rule's description).
describe("hyphenated aws key names (tier regression)", () => {
  const KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYZZZZZKEY42";
  const loud = (t: string) =>
    scanText(t).filter((f) => f.tier === "structured").map((f) => f.secretType);

  test("the canonical GitHub Actions spelling alerts", () => {
    expect(loud(`      aws-secret-access-key: ${KEY}`)).toContain("aws-secret-access-key");
  });

  test("hyphenated and underscored spellings agree", () => {
    // The bug was that these two disagreed: same secret, same shape, and the
    // verdict turned on the separator character alone.
    const hyphen = loud(`aws-secret-access-key=${KEY}`);
    expect(hyphen).toEqual(loud(`aws_secret_access_key=${KEY}`));
    // Pinned non-empty: equality alone would also hold if a later change
    // silenced BOTH spellings, which is the regression this test exists to
    // catch. Agreeing at zero is not agreement.
    expect(hyphen).toContain("aws-secret-access-key");
  });

  test("the 'secret-access' prescan keyword is reachable without 'aws'", () => {
    // Nothing in this body contains "aws", so the match must come through the
    // "secret-access" keyword — which before the fix advertised a spelling the
    // regex structurally could not reach, making it dead weight.
    expect(loud(`secret-access-key: ${KEY}`)).toContain("aws-secret-access-key");
  });

  test("a hyphen-chained identifier before a digest stays silent", () => {
    // Rejected fix #1: widening the window to [a-zA-Z_ -]. A 40-hex digest's
    // ~4.0 entropy clears the rule's 3.0 gate, so this fired structured/high.
    expect(scanText("aws-cdk-lib-construct-x 3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5e")).toEqual([]);
  });

  test("aws vocabulary that merely ends in -key does not alert", () => {
    // Rejected fix #2: allowing bounded hyphen segments before the anchor,
    // (?:-[a-zA-Z]{1,12}){0,3}-key. These are ordinary DynamoDB/S3 field names
    // and a trailing digest is exactly what they carry.
    // Asserted on the loud tier, not on zero findings: <name>-key: <high-entropy>
    // is a generic-api-key shape and trips that rule quietly both before and
    // after this change. Quiet is the correct verdict — it never alerts.
    for (const id of ["aws-object-key", "aws-partition-key", "aws-cdk-cache-key"]) {
      expect(loud(`${id}: 3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5e`)).toEqual([]);
    }
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

describe("pasted secrets, JSON-encoded as they arrive on the wire", () => {
  // The scanner sees the request body, not the chat message, so a pasted .env
  // line reaches it JSON-encoded and the quotes around a quoted assignment
  // arrive as \". A raw body matched that same paste on the bare quote, so a
  // rule reading only the raw form alerts or stays silent depending purely on
  // transport. Tier is what carries the consequence: AlertEngine.process fires
  // the loud alert only on tier === "structured". Unmatched, the paste is not
  // silent but demoted — the anchor-free aws-secret-shape rule still logs it at
  // tier "possible", which is recorded and never shown to the user.
  const SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYZZZZZKEY42";
  const DIGEST = "3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5e"; // 40 hex: clears the 3.0 entropy gate
  const wireBody = (line: string) =>
    JSON.stringify({ messages: [{ role: "user", content: `here is my env:\n${line}\nplease use it` }] });

  // Separator shapes a paste can put between the key name and the secret. Each
  // is written raw here and JSON-encoded by wireBody, exactly as a chat client
  // would encode it. The first two are controls: JSON.stringify escapes neither
  // = nor ', so they reach the wire byte-identical to their raw form and match
  // even without the fix. They are here to prove the fix costs nothing, not to
  // exercise it — every shape below them fails if the fix is reverted.
  const SHAPES: Array<[string, string]> = [
    ["unquoted (control)", `AWS_SECRET_ACCESS_KEY=${SECRET}`],
    ["single-quoted (control)", `AWS_SECRET_ACCESS_KEY='${SECRET}'`],
    ["double-quoted", `AWS_SECRET_ACCESS_KEY="${SECRET}"`],
    ["spaced and quoted", `aws_secret_access_key = "${SECRET}"`],
    ["shell export", `export AWS_SECRET_ACCESS_KEY="${SECRET}"`],
    ["json field", `{"aws_secret_access_key": "${SECRET}"}`],
    ["pretty-printed json", `{\n  "aws_secret_access_key": "${SECRET}"\n}`],
  ];

  for (const [shape, line] of SHAPES) {
    test(`${shape} alerts at the structured tier, encoded or not`, () => {
      const body = wireBody(line);
      const hit = scanText(body).find((x) => x.secretType === "aws-secret-access-key");
      expect(hit).toBeDefined();
      expect(hit?.tier).toBe("structured");
      expect(hit?.severity).toBe("high");
      // Span covers the secret alone: redact-on-capture splices these offsets
      // out of the stored body, so a span that ate the \" would corrupt the JSON.
      expect(body.slice(hit!.start, hit!.end)).toBe(SECRET);
      // The bug this pins: the same content alerted unquoted but not quoted,
      // purely because JSON encoding moved a backslash between key and value.
      // A raw (unencoded) body must reach the same verdict.
      const rawHit = scanText(line).find((x) => x.secretType === "aws-secret-access-key");
      expect(rawHit?.tier).toBe("structured");
    });
  }

  test("every shape fingerprints identically (one secret, not seven)", () => {
    const fps = new Set(
      SHAPES.map(([, line]) =>
        scanText(wireBody(line)).find((x) => x.secretType === "aws-secret-access-key")!.fingerprint),
    );
    expect(fps.size).toBe(1);
  });

  // Only backslash-QUOTE is a separator, and only as a unit. Each case below
  // is a raw body that a looser rule was measured to fire on, at high severity,
  // with no secret present — these pin the shapes that were rejected while
  // arriving at the fix, so a future widening has to re-argue them:
  //   a bare \ in the class      -> "windows path", "home dir listing"
  //   \\? before any separator   -> the backslash-then-separator cases
  // A raw body carries the single backslash the user typed; wireBody doubles
  // it, so asserting both covers each form. Escaped whitespace (\\[ntr]) needs
  // no case here: maskJsonEscapes already blanks those to spaces before any
  // rule runs, which is also why this rule only has to learn \".
  const PATHS: Array<[string, string]> = [
    ["windows path", `C:\\aws\\${DIGEST}\\cache`],
    ["home dir listing", `ls ~/.aws\\${DIGEST}`],
    ["path to a key-shaped segment", `the path is C:\\aws\\${SECRET}`],
    ["backslash then space (dir paste)", `dir C:\\aws\\ ${DIGEST}`],
    ["backslash then newline (dir paste)", `C:\\aws\\\n${DIGEST}`],
    ["backslash then equals", `C:\\aws\\=${DIGEST}`],
    ["backslash then colon", `C:\\aws\\:${DIGEST}`],
    ["backslash then tab", `C:\\aws\\\t${DIGEST}`],
  ];
  // The tail is a negative lookahead, not \b, which needs a word char: a real
  // 40-char key ending in + or / was missed outright (~3% of the keyspace).
  for (const tail of ["+", "/"]) {
    test(`a key ending in '${tail}' still alerts (\\b would not match it)`, () => {
      const key = `${SECRET.slice(0, 39)}${tail}`;
      const hit = scanText(wireBody(`AWS_SECRET_ACCESS_KEY="${key}"`))
        .find((x) => x.secretType === "aws-secret-access-key");
      expect(hit?.tier).toBe("structured");
    });
  }

  test("a padded base64 blob near an aws keyword stays silent", () => {
    // '=' is not a value character: 40 base64 chars encode exactly 30 bytes, so
    // a real key never carries padding. Admitting it would make data-URI image
    // blobs fire the moment the tail stopped requiring a word char.
    const f = scanText(wireBody("aws logo: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAA="));
    expect(f.some((x) => x.secretType === "aws-secret-access-key")).toBe(false);
  });

  test("a longer run is not half-matched (partial redaction would leak the tail)", () => {
    // \b let a 50-char value match on its first 40 when char 41 was + / or =.
    // redact-on-capture splices exactly the finding's span, so that stored a
    // live token with its last 10 characters intact. Whole run or nothing.
    const long = `${SECRET}ABCDEFGHIJ`;
    const hits = scanText(wireBody(`aws_secret_access_key = "${long}"`))
      .filter((x) => x.secretType === "aws-secret-access-key");
    expect(hits).toEqual([]);
  });

  for (const [shape, text] of PATHS) {
    test(`a backslash that does not escape a quote stays silent: ${shape}`, () => {
      // Raw body (single backslash) and wire body (doubled) must both stay quiet.
      expect(scanText(text).some((x) => x.secretType === "aws-secret-access-key")).toBe(false);
      expect(scanText(wireBody(text)).some((x) => x.secretType === "aws-secret-access-key")).toBe(false);
    });
  }
});

describe("fingerprint stability across wrapping and wire encoding", () => {
  const BODY = "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn";
  const pem = (body: string) =>
    `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`;
  const fpOf = (text: string) =>
    scanText(text).find((x) => x.secretType === "private-key")!.fingerprint;
  const fpConn = (text: string) =>
    scanText(text).find((x) => x.secretType === "connection-string")!.fingerprint;

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

  test("a password ending in a quote fingerprints identically JSON-encoded and raw", () => {
    // JSON-encoded, the password's closing quote ships as the two characters
    // \ + ". Stripping the bare quote before decoding ate the " out of the
    // escape and hashed the dangling `hunterpw\`, while the raw arrival hashed
    // `hunterpw` — one secret, two fingerprints, and R6 dedup re-alerted.
    const url = 'mongodb://app:hunterpw"@db.internal/prod';
    expect(fpConn(JSON.stringify({ url }))).toBe(fpConn(`URL=${url}`));
    // Both arrivals converge on the undecorated password itself.
    expect(fpConn(`URL=${url}`)).toBe(fingerprint("hunterpw", HMAC_KEY));
  });

  test("a password starting with a quote agrees across encodings too", () => {
    // The mirror image: `\"hunterpw` has no BARE leading quote, so the strip
    // used to skip it and the decoded `"hunterpw` hashed with its quote on.
    const url = 'mongodb://app:"hunterpw@db.internal/prod';
    expect(fpConn(JSON.stringify({ url }))).toBe(fpConn(`URL=${url}`));
  });

  test("a \\u0022-escaping encoder agrees as well", () => {
    // Same closing quote, third spelling. An escape-aware quote-strip taught
    // the two-character `\"` would still split this one — the reason the fix
    // is decode order, not a smarter strip.
    const url = 'mongodb://app:hunterpw"@db.internal/prod';
    const body = JSON.stringify({ url }).replace(/\\"/g, "\\u0022");
    expect(fpConn(body)).toBe(fpConn(`URL=${url}`));
  });

  test("distinct quote-bearing passwords stay distinct", () => {
    expect(fpConn(JSON.stringify({ url: 'mongodb://app:alpha9z"@db.internal/prod' }))).not.toBe(
      fpConn(JSON.stringify({ url: 'mongodb://app:alpha9x"@db.internal/prod' })),
    );
  });

  test("escape-free fingerprints are pinned — no silent rotation", () => {
    // The ux_leak_fp index keys on these values with no migration path, and
    // every rule except connection-string and private-key has an alphabet
    // excluding backslash and quote, so its stored rows must NEVER rotate.
    // This golden value has survived both fingerprint reworks; a diff here
    // means orphaning every stored row, not a harmless refactor.
    expect(fingerprint("AKIAZQ3DRSTUVWXY2345", HMAC_KEY)).toBe(
      "226a219ccad33f919765e314dd7ec13d3135b37dc8ce19ac99c68bf97e575381",
    );
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
    // Only the trailing 2^k backslashes belong to the escape. A run of 40 uses
    // 32 of them, so 8 literal backslashes survive and 33 chars blank.
    expect(maskJsonEscapes(`x${"\\".repeat(40)}ny`)).toBe(`x${"\\".repeat(8)}${" ".repeat(33)}y`);
  });

  // The split is what keeps a literal backslash from being erased. An odd run
  // longer than one is never a pure nested escape: a newline at depth d takes
  // 2^(d-1) backslashes, so 1, 2, 4, 8 are escapes and 3 is a typed backslash
  // followed by a depth-1 one. Blanking all of 3 erased the backslash that
  // stops `C:\aws\` + newline + digest reading as an aws-keyed secret.
  test("a run splits into kept literals and a blanked 2^k escape", () => {
    expect(maskJsonEscapes(String.raw`a\nb`)).toBe("a  b"); // depth 1
    expect(maskJsonEscapes(String.raw`a\\nb`)).toBe("a   b"); // depth 2
    expect(maskJsonEscapes(String.raw`a\\\\nb`)).toBe("a     b"); // depth 3
    // 3 backslashes: the escape takes 2, so one literal backslash survives.
    expect(maskJsonEscapes(String.raw`a\\\nb`)).toBe("a\\   b");
    // 5 backslashes: the escape takes 4, so again one survives.
    expect(maskJsonEscapes(String.raw`a\\\\\nb`)).toBe("a\\     b");
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

  test("a Windows path is not a row of escapes", () => {
    // Regression: every run here is a clean 1-backslash escape, so the split
    // has no literal to keep, and blanking rewrote the path to
    // `C:\aws  3f9c…d5x  lob.bin` — standing the `aws` keyword two spaces from
    // a 40-char run and firing aws-secret-access-key at HIGH on a path holding
    // no secret at all. Same alert as the 3-run case, by a different route.
    // The run is 39 hex plus a trailing letter, so it draws from 17 symbols and
    // clears the 4.0 gate. A pure hex digest could not — 40 chars over hex's 16
    // symbols tops out at 3.971 — which is the sibling FP this rule already
    // fixed by raising the gate. Masking is what remained.
    const path = String.raw`C:\aws\n3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5x\blob.bin`;
    expect(maskJsonEscapes(path)).toBe(path); // untouched
    for (const body of [path, `run "${path}" now`]) {
      expect(scanText(body)).toEqual([]);
    }
    // NOT asserted silent: JSON.stringify(path) doubles the backslashes, so the
    // `\\n` really is an encoded newline and blanking it is correct. What that
    // body decodes to is `C:\aws`, a line break, then the run — and the rule
    // fires on `aws <run>` with no backslash anywhere in it, so this is the
    // rule's call on decoded content, not something the mask manufactured.
    const encoded = JSON.stringify({ path });
    expect(scanText(encoded).map((f) => f.secretType)).toEqual(
      scanText(`aws ${"3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5x"}`).map((f) => f.secretType),
    );
  });

  test("parity decides which bare runs poison a token", () => {
    const K = "AKIAZQ3DRSTUVWXY2345";
    // Odd and bare: a lone backslash the sender typed, which no encoder emits.
    // The token is raw text, so the `\n` beside it is not an escape either.
    expect(maskJsonEscapes(String.raw`C:\aws\n${K}`)).toBe(String.raw`C:\aws\n${K}`);
    // Even and bare: exactly how JSON writes a literal backslash, at depth 1
    // and 2. The escape beside it still masks — which is what stops a path in
    // one field of a minified body from silencing the secret in the next, a
    // miss a coarser "some run opens nothing" test measurably caused.
    expect(maskJsonEscapes(String.raw`C:\\proj\n${K}`)).toBe(String.raw`C:\\proj` + "  " + K);
    expect(maskJsonEscapes(String.raw`C:\\\\proj\\n${K}`)).toBe(String.raw`C:\\\\proj` + "   " + K);
    // Poisoning stops at whitespace, which is also why the FP needs one token:
    // a keyword and a value in separate tokens were already separated.
    expect(maskJsonEscapes(String.raw`C:\aws\q key\n${K}`)).toBe(String.raw`C:\aws\q key  ${K}`);
  });

  test("masking survives the surfaces that are not JSON", () => {
    // Half the scan path is not a JSON body: derivedScanText joins decoded
    // parts with a real newline around a NUL, otlp-map builds synthetic
    // prompt+tool bodies, and a capture can stop at the buffer cap mid-string.
    // Gating on a well-formed JSON STRING lost every one of these; a token
    // needs no quotes, no terminator, and has no quote parity to desynchronize.
    const K = "AKIAZQ3DRSTUVWXY2345";
    const NUL = String.fromCharCode(0), TAB = String.fromCharCode(9);
    for (const body of [
      `paste from my notes:${BS}n${K}${BS}nuse it`, // raw prose, no quotes
      `cat cfg\n${NUL}\n{"boot":"setup${BS}n${K}`, // derived join, truncated
      `x "name${TAB}value" -> {"aws":"${BS}n${K}"}`, // raw tab inside quotes
      `the 6" gauge -> {"aws":"${BS}n${K}"}`, // one stray quote
      `{"messages":[{"content":"token:${BS}n${K} rest of the mess`, // cut short
    ]) {
      expect(scanText(body).some((f) => f.secretType === "aws-access-key-id")).toBe(true);
    }
  });

  test("a body cut mid-escape still detects the secrets before the cut", () => {
    // The proxy keeps at most captureBufferCap bytes and drops the rest, so a
    // stored body can end INSIDE an escape — `…\` with its `n` dropped, or
    // `…\u0` with the hex dropped — and that stub is bytewise the bare odd run
    // the parity tell reads as raw text. Poisoning on it un-masked the stub's
    // whole token, and a minified body is one token: the cut that already cost
    // the body's tail also silently cost every escape-nested secret BEFORE it,
    // unalerted, on a row whose scanState still read "ok".
    const K = "AKIAZQ3DRSTUVWXY2345";
    const intact = `{"content":"key:${BS}n${K}"}`;
    const found = (b: string) => scanText(b).some((f) => f.secretType === "aws-access-key-id");
    expect(found(intact)).toBe(true); // control
    // Every stub a cut can write: mid-run at the odd lengths (even runs never
    // poisoned), and mid-\uXXXX at every partial-hex length.
    for (const stub of [BS, BS + BS + BS, `${BS}u`, `${BS}ud`, `${BS}ud8`, `${BS}ud83`]) {
      const cut = intact + stub;
      expect(found(cut)).toBe(true);
      // The span still indexes the raw bytes, so redaction on a truncated
      // body splices the key and nothing else.
      const hit = scanText(cut).find((f) => f.secretType === "aws-access-key-id")!;
      expect(cut.slice(hit.start, hit.end)).toBe(K);
    }
    // A realistic minified body cut at EVERY position past the secret — chunk
    // boundaries land anywhere, so no cut point may lose it. Three did.
    const long = `{"content":"key:${BS}n${K}${BS}nrest","path":"C:${BS}${BS}proj${BS}${BS}x"}`;
    for (let cut = long.indexOf(K) + K.length; cut <= long.length; cut++) {
      expect(found(long.slice(0, cut))).toBe(true);
    }
  });

  test("the truncation exemption does not reopen the Windows-path FP", () => {
    // Only the input-terminal run is forgiven. A path carries its tell
    // mid-token — `C:\aws\n…` poisons at `\a` — so the path stays silent even
    // when the path itself is what the cap cut.
    const digest = "3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5x";
    const cutPath = `C:${BS}aws${BS}n${digest}${BS}`; // C:\aws\n<digest>\blob.bin, cut
    expect(maskJsonEscapes(cutPath)).toBe(cutPath); // still untouched
    expect(scanText(cutPath)).toEqual([]);
  });

  test("the input-edge exemption favors the truncated-JSON reading", () => {
    // `aws\n<digest>` with no other backslash carries no parity tell in either
    // direction; it masks, and the rule fires — that call predates this change.
    // A trailing lone backslash used to flip the same body to silent. Now only
    // a MID-body dangling backslash does: there the raw reading holds, while at
    // the input edge the stub reads as a cut, because a real truncated body
    // losing its secret costs more than this alert.
    const digest = "3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5x";
    const fires = (b: string) => scanText(b).some((f) => f.secretType === "aws-secret-access-key");
    expect(fires(`aws${BS}n${digest}`)).toBe(true); // pre-existing call, control
    expect(fires(`aws${BS}n${digest}${BS}`)).toBe(true); // stub at the input edge
    expect(fires(`aws${BS}n${digest}${BS} more`)).toBe(false); // mid-body keeps its poison
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
