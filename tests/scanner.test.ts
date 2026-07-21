import { describe, expect, test } from "bun:test";
import { compileRules, scan, shannonEntropy, luhnValid, maskJsonEscapes } from "../src/core/scanner/engine";
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

// Bodies are scanned as raw wire bytes, so every secret arrives wrapped in
// however many layers of JSON string escaping the client applied. Each case
// below states the WIRE bytes, because that — not the decoded value — is what
// the rules actually see. `String.raw` keeps this honest: what you read is
// byte-for-byte what is scanned.
const AWS_KEY = "AKIAZQ3DRSTUVWXY2345";

describe("JSON-escaped bodies (R5)", () => {
  // Depth 1: an ordinary JSON body. A secret pasted at the start of a line is
  // preceded on the wire by the two chars `\` `n` — whose `n` is a word char,
  // so a `\b`-anchored rule finds no boundary.
  test("single-encoded: secret first on a line", () => {
    const body = String.raw`{"messages":[{"content":"# prod creds\n${AWS_KEY}\n"}]}`;
    expect(body).toContain(String.raw`creds\n` + AWS_KEY);
    expect(scanText(body).map((f) => f.secretType)).toContain("aws-access-key-id");
  });

  // Depth 2 — the shape this suite exists for. OpenAI puts tool-call arguments
  // in a JSON *string* nested inside the request JSON, so a newline in a file
  // the agent writes arrives as THREE chars: `\` `\` `n`. "Agent writes a .env
  // file" is the mainstream form of exactly the leak beagle is for.
  test("double-encoded: openai tool_calls[].function.arguments", () => {
    const args = String.raw`{\"path\":\".env\",\"content\":\"# prod creds\\n${AWS_KEY}\\n\"}`;
    const body = String.raw`{"model":"gpt-4o","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"write_file","arguments":"${args}"}}]}]}`;
    expect(body).toContain(String.raw`creds\\n` + AWS_KEY); // three chars, not one newline
    const f = scanText(body);
    expect(f.map((x) => x.secretType)).toContain("aws-access-key-id");
    // The span must index the RAW bytes, or redact-on-capture splices the
    // wrong range and the stored body keeps the secret.
    const hit = f.find((x) => x.secretType === "aws-access-key-id")!;
    expect(body.slice(hit.start, hit.end)).toBe(AWS_KEY);
  });

  // Anthropic's tool_use carries `input` as a nested JSON OBJECT, not a
  // string, so this shape is only single-encoded. Pinned so that stays true:
  // if a client ever pre-serializes `input`, this test keeps passing via the
  // depth-2 path rather than silently regressing to a miss.
  test("anthropic tool_use.input (nested object, single-encoded)", () => {
    const body = String.raw`{"content":[{"type":"tool_use","id":"toolu_1","name":"write_file","input":{"path":".env","content":"# prod creds\n${AWS_KEY}\n"}}]}`;
    expect(scanText(body).map((f) => f.secretType)).toContain("aws-access-key-id");
  });

  // Anthropic's streaming form DOES double-encode: input_json_delta carries
  // partial JSON as a string, same nesting as OpenAI's `arguments`.
  test("double-encoded: anthropic input_json_delta.partial_json", () => {
    const partial = String.raw`{\"path\":\".env\",\"content\":\"# prod creds\\n${AWS_KEY}\\n\"}`;
    const body = String.raw`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"${partial}"}}`;
    expect(scanText(body).map((f) => f.secretType)).toContain("aws-access-key-id");
  });

  // Nesting is not capped at two: a sub-agent relaying a tool call adds another
  // layer, taking the escape run to four backslashes.
  test("triple-encoded", () => {
    const body = String.raw`{"arguments":"{\"inner\":\"{\\\"content\\\":\\\"x\\\\\\\\n${AWS_KEY}\\\\\\\\n\\\"}\"}"}`;
    expect(scanText(body).map((f) => f.secretType)).toContain("aws-access-key-id");
  });

  // Keyword-adjacency rules match a keyword, then a short run of separator
  // chars, then the value. Double encoding turns `":"` into `\":\"` and the
  // backslashes are not separator chars, so these rules missed too.
  test("double-encoded: keyword-adjacency rules match across escaped quotes", () => {
    const args = String.raw`{\"api_key\":\"Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm\"}`;
    const body = String.raw`{"tool_calls":[{"function":{"name":"configure","arguments":"${args}"}}]}`;
    const f = scanText(body);
    expect(f.map((x) => x.secretType)).toContain("generic-api-key");
    const hit = f.find((x) => x.secretType === "generic-api-key")!;
    // Capture must stop at the escaped quote, not swallow it — the stored JSON
    // is corrupted if a redaction splices out the delimiter too.
    expect(body.slice(hit.start, hit.end)).toBe("Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm");
  });

  // Soundness in the other direction. Nothing on the wire distinguishes a JSON
  // escape from a literal backslash in a non-JSON body, so treating every
  // escape-looking run as an escape MUST NOT be the only reading: these are
  // bodies where the backslash is literal text and the letter after it is part
  // of the secret. They are caught by scanning the unmasked bytes too.
  test("literal backslash: windows path glued to a token", () => {
    const body = String.raw`{"path":"C:\\npm_A7hK9mP2qR5tW8xZ1cV4bN6jL3gF0dSe2aYb"}`;
    // The masked view reads `\\n` as a depth-2 escape and blanks the token's
    // own first letter; only the unmasked view can catch this one.
    expect(maskJsonEscapes(body)).toContain("   pm_");
    expect(scanText(body).map((f) => f.secretType)).toContain("npm-token");
  });

  test("literal backslash: windows path before a connection string", () => {
    const body = String.raw`C:\creds\redis://admin:hunter2secret@db.internal:6379/0`;
    expect(scanText(body).map((f) => f.secretType)).toContain("connection-string");
  });

  // A backslash before a non-escape char is literal text in every reading, so
  // it must never be blanked — blanking would eat the secret's first char.
  test("literal backslash before a non-escape char is left intact", () => {
    // Built by concatenation, not interpolation: in String.raw a `\` before
    // `${` escapes the placeholder instead of interpolating it.
    const body = String.raw`{"path":"C:\creds` + "\\" + AWS_KEY + `"}`;
    expect(body).toContain("creds\\" + AWS_KEY);
    expect(maskJsonEscapes(body)).toBe(body); // neither backslash starts an escape
    expect(scanText(body).map((f) => f.secretType)).toContain("aws-access-key-id");
  });

  test("masking is length-preserving at every depth", () => {
    for (const s of [
      String.raw`a\nb`,
      String.raw`a\\nb`,
      String.raw`a\\\\nb`,
      String.raw`aAb`,
      String.raw`a\\u0041b`,
      String.raw`a\"b`,
      String.raw`C:\creds`,
      "no backslashes here",
    ]) {
      expect(maskJsonEscapes(s).length).toBe(s.length);
    }
  });

  // Masking may only ever turn a character into a space. If it could turn a
  // space into a word char it could fabricate a boundary inside a secret and
  // invent findings; this pins the direction.
  test("masking only ever blanks — it never introduces non-space characters", () => {
    const s = String.raw`{"a":"x\n\\n\\\\nA\"y\/z"}`;
    const masked = maskJsonEscapes(s);
    for (let i = 0; i < s.length; i++) {
      const m = masked[i]!;
      expect(m === s[i] || m === " ").toBe(true);
    }
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
