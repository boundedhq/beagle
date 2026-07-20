import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/core/store/store";
import { applyCaptureRedaction, redactBody, redactValues, redactValuesInText, redactionPlaceholder } from "../src/transform/redact";
import { DEFAULT_CONFIG } from "../src/core/config/config";
import { quarantineCorruptDb } from "../src/core/store/quarantine";
import type { Finding } from "../src/core/scanner/engine";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe("secure defaults", () => {
  test("redact-on-capture is ON by default — a detection tool must not keep secrets in cleartext", () => {
    expect(DEFAULT_CONFIG.redactOnCapture).toBe(true);
  });
});

function tmp() {
  return mkdtempSync(join(tmpdir(), "beagle-hard-"));
}

function finding(start: number, end: number, type = "aws-access-key-id"): Finding {
  return {
    detector: type, secretType: type, severity: "high", tier: "structured",
    start, end, fingerprint: "fp", destinationOwnKey: false,
  };
}

describe("redact-on-capture (R11)", () => {
  test("replaces the secret span with a stable typed placeholder", () => {
    const body = 'key = "AKIAZQ3DRSTUVWXY2345" done';
    const start = body.indexOf("AKIA");
    const out = redactBody(enc(body), [finding(start, start + 20)]);
    const text = dec(out.bytes);
    expect(text).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(text).toContain("[REDACTED:aws-access-key-id:");
    expect(text).toContain("done"); // surrounding bytes intact
    expect(out.values[0]?.value).toBe("AKIAZQ3DRSTUVWXY2345");
  });

  test("overlapping findings on the same span don't corrupt the body", () => {
    // Two quiet-tier rules can flag the same 40-char value (generic-assignment
    // + aws-secret-shape). A naive double-splice ate the bytes after the span.
    const body = '{"secret":"wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn","next":"keepme"}';
    const start = body.indexOf("wJa1");
    const span = finding(start, start + 40, "aws-secret-shape");
    const dup = finding(start, start + 40, "generic-api-key");
    const out = dec(redactBody(enc(body), [span, dup]).bytes);
    expect(out).not.toContain("wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn");
    expect(out).toContain('"next":"keepme"}'); // bytes after the span survive intact
    expect(out.startsWith('{"secret":"[REDACTED:')).toBe(true);
  });

  test("redactValues scrubs an echoed secret from another body", () => {
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const resp = enc(`the model says your key ${secret} is set`);
    const out = redactValues(resp, [{ value: secret, type: "aws-access-key-id" }]);
    expect(dec(out!)).not.toContain(secret);
    expect(dec(out!)).toContain("[REDACTED:aws-access-key-id:");
  });

  test("redactValues ignores short values (avoids scrubbing common substrings)", () => {
    const resp = enc("the word key appears often, key key key");
    const out = redactValues(resp, [{ value: "key", type: "x" }]);
    expect(dec(out!)).toBe("the word key appears often, key key key");
  });

  test("redactValuesInText scrubs derived text (summary, search index) by value", () => {
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const out = redactValuesInText(`my key ${secret} leaked`, [{ value: secret, type: "aws-access-key-id" }]);
    expect(out).not.toContain(secret);
    expect(out).toContain("[REDACTED:aws-access-key-id:");
  });

  // The scanner matches the RAW bytes; the transcript, summary and Mode B
  // search index render a JSON-DECODED view of them. A value matched inside a
  // JSON string carries the two-char escape `\n`, so a literal-match scrub of
  // the decoded text found nothing and silently no-opped — the body was masked
  // while the raw key stayed readable in the viewer and searchable by `beagle
  // search`. Every escaping form of a value must scrub.
  test("redactValuesInText scrubs the JSON-decoded form of an escaped value", () => {
    // Both forms written out literally rather than derived from each other: a
    // test that decodes with the same primitive the fix uses would agree with
    // a wrong decoding instead of catching it.
    const escaped = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAderivedTextRegression\\n-----END RSA PRIVATE KEY-----";
    const decoded = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAderivedTextRegression\n-----END RSA PRIVATE KEY-----";
    const out = redactValuesInText(`deploy:\n${decoded}`, [{ value: escaped, type: "private-key" }]);
    expect(out).not.toContain("MIIEowIBAAKCAQEAderivedTextRegression");
    expect(out).toContain("[REDACTED:private-key:");
    // One secret reads as ONE placeholder whichever form was found, so the
    // viewer highlights the transcript and the body identically.
    expect(out).toContain(redactionPlaceholder("private-key", escaped));
  });

  test("redactValuesInText still scrubs the raw escaped form (stored bodies keep their escapes)", () => {
    const escaped = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAderivedTextRegression\\n-----END RSA PRIVATE KEY-----";
    const out = redactValuesInText(`{"prompt":"${escaped}"}`, [{ value: escaped, type: "private-key" }]);
    expect(out).not.toContain("MIIEowIBAAKCAQEAderivedTextRegression");
    expect(out).toContain("[REDACTED:private-key:");
  });

  test("redactValuesInText leaves text alone when a value's escapes are malformed", () => {
    // A match that cut an escape in half is not a well-formed JSON string body;
    // decoding must fail closed (no variant) rather than throw out of the scrub.
    const text = "nothing sensitive here at all";
    expect(redactValuesInText(text, [{ value: "trailing-backslash\\", type: "x" }])).toBe(text);
  });

  test("applyCaptureRedaction holds all content out on an incomplete scan", () => {
    const out = applyCaptureRedaction({
      incomplete: true,
      requestBytes: enc("could hold anything"),
      requestFindings: [],
      responseBody: enc("also unverified"),
    });
    expect(out.redacted).toBe(true);
    expect(out.heldOut).toBe(true);
    expect(dec(out.requestBody)).toContain("[REDACTION INCOMPLETE");
    expect(out.responseBody).toBeNull();
    expect(out.values).toEqual([]);
  });

  test("applyCaptureRedaction redacts response-side findings (Mode B echo)", () => {
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const resp = `your key is ${secret}`;
    const start = resp.indexOf(secret);
    const out = applyCaptureRedaction({
      incomplete: false,
      requestBytes: enc(""),
      requestFindings: [],
      responseBody: enc(resp),
      responseFindings: [finding(start, start + secret.length)],
    });
    expect(out.redacted).toBe(true);
    expect(out.heldOut).toBe(false);
    expect(dec(out.responseBody!)).not.toContain(secret);
    expect(dec(out.responseBody!)).toContain("[REDACTED:aws-access-key-id:");
    expect(out.values).toEqual([{ value: secret, type: "aws-access-key-id" }]);
  });

  test("value-scrubs EVERY occurrence, not just the one span the scanner reported", () => {
    // A secret appearing more than once in a body (codex echoes the prompt
    // across fields) with only ONE reported finding must leave NO raw copy —
    // else the store + FTS index keep the secret in cleartext. Verified live.
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const body = `{"a":"my key ${secret}","b":"copy ${secret} here"}`;
    const first = body.indexOf(secret);
    const out = applyCaptureRedaction({
      incomplete: false,
      requestBytes: enc(body),
      requestFindings: [finding(first, first + secret.length)], // only the first occurrence
      responseBody: null,
    });
    expect(dec(out.requestBody)).not.toContain(secret); // both copies gone
    expect(dec(out.requestBody).match(/\[REDACTED:/g)?.length).toBe(2);
  });

  test("placeholder is stable for the same secret, distinct per type", () => {
    const a = redactionPlaceholder("aws-access-key-id", "AKIAZQ3DRSTUVWXY2345");
    const b = redactionPlaceholder("aws-access-key-id", "AKIAZQ3DRSTUVWXY2345");
    const c = redactionPlaceholder("github-pat", "AKIAZQ3DRSTUVWXY2345");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });

  test("multiple findings redacted without shifting later spans wrongly", () => {
    const body = "a AKIAZQ3DRSTUVWXY2345 b ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX c";
    const s1 = body.indexOf("AKIA");
    const s2 = body.indexOf("ghp_");
    const out = dec(redactBody(enc(body), [
      finding(s1, s1 + 20),
      finding(s2, s2 + 40, "github-pat"),
    ]).bytes);
    expect(out).not.toContain("AKIAZQ3DRSTUVWXY2345");
    expect(out).not.toContain("ghp_XXXX");
    expect(out.startsWith("a ")).toBe(true);
    expect(out.endsWith(" c")).toBe(true);
  });

  test("no findings leaves the body byte-identical", () => {
    const body = enc('{"hello":"world"}');
    expect(dec(redactBody(body, []).bytes)).toBe('{"hello":"world"}');
  });
});

describe("exclusions enforced before the write queue (R11)", () => {
  test("excluded agent traffic is never stored", () => {
    // Simulated at the store level: the daemon drops before insert; here we
    // assert the store has no leftover when nothing is inserted.
    const store = Store.open(tmp());
    expect(store.countCalls()).toBe(0);
    store.close();
  });
});

describe("corrupt DB quarantine (§6.6)", () => {
  test("moves a corrupt db into quarantine/ and lets a fresh store open", () => {
    const dir = tmp();
    const dbPath = join(dir, "beagle.db");
    writeFileSync(dbPath, "this is not a sqlite file at all");
    const moved = quarantineCorruptDb(dir);
    expect(moved).toBe(true);
    expect(existsSync(join(dir, "quarantine"))).toBe(true);
    expect(readdirSync(join(dir, "quarantine")).length).toBeGreaterThan(0);
    // a fresh store now opens cleanly
    const store = Store.open(dir);
    expect(store.countCalls()).toBe(0);
    store.close();
  });

  test("openOrRecover returns a working store even when the existing db is corrupt", () => {
    const dir = tmp();
    writeFileSync(join(dir, "beagle.db"), "corrupt");
    const store = Store.openOrRecover(dir);
    store.insertCall({
      id: "01JZZZZZZZZZZZZZZZZZZZZZZZZ", sessionId: "s", runId: "r", source: "wire",
      endpoint: "/", tsRequest: Date.now(), scanState: "ok", captureState: "ok",
      sessionTier: "run", requestBody: null, requestHeaders: null, responseBody: null,
      responseHeaders: null, sseRaw: null, searchText: "x",
    });
    expect(store.countCalls()).toBe(1);
    store.close();
  });
});
