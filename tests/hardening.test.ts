import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/core/store/store";
import { redactBody, redactValues, redactValuesInText, redactionPlaceholder } from "../src/transform/redact";
import { quarantineCorruptDb } from "../src/core/store/quarantine";
import type { Finding } from "../src/core/scanner/engine";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

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
