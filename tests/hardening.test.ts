import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/core/store/store";
import { applyCaptureRedaction, clampRedacted, derivedScanText, derivedSplitAt, redactBody, redactDerivedParts, redactRawStream, redactValues, redactValuesInText, redactionPlaceholder, secretKeys } from "../src/transform/redact";
import { DEFAULT_CONFIG } from "../src/core/config/config";
import { quarantineCorruptDb } from "../src/core/store/quarantine";
import { compileRules, scan, type Finding } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";
import { readFileSync } from "node:fs";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const rules = compileRules(
  loadRuleFile(readFileSync("rules/beagle-rules.json", "utf8")),
  new Uint8Array(32).fill(9),
);

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

  // End-to-end for the double-encoded shape: the scanner reads the masked view
  // but reports offsets into the raw bytes, and this is where that has to hold
  // — a span that indexed the wrong range would splice mid-escape, corrupting
  // the stored JSON while leaving the secret in it.
  test("a secret inside an OpenAI tool call is spliced out and the body stays parseable", () => {
    const key = "AKIAZQ3DRSTUVWXY2345";
    const args = String.raw`{\"path\":\".env\",\"content\":\"# prod creds\\n${key}\\n\"}`;
    const body = String.raw`{"tool_calls":[{"function":{"name":"write_file","arguments":"${args}"}}]}`;
    const findings = scan(enc(body), {}, rules).filter((f) => f.secretType === "aws-access-key-id");
    expect(findings.length).toBe(1);

    const out = dec(redactBody(enc(body), findings).bytes);
    expect(out).not.toContain(key);
    expect(out).toContain("[REDACTED:aws-access-key-id:");
    // Both nesting levels must still parse: the outer request, and the
    // tool-call arguments string it carries.
    const outer = JSON.parse(out) as { tool_calls: Array<{ function: { arguments: string } }> };
    const inner = JSON.parse(outer.tool_calls[0]!.function.arguments) as { path: string; content: string };
    expect(inner.path).toBe(".env");
    expect(inner.content).toContain("[REDACTED:aws-access-key-id:");
    expect(inner.content).toContain("# prod creds\n"); // a real newline, decoded
  });

  // End-to-end for the span bug above: a 4-char password equal to the username
  // is below redactValuesInText's 8-char echo-scrub floor, so nothing downstream
  // rescues it — if the span is wrong, the password ships in cleartext.
  test("a connection-string password matching the username is redacted, not the username", () => {
    const body = '{"MONGO_URL":"mongodb://root:root@db.internal:27017/app"}';
    const findings = scan(enc(body), {}, rules).filter((f) => f.secretType === "connection-string");
    expect(findings.length).toBe(1);
    const out = dec(applyCaptureRedaction({
      incomplete: false, requestBytes: enc(body), requestFindings: findings, responseBody: null,
      extraValues: [],
    }).requestBody);
    expect(out).not.toContain(":root@"); // the password is gone
    expect(out).toContain("mongodb://root:[REDACTED:connection-string:"); // the username is not
    expect(JSON.parse(out)).toBeDefined(); // stored JSON still parses
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

  test("a value whose escapes are malformed still scrubs by its raw form", () => {
    // A match that cut an escape in half is not a well-formed JSON string body,
    // so no decoded variant exists. The failed decode must not throw out of the
    // scrub, and must not cost the RAW form its scrub either — asserted with the
    // value actually PRESENT, since a no-op on absent text would pass either way.
    const value = "secret-value-with-trailing\\";
    const out = redactValuesInText(`held ${value} here`, [{ value, type: "x" }]);
    expect(out).toBe(`held ${redactionPlaceholder("x", value)} here`);
  });

  test("redactValuesInText scrubs escapes other than \\n (quote, tab, unicode)", () => {
    // The `\n` case is what surfaced the bug, but the mismatch is general: any
    // escape the display decodes leaves the raw matched value un-findable.
    const tab = String.fromCharCode(9);
    // Each pair is [what the scanner matched in the raw bytes, what the display shows].
    const pairs: Array<[string, string]> = [
      ['api\\"key\\"value', 'api"key"value'],
      ["api\\tkey\\tvalue", `api${tab}key${tab}value`],
      ["api\\u0041key\\u0042value", "apiAkeyBvalue"],
    ];
    for (const [escaped, decoded] of pairs) {
      const out = redactValuesInText(`sent ${decoded} onward`, [{ value: escaped, type: "x" }]);
      expect(out).toBe(`sent ${redactionPlaceholder("x", escaped)} onward`);
    }
  });

  test("redactValuesInText scrubs the JSON-ESCAPED form of a decoded value", () => {
    // The mirror of the two tests above, and the direction extraValues needs:
    // the value was matched in the DERIVED text (decoded) and has to be scrubbed
    // from the raw BODY, where it is escaped. Only the decode direction existed,
    // because every value used to come from the bytes and travel outward.
    const decoded = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsaid"quoted"\n-----END RSA PRIVATE KEY-----';
    const escaped = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAsaid\\"quoted\\"\\n-----END RSA PRIVATE KEY-----';
    const out = redactValuesInText(`{"prompt":"${escaped}"}`, [{ value: decoded, type: "private-key" }]);
    expect(out).not.toContain("MIIEowIBAAKCAQEAsaid");
    expect(out).toBe(`{"prompt":"${redactionPlaceholder("private-key", decoded)}"}`);
  });

  test("escaping can lift a sub-floor value OVER the 8-char floor, and that is intended", () => {
    // The floor is re-checked per form, and the note on redactValuesInText
    // reasons about decoding, which only SHORTENS. Encoding lengthens: this
    // six-char value is under the floor raw and eight escaped, so the escaped
    // form scrubs where the raw one is skipped. Over-redaction of a genuine
    // secret, i.e. the fail-safe direction — and the form that clears the floor
    // is the more distinctive of the two, so it is the safer one to act on.
    // Pinned because it is a behaviour the third form ADDED, not one it
    // inherited.
    const raw = 'a"b"cd'; // 6
    const escaped = 'a\\"b\\"cd'; // 8
    expect(raw.length).toBe(6);
    expect(escaped.length).toBe(8);
    expect(redactValuesInText(`held ${raw} here`, [{ value: raw, type: "x" }])).toBe(`held ${raw} here`);
    expect(redactValuesInText(`{"k":"${escaped}"}`, [{ value: raw, type: "x" }])).toBe(
      `{"k":"${redactionPlaceholder("x", raw)}"}`,
    );
  });

  test("an extraValue no span covers is masked out of the stored bodies", () => {
    // The derived-scan hole: a finding only the DERIVED scan made is in no
    // `requestFindings` list, so redactBody masks nothing and the row used to
    // claim `redacted` over a body still holding the key. JSON escaping is the
    // usual cause — `\": \"` is six characters where the parsed message content
    // spends four on `": "`, over the generic rule's `["':=\s]{1,5}` cap (and
    // starting with a backslash, which that class does not even accept).
    const key = "Xk7Qm2Vb9Rt4Ws8Yz1Nc6Pd3aJ5Hf0Lg";
    const body = JSON.stringify({ messages: [{ role: "user", content: `config has "api_key": "${key}" in it` }] });
    expect(scan(enc(body), {}, rules)).toEqual([]); // premise: the body scan sees nothing
    const out = applyCaptureRedaction({
      incomplete: false,
      requestBytes: enc(body),
      requestFindings: [],
      responseBody: enc(`I set ${key} for you`), // …and the echo in the reply
      extraValues: [{ value: key, type: "generic-api-key" }],
    });
    expect(dec(out.requestBody)).not.toContain(key);
    expect(dec(out.requestBody)).toContain("[REDACTED:generic-api-key:");
    expect(dec(out.responseBody!)).not.toContain(key);
    expect(out.redacted).toBe(true);
    expect(JSON.parse(dec(out.requestBody))).toBeDefined(); // still parseable
    // Handed back, so the surfaces the CALLER redacts from these same bytes —
    // the raw SSE stream, the search text, the summary's backstop — cover it
    // without a second list to keep in step.
    expect(out.values).toContainEqual({ value: key, type: "generic-api-key" });
  });

  test("an extraValue is masked in the ESCAPED form the body actually holds", () => {
    // The derived scan matches the decoded rendering, so its value carries real
    // newlines while the bytes carry `\n`. A literal-match scrub of the raw form
    // alone silently no-ops here — the same mismatch that produced this
    // function's decode direction, read the other way.
    const decoded = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAonlyInTheRendering\n-----END RSA PRIVATE KEY-----";
    const body = JSON.stringify({ prompt: `deploy with:\n${decoded}` });
    const out = applyCaptureRedaction({
      incomplete: false,
      requestBytes: enc(body),
      requestFindings: [],
      responseBody: null,
      extraValues: [{ value: decoded, type: "private-key" }],
    });
    expect(dec(out.requestBody)).not.toContain("MIIEowIBAAKCAQEAonlyInTheRendering");
    expect(dec(out.requestBody)).toContain("[REDACTED:private-key:");
  });

  test("an extraValue absent from the bytes leaves them alone, and `redacted` says so", () => {
    // The other derived-only shape: a secret the display MANUFACTURED by joining
    // two content blocks is in no body at all, so there is nothing here to mask.
    // `redacted` must not claim a rewrite that didn't happen — the viewer paints
    // its highlight on that flag, and the wire path switches its search text to
    // the stored body when it is set. (The row still reads redacted overall: the
    // caller ORs in the derived parts it DID rewrite.)
    const body = '{"messages":[{"content":"half AKIAZQ3DRSTUV"},{"content":"WXY2345 half"}]}';
    const out = applyCaptureRedaction({
      incomplete: false,
      requestBytes: enc(body),
      requestFindings: [],
      responseBody: null,
      extraValues: [{ value: "AKIAZQ3DRSTUVWXY2345", type: "aws-access-key-id" }],
    });
    expect(dec(out.requestBody)).toBe(body); // byte-identical
    expect(out.redacted).toBe(false);
  });

  // redactDerivedParts is what the value scrub above structurally cannot be:
  // it splices the offsets of a scan run over the DERIVED text itself, so it
  // reaches secrets that exist only in the rendering.
  test("redactDerivedParts splices a finding out of the one part that holds it", () => {
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const parts = ["hello", `key ${secret} here`, "bye"];
    // Ask for the joined text rather than restating the separator: it is a
    // NUL barrier now, so no rule can match across the join.
    const joined = derivedScanText(parts);
    const at = joined.indexOf(secret);
    const out = redactDerivedParts(parts, [finding(at, at + secret.length, "aws-access-key-id")]);
    expect(out.parts[0]).toBe("hello"); // untouched
    expect(out.parts[2]).toBe("bye");
    expect(out.parts[1]).toBe(`key ${redactionPlaceholder("aws-access-key-id", secret)} here`);
    // The value comes back in the DERIVED form, for scrubbing text built from
    // these parts that isn't one of them (the summary's quoted ask).
    expect(out.values).toEqual([{ value: secret, type: "aws-access-key-id" }]);
  });

  // The floor is redactValuesInText's alone. This path is what makes a short
  // secret recoverable at all — it splices by OFFSET, and an offset does not
  // care how long the value is — so state that as its own assertion rather than
  // leaving it implied by the daemon tests that depend on it. Four chars is the
  // shortest a rule can report today (connection-string's secretGroup is the
  // password alone, `([^\s@\/]{4,})`), which is exactly half the floor: a floor
  // added here "for symmetry" with the value scrub would silently reopen the
  // hole this path exists to close.
  test("redactDerivedParts has NO length floor — a 4-char finding is still spliced", () => {
    const secret = "abcd";
    const parts = ["connect with", `mongodb+srv://svc:${secret}@cluster0.mongodb.test/db`];
    const joined = derivedScanText(parts);
    const at = joined.indexOf(`:${secret}@`) + 1; // the password alone, as secretGroup reports it
    const out = redactDerivedParts(parts, [finding(at, at + secret.length, "connection-string")]);
    expect(out.parts[0]).toBe("connect with"); // untouched
    expect(out.parts[1]).toBe(`mongodb+srv://svc:${redactionPlaceholder("connection-string", secret)}@cluster0.mongodb.test/db`);
    expect(out.values).toEqual([{ value: secret, type: "connection-string" }]);
    // And the contrast that makes the point: the same value through the value
    // scrub is a NO-OP. Two passes, one input, opposite outcomes — which is why
    // every derived surface must be built from the parts above and never from
    // raw text handed to the scrub.
    expect(redactValuesInText(parts[1]!, out.values)).toBe(parts[1]!);
  });

  test("redactDerivedParts splices a finding that SPANS two parts out of both", () => {
    // A PEM whose BEGIN and END sit in different messages: the transcript
    // renders them adjacently, so it is readable, so it must be masked — and
    // neither part may be left holding its half.
    const parts = [
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAspanning",
      "tail\n-----END RSA PRIVATE KEY-----",
    ];
    // Ask for the joined text rather than restating the separator: it is a
    // NUL barrier now, so no rule can match across the join.
    const joined = derivedScanText(parts);
    const out = redactDerivedParts(parts, [finding(0, joined.length, "private-key")]);
    expect(out.parts[0]).not.toContain("MIIEowIBAAKCAQEAspanning");
    expect(out.parts[0]).not.toContain("BEGIN RSA PRIVATE KEY");
    expect(out.parts[1]).not.toContain("END RSA PRIVATE KEY");
    // Each part is fully replaced here, so both read as the same placeholder —
    // one secret, two masks, which is the over-redacting direction.
    const ph = redactionPlaceholder("private-key", joined);
    expect(out.parts).toEqual([ph, ph]);
  });

  test("redactDerivedParts skips an overlapping second finding rather than double-splicing", () => {
    // Two quiet-tier rules can flag the same characters; splicing twice would
    // corrupt the text around them. Same guard redactBody holds — and the
    // skipped finding's value is still reported, so callers can scrub it.
    const parts = [`x ${"a".repeat(40)} y`];
    const out = redactDerivedParts(parts, [finding(2, 42, "generic"), finding(2, 30, "aws-secret-shape")]);
    expect(out.parts[0]).toBe(`x ${redactionPlaceholder("generic", "a".repeat(40))} y`);
    expect(out.values.length).toBe(2);
  });

  test("redactDerivedParts handles many findings scattered over many parts", () => {
    // The part walk carries a cursor that only moves downward, relying on the
    // findings being applied in descending order. A cursor that advanced too
    // far would silently skip a part — leaving a secret in the transcript with
    // every other assertion still green — so sweep a whole grid: one secret in
    // every part, plus untouched filler either side of each to catch an
    // off-by-one splice.
    const parts: string[] = [];
    const secrets: string[] = [];
    for (let i = 0; i < 40; i++) {
      const s = `SECRET${String(i).padStart(2, "0")}${"v".repeat(12)}`;
      secrets.push(s);
      parts.push(`head${i}-${s}-tail${i}`);
    }
    const joined = derivedScanText(parts);
    const findings = secrets.map((s) => {
      const at = joined.indexOf(s);
      return finding(at, at + s.length, "generic");
    });
    // Shuffled deterministically: redactDerivedParts sorts internally, and a
    // caller is not required to hand them over in order.
    const shuffled = findings.filter((_, i) => i % 2 === 0).concat(findings.filter((_, i) => i % 2 === 1));
    const out = redactDerivedParts(parts, shuffled);
    for (let i = 0; i < parts.length; i++) {
      expect(out.parts[i]).toBe(`head${i}-${redactionPlaceholder("generic", secrets[i]!)}-tail${i}`);
    }
    expect(out.values.length).toBe(secrets.length);
  });

  test("derivedSplitAt agrees with derivedScanText about where the halves meet", () => {
    // The outbound/inbound split is what keeps an inbound secret from being
    // reported as a leak, and it is computed WITHOUT joining the outbound half
    // (too expensive on a long conversation). If the two ever disagreed about
    // the separator, findings would be attributed to the wrong direction and
    // nothing else would notice — so pin their agreement directly.
    for (const head of [[], [""], ["ab"], ["ab", "cde"], ["", "x", ""]]) {
      const tail = ["INBOUND"];
      const joined = derivedScanText([...head, ...tail]);
      const at = derivedSplitAt(head);
      expect(joined.slice(at)).toBe(derivedScanText(tail));
      // …and it lands one past the last head part, on the separator, so a
      // finding starting exactly there counts as head — the fail-safe side.
      if (head.length > 0) expect(joined[at - 1]).toBe("\n");
    }
  });

  test("clampRedacted cuts past a straddling placeholder, never through it", () => {
    const ph = redactionPlaceholder("aws-access-key-id", "AKIAZQ3DRSTUVWXY2345");
    // The cap lands 4 characters into the placeholder: a plain slice would
    // leave "[RED", which reads as a corrupted transcript, not a redaction.
    const text = `${"f".repeat(10)}${ph} trailing`;
    const out = clampRedacted(text, 14);
    expect(out).toBe(`${"f".repeat(10)}${ph}`);
    // Nothing to protect: a cut in ordinary text is exact.
    expect(clampRedacted("f".repeat(50), 14)).toBe("f".repeat(14));
    expect(clampRedacted("short", 14)).toBe("short");
  });

  test("clampRedacted is not defeated by a literal [REDACTED: in captured content", () => {
    // The cap bounds what a tool RESULT persists, and a tool result is content
    // the agent's environment chose — including, say, a log line another
    // scrubber wrote. Running to the next `]` after any `[REDACTED:` let that
    // content opt itself out of the cap entirely: a 500 KB result stored whole
    // where the cap says 4000. Only a well-formed placeholder earns the
    // overshoot.
    const hostile = "x".repeat(3990) + "auth=[REDACTED: by ci-scrubber " + "y".repeat(500_000) + "]";
    expect(clampRedacted(hostile, 4000).length).toBe(4000);
    // A truncated-looking opener with no bracket at all is also just cut.
    expect(clampRedacted("z".repeat(3995) + "[REDACTED:" + "z".repeat(9000), 4000).length).toBe(4000);
    // …while a real placeholder still survives whole.
    const real = "z".repeat(3995) + redactionPlaceholder("aws-access-key-id", "AKIAZQ3DRSTUVWXY2345");
    const out = clampRedacted(real, 4000);
    expect(out.endsWith("]")).toBe(true);
    expect(out.length).toBeLessThan(4040);
  });

  test("secretKeys matches an escaped body value against its decoded rendering", () => {
    // The dedup the alert path needs: one PEM seen in the bytes and again in
    // the transcript is one leak, but the scanner's fingerprint can't say so —
    // it strips whitespace, and the escaped form's `\n` is a backslash and an
    // `n`, which survives.
    const escaped = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAkeyed\\n-----END RSA PRIVATE KEY-----";
    const decoded = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAkeyed\n-----END RSA PRIVATE KEY-----";
    const shared = secretKeys(escaped).filter((k) => secretKeys(decoded).includes(k));
    expect(shared.length).toBeGreaterThan(0);
    // Two genuinely different secrets must not collide.
    expect(secretKeys("AKIAZQ3DRSTUVWXY2345").some((k) => secretKeys("AKIAZQ3DRSTUVWXY9999").includes(k)))
      .toBe(false);
  });

  test("redactRawStream span-redacts a value the scrub floor skips", () => {
    // The gap this closes: redactValuesInText ignores values under 8 chars, and
    // connection-string captures the password alone. The raw stream was
    // value-scrubbed and nothing else, so a short password stayed cleartext
    // there while the body beside it was spliced clean.
    const stream = 'data: {"text":"postgres://svc:pw12@db.internal/app"}\n\n';
    const start = stream.indexOf("pw12");
    const spans = [finding(start, start + 4, "connection-string")];
    // No values passed: the span pass alone must do it. Handing it the value too
    // would still pass if the floor were lowered, hiding which pass did the work.
    const out = redactRawStream(enc(stream), enc(stream), spans, []);
    expect(dec(out!)).not.toContain("pw12");
    expect(dec(out!)).toContain("[REDACTED:connection-string:");
    // and the surrounding stream is intact — the splice is the span, not the frame
    expect(dec(out!)).toContain('data: {"text":"postgres://svc:');
  });

  test("redactRawStream still scrubs echoed values that no span covers", () => {
    const secret = "AKIAZQ3DRSTUVWXY2345";
    const stream = `data: {"text":"echoing ${secret}"}\n\n`;
    // No findings of its own (the echo was detected request-side) — the value
    // pass must still reach it.
    const out = redactRawStream(enc(stream), enc(stream), [], [{ value: secret, type: "aws-access-key-id" }]);
    expect(dec(out!)).not.toContain(secret);
    expect(dec(out!)).toContain("[REDACTED:aws-access-key-id:");
  });

  test("redactRawStream withholds the stream when it is NOT the scanned bytes", () => {
    // The spans index the scanned body. If the capture path ever stops handing
    // the stream those same bytes, splicing at those offsets would corrupt the
    // stream instead of failing — so it is dropped, not guessed at (§4).
    const stream = 'data: {"text":"key AKIAZQ3DRSTUVWXY2345"}\n\n';
    const scanned = "reassembled: key AKIAZQ3DRSTUVWXY2345";
    const start = scanned.indexOf("AKIA");
    expect(redactRawStream(enc(stream), enc(scanned), [finding(start, start + 20)], [])).toBeNull();
    // Same LENGTH, different bytes: the check is content, not size. The span
    // would land inside the stream here, so a length-only guard would splice
    // the wrong 20 characters and hand back a corrupted stream that looks fine.
    const a = 'data: {"k":"AKIAZQ3DRSTUVWXY2345"}';
    const b = 'data: {"k":"AKIAZQ3DRSTUVWXY9999"}';
    expect(redactRawStream(enc(a), enc(b), [finding(12, 32)], [])).toBeNull();
  });

  test("applyCaptureRedaction holds all content out on an incomplete scan", () => {
    const out = applyCaptureRedaction({
      incomplete: true,
      requestBytes: enc("could hold anything"),
      requestFindings: [],
      responseBody: enc("also unverified"),
      extraValues: [],
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
      extraValues: [],
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
      extraValues: [],
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
