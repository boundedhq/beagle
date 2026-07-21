// redact-on-capture (design §4/R11): drop the raw secret value at capture
// time, keeping a stable typed placeholder. The single biggest store-liability
// reducer, and ON by default — a detection tool must not keep secrets in
// cleartext (DEFAULT_CONFIG.redactOnCapture, asserted in hardening.test.ts).
import { createHash } from "node:crypto";
import type { Finding } from "../core/scanner/engine";

export function redactionPlaceholder(secretType: string, secretValue: string): string {
  const shorthash = createHash("sha256").update(secretValue).digest("hex").slice(0, 6);
  return `[REDACTED:${secretType}:${shorthash}]`;
}

// Replace each finding's byte span with a placeholder. Findings carry offsets
// into the decoded text; we splice on the string then re-encode. Returns the
// redacted bytes plus the raw secret values (for scrubbing echoes elsewhere).
export function redactBody(bytes: Uint8Array, findings: Finding[]): { bytes: Uint8Array; values: Array<{ value: string; type: string }> } {
  if (findings.length === 0) return { bytes, values: [] };
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  // Apply from the end so earlier offsets stay valid as we splice.
  const ordered = [...findings].sort((a, b) => b.start - a.start);
  const values: Array<{ value: string; type: string }> = [];
  let out = text;
  // Splicing assumes non-overlapping spans; two quiet-tier rules can flag the
  // same bytes (e.g. a 40-char value matched by both the generic-assignment
  // and the aws-secret-shape rule), and a double splice would corrupt the
  // surrounding text. Skip any finding overlapping one already redacted —
  // its value is still recorded, so echo-scrubbing below removes every copy.
  let lastStart = Infinity;
  for (const f of ordered) {
    const value = text.slice(f.start, f.end);
    values.push({ value, type: f.secretType });
    if (f.end > lastStart) continue;
    out = out.slice(0, f.start) + redactionPlaceholder(f.secretType, value) + out.slice(f.end);
    lastStart = f.start;
  }
  return { bytes: new TextEncoder().encode(out), values };
}

// The scanner reads the RAW bytes, but the surfaces scrubbed below render a
// DECODED view of them: a Mode B prompt attribute carrying a serialized message
// list is JSON.parse'd for the transcript, and the wire path's summary comes
// from messages parsed out of the provider JSON. So a multi-line secret's
// matched value holds the two-char escape `\n` while the text to scrub holds a
// real newline — `includes` misses, the scrub silently no-ops, and the secret
// survives in the transcript and the search index even though the body was
// masked. Decode the value the same way the display did and scrub that form
// too. JSON.parse is the arbiter: a value that isn't a well-formed string body
// (a match that cut an escape in half, a non-JSON body with raw control chars)
// yields no variant and behaves exactly as before.
//
// BOUNDARY, so the next reader knows what this does NOT cover: it re-encodes a
// value, it does not re-scan the text. Two cases escape it, because in each the
// display and the scanned bytes disagree about more than escaping:
//   - A match SPANNING JSON STRUCTURE (a PEM whose BEGIN and END sit in two
//     messages of a serialized list) carries a literal `"},{"role":…` that the
//     flattened display drops, so neither form matches.
//   - A secret MANUFACTURED by flattening: flattenPromptText joins adjacent
//     content blocks with no separator, so a value split across two blocks
//     exists only in the display — the bytes never held that string, and no
//     value-scrub can find what was never there to scrub.
// Neither is fixable by adding more forms here; both need the derived text
// SCANNED on its own so its own findings drive its own redaction. That scan now
// exists (the daemon's scanDerivedText, Mode B), and its values arrive back
// here as applyCaptureRedaction's `extraValues`. So the guarantee is a joint
// one: this function covers re-encodings of a value the bytes already proved,
// the derived scan covers what only the rendered text shows — and this function
// alone is still not a guarantee that derived text is secret-free.
function jsonUnescaped(value: string): string | null {
  if (!value.includes("\\")) return null; // no escapes: decoded form is identical
  try {
    const out: unknown = JSON.parse(`"${value}"`);
    return typeof out === "string" && out !== value ? out : null;
  } catch {
    return null; // not a JSON string body — nothing was escaped, nothing to add
  }
}

// The MIRROR of jsonUnescaped, for a value matched in DERIVED text rather than
// in the bytes: the daemon's derived-text scan finds secrets in the flattened
// (JSON.parse'd) prompt, so its value carries a REAL newline while the stored
// body — the serialized form — holds the two-char escape `\n`. Without this
// form the direction that scrubs body-from-derived silently no-ops, the exact
// failure jsonUnescaped fixes in the opposite direction.
function jsonEscaped(value: string): string | null {
  // Cheap reject first, mirroring jsonUnescaped's `includes("\\")`: only a
  // quote, a backslash, a control char or a lone surrogate can change under
  // stringify, and the overwhelming majority of matched values (an API key, a
  // token) hold none of them. Without it the stringify runs for every value on
  // every derived-text scrub, and buildSummary scrubs once per message AND
  // once per action — the same per-call cost the lazy hashing below avoids.
  if (!/["\\\u0000-\u001f\ud800-\udfff]/.test(value)) return null;
  const out = JSON.stringify(value).slice(1, -1); // drop the wrapping quotes
  return out === value ? null : out; // nothing needed escaping
}

// The object boundary between two messages of a serialized list — the run
// flattenPromptText drops. A rule whose match can cross ANY bytes (private-key
// spans `[\s\S]{0,4096}?`) matches straight through it, so the raw bytes and
// the flattened rendering yield the SAME key as two different strings, hashing
// to two fingerprints and filing two events for one secret. Reversing the drop
// is what lets one secret read as one secret. Structural and bounded: `[^{}]*?`
// cannot span another object, and a value contains this run only if it really
// did span structure.
const STRUCTURE_RUN = /"\s*\}\s*,\s*\{[^{}]*?"(?:content|text)"\s*:\s*"/g;

/** Every encoding a matched value can appear in: as read from raw serialized
 *  bytes (a newline is the two-char escape `\n`) and as read from the parsed
 *  text (a real newline). Two forms of ONE secret, and the scanner's
 *  fingerprint cannot equate them — it strips WHITESPACE so a re-wrapped PEM
 *  dedups, but an escape sequence is not whitespace, so the two hash
 *  differently. The daemon's derived-text scan compares through this to drop a
 *  finding the raw bytes already proved, rather than filing one secret twice.
 *
 *  Returned as a list to intern into a Set, deliberately, so that comparison is
 *  a lookup: findings are capped per RULE, not in total, so a pairwise
 *  predicate would be quadratic in a number an adversarial body controls — on
 *  the daemon thread, outside the scan worker's deadline. */
export function secretForms(value: string): string[] {
  const forms = new Set<string>();
  // Structure first, then escaping — the two COMPOSE: a PEM that spanned two
  // messages carries both the object-boundary run and `\n` escapes, and only
  // dropping the run and then decoding reproduces what the rendering shows.
  // Messages join with "\n" and content blocks with "", so both readings are
  // offered rather than guessing which kind of boundary was crossed.
  //
  // The message join is substituted as the ESCAPED `\n`, not a real newline,
  // precisely so the decode can still run: the base has to stay a well-formed
  // JSON string body, and a raw newline inside one makes JSON.parse reject it —
  // which would silently drop the decoded form and leave the two readings of
  // one PEM looking like two secrets, the whole point of this.
  STRUCTURE_RUN.lastIndex = 0; // a /g regex carries state across test() calls
  const bases = STRUCTURE_RUN.test(value)
    ? [value, value.replace(STRUCTURE_RUN, "\\n"), value.replace(STRUCTURE_RUN, "")]
    : [value];
  for (const base of bases) {
    forms.add(base);
    for (const f of [jsonUnescaped(base), jsonEscaped(base)]) if (f !== null) forms.add(f);
  }
  return [...forms];
}

// Scrub known secret values by literal match wherever they appear — used on
// derived text (summary, search text) built from parsed messages rather than
// the stored bytes, so a body-side redaction can't be undone by a re-derive.
// The 8-char floor avoids mangling unrelated text on common substrings; a
// shorter value is still span-redacted from the body it was found in but
// would survive here — no rule matches anything that short today, so revisit
// the floor before adding one that does. Re-checked per form, because decoding
// only shortens — but note the floor is a weaker guarantee for a decoded form
// than for a raw one: 48 chars of \uXXXX escapes decode to the 8-char word
// "password", and scrubbing that would blank the word wherever it appears.
// Over-redaction, i.e. the fail-safe direction, and it needs a client that
// escapes ASCII letters — no standard serializer does (Python's ensure_ascii
// escapes only non-ASCII) — so it is documented rather than guarded against.
export function redactValuesInText(
  text: string,
  values: Array<{ value: string; type: string }>,
): string {
  for (const { value, type } of values) {
    // Both forms hash the RAW value, so one secret reads as one placeholder
    // whichever form was found — the viewer highlights body and transcript
    // alike. Hashed lazily, on the first form that actually hits: buildSummary
    // scrubs once per message plus once per action, so hashing every value up
    // front would run sha256 O(values x messages) times per captured call to
    // throw nearly all of it away.
    let placeholder: string | null = null;
    for (const form of [value, jsonUnescaped(value), jsonEscaped(value)]) {
      if (form !== null && form.length >= 8 && text.includes(form)) {
        placeholder ??= redactionPlaceholder(type, value);
        text = text.split(form).join(placeholder);
      }
    }
  }
  return text;
}

// Byte variant — used on the response body so an echoed key doesn't survive
// request-side redaction.
export function redactValues(
  bytes: Uint8Array | null,
  values: Array<{ value: string; type: string }>,
): Uint8Array | null {
  if (!bytes || values.length === 0) return bytes;
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const out = redactValuesInText(text, values);
  return out === text ? bytes : new TextEncoder().encode(out);
}

export interface CaptureRedaction {
  /** True only when the stored content was actually rewritten (viewer highlight). */
  redacted: boolean;
  /** Incomplete scan: bodies withheld outright — the caller must withhold its
   *  derived text (summary, search index, raw stream) too. */
  heldOut: boolean;
  requestBody: Uint8Array;
  responseBody: Uint8Array | null;
  values: Array<{ value: string; type: string }>;
}

// One redact-on-capture outcome per captured call (design §4/R11), shared by
// the wire and Mode B ingest paths. An incomplete scan can't trust any spans,
// so the raw content is held out entirely (never write raw-and-hope);
// otherwise each finding's span is substituted in the body it was found in,
// and the caller scrubs its derived text with the returned values.
export function applyCaptureRedaction(o: {
  incomplete: boolean;
  requestBytes: Uint8Array;
  requestFindings: Finding[];
  responseBody: Uint8Array | null;
  responseFindings?: Finding[];
  /** Secret values detected in a surface OTHER than these bytes — the daemon's
   *  derived-text scan of a flattened prompt. They carry no offsets into the
   *  request body (their spans index the flattened text), so they can only be
   *  value-scrubbed, never spliced. Two outcomes, both correct: where the value
   *  is a contiguous run the body also holds, the scrub masks it; where the
   *  flattening MANUFACTURED it by fusing two content blocks, the body never
   *  contained that string and there is nothing there to mask — but it is
   *  returned in `values` either way, so the caller scrubs the derived surfaces
   *  (summary, transcript, search index) where it does appear. */
  extraValues?: Array<{ value: string; type: string }>;
}): CaptureRedaction {
  if (o.incomplete) {
    return {
      redacted: true,
      heldOut: true,
      requestBody: new TextEncoder().encode("[REDACTION INCOMPLETE: scan did not verify this body]"),
      responseBody: null,
      values: [],
    };
  }
  const respFindings = o.responseFindings ?? [];
  const extra = o.extraValues ?? [];
  if (o.requestFindings.length === 0 && respFindings.length === 0 && extra.length === 0) {
    return { redacted: false, heldOut: false, requestBody: o.requestBytes, responseBody: o.responseBody, values: [] };
  }
  const req = redactBody(o.requestBytes, o.requestFindings);
  let responseBody = o.responseBody;
  // Ordered spans first, then the offset-less values, so the value-scrub below
  // runs over a body whose spliced spans are already placeholders.
  let values = [...req.values, ...extra];
  if (respFindings.length > 0 && responseBody) {
    const resp = redactBody(responseBody, respFindings); // spans first: offsets index the original bytes
    responseBody = resp.bytes;
    values = [...values, ...resp.values]; // keep `extra` — rebuilding from req.values would drop it
  }
  // Span redaction only masks the ONE occurrence the scanner reported, but a
  // secret can appear more than once in a body (the codex request echoes the
  // prompt across several fields) and an echoed key can reappear in the
  // response. Value-scrub BOTH bodies with every detected value so no raw copy
  // of a detected secret survives — in the stored bytes or the search index
  // derived from them. Placeholders match redactBody's, so the viewer still
  // highlights them.
  const requestBody = redactValues(req.bytes, values) ?? req.bytes;
  responseBody = redactValues(responseBody, values);
  // Reported from what actually CHANGED, not from "there was something to try".
  // An extraValues-only pass can legitimately rewrite nothing — a value the
  // flattening manufactured was never in these bytes to begin with — and
  // claiming otherwise would be a false badge on the row ("secrets masked in
  // storage") and, worse, would send the viewer down its placeholder-scanning
  // branch on a body that holds no placeholders. Both helpers return the input
  // reference untouched when they find nothing, so identity is the test.
  const redacted = requestBody !== o.requestBytes || responseBody !== o.responseBody;
  return { redacted, heldOut: false, requestBody, responseBody, values };
}
