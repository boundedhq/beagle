// redact-on-capture (design §4/R11): drop the raw secret value at capture
// time, keeping a stable typed placeholder. The single biggest store-liability
// reducer, and ON by default (config.ts) — a detection tool must not itself
// keep detected secrets in cleartext. Opting out buys the raw-fidelity view.
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
// value, it does not re-scan the text. Cases where the display and the scanned
// bytes disagree about more than escaping escape it, and no further list of
// value forms can reach them — a match spanning JSON structure, or a secret
// MANUFACTURED by a join out of bytes the scanner never saw as a secret. Those
// need the derived text scanned on its own so its own offsets drive its own
// redaction, which is what redactDerivedParts below does; this function is the
// cheap complement, not a guarantee that derived text is secret-free.
function jsonUnescaped(value: string): string | null {
  if (!value.includes("\\")) return null; // no escapes: decoded form is identical
  try {
    const out: unknown = JSON.parse(`"${value}"`);
    return typeof out === "string" && out !== value ? out : null;
  } catch {
    return null; // not a JSON string body — nothing was escaped, nothing to add
  }
}

// Hoisted: a literal here would materialize a RegExp per call, and this runs
// once per value per scrubbed text (O(values x messages) on the summary pass).
const JSON_MUST_ESCAPE_RE = /["\\\u0000-\u001f]/;

// The same difference read the other way, and needed for the same reason once a
// value can arrive from a DERIVED surface: applyCaptureRedaction's extraValues
// are matched in the transcript's decoded text and scrubbed from the raw BODY,
// where a `"` inside them is `\"` and a newline is `\n`. Only jsonUnescaped
// existed because every value used to come from the bytes and travel outward.
//
// The pre-test keeps this off the hot path — buildSummary scrubs once per
// message, so an unconditional stringify would run O(values x messages) times
// per call to throw all of it away on the alphanumeric keys that are the norm.
// JSON.stringify's escaping is ONE serializer's choice, so this reaches the
// escapes every serializer agrees on and not the optional ones (a body writing
// `\/` for a slash, or `\u0041` for an ASCII letter, renders that value in a
// third form this misses) — which is why the derived text is SCANNED rather
// than only re-encoded.
//
// Narrow by construction, and unit-tested rather than end-to-end for that
// reason: of the 30 rules, only connection-string (`[^\s@\/]{4,}`) and
// private-key (`[\s\S]`) have a secret group that can hold a character JSON
// escapes at all — every other value class is alphanumeric-ish, so this returns
// null and costs one regex test. And for those two the body scan usually
// matches as well, because maskJsonEscapes lets it see through the escapes, so
// a real span already covers the bytes. This is for the residue of that
// intersection: a value the derived scan matched decoded, in bytes no span
// reached.
function jsonEscaped(value: string): string | null {
  if (!JSON_MUST_ESCAPE_RE.test(value)) return null; // nothing JSON must escape
  // Unconditional past the pre-test: every character it lets through is one
  // JSON must escape, so the encoded form always differs from the raw one.
  return JSON.stringify(value).slice(1, -1); // strip the quotes it adds
}

// Scrub known secret values by literal match wherever they appear — used on
// derived text (summary, search text) built from parsed messages rather than
// the stored bytes, so a body-side redaction can't be undone by a re-derive,
// and (as applyCaptureRedaction's extraValues) in the other direction, on bytes
// holding the ESCAPED form of a value the derived scan matched decoded.
// The 8-char floor avoids mangling unrelated text on common substrings; a
// shorter value is still span-redacted from the body it was found in but
// SURVIVES here. A rule matching that short is not hypothetical —
// connection-string captures the password alone, so `postgres://u:pw12@host/db`
// yields a four-char value. So treat this pass as an echo-catcher and never as
// a guarantee: what actually removes a short secret is a SPAN, and only from
// bytes some scan matched it in (redactBody, redactRawStream, redactDerivedParts).
// Where no span can exist the floor is the whole defence and a short value
// survives — buildSummary scrubs raw parsed text by value alone, so a password
// under the floor reaches the always-visible feed line. Known and unfixed here:
// a floor low enough to catch it would blank four-char substrings everywhere.
// Do not read this floor as safe for short values. Re-checked per form, because
// the forms differ in length both ways. Decoding only SHORTENS, and the floor is
// a weaker guarantee for a decoded form than for a raw one: 48 chars of \uXXXX
// escapes decode to the 8-char word "password", and scrubbing that would blank
// the word wherever it appears. Encoding only LENGTHENS, so it runs the other
// way — a six-char `a"b"cd` is skipped raw and scrubbed as the eight-char
// `a\"b\"cd`, which is the more distinctive string of the two and so the safer
// one to act on. Both directions over-redact rather than under-, which is why
// the check is per form and not on the raw value alone.
// Over-redaction, i.e. the fail-safe direction, and it needs a client that
// escapes ASCII letters — no standard serializer does (Python's ensure_ascii
// escapes only non-ASCII) — so it is documented rather than guarded against.
export function redactValuesInText(
  text: string,
  values: Array<{ value: string; type: string }>,
): string {
  for (const { value, type } of values) {
    // Every form hashes the RAW value, so one secret reads as one placeholder
    // whichever form was found — the viewer highlights body and transcript
    // alike. Hashed lazily, on the first form that actually hits: buildSummary
    // scrubs once per message plus once per action, so hashing every value up
    // front would run sha256 O(values x messages) times per captured call to
    // throw nearly all of it away.
    let placeholder: string | null = null;
    // LONGEST FIRST, and that ordering is load-bearing rather than tidy: one
    // form can be a SUBSTRING of another, and replacing the short one first
    // consumes the middle of the long one and leaves its head behind. Concrete,
    // and it corrupts the stored body rather than just missing: a value opening
    // with a backslash (connection-string and private-key both admit one) sits
    // in the bytes as `\\abcdefgh`, the raw form `\abcdefgh` matches at offset
    // ONE, and the result is `\[REDACTED:…]` — a dangling escape that no longer
    // parses as JSON, on a row reporting a clean rewrite. Encoding only
    // lengthens and decoding only shortens, so escaped/raw/decoded IS that
    // order; sorting by length would say the same thing less directly.
    for (const form of [jsonEscaped(value), value, jsonUnescaped(value)]) {
      if (form !== null && form.length >= 8 && text.includes(form)) {
        placeholder ??= redactionPlaceholder(type, value);
        text = text.split(form).join(placeholder);
      }
    }
  }
  return text;
}

/** Keys one secret VALUE across the two things that differ between a raw body
 *  and its rendering: JSON escaping and line wrapping. Two findings sharing a
 *  key are the same secret seen twice, not two leaks. The scanner's fingerprint
 *  can't answer that on its own — it strips whitespace so a rewrapped PEM
 *  matches itself, but the escaped form's `\n` is a backslash and an `n`, not
 *  whitespace, so it survives and hashes to something else. */
export function secretKeys(value: string): string[] {
  const bare = (s: string) => s.trim().replace(/\s+/g, "");
  const decoded = jsonUnescaped(value);
  return decoded === null ? [bare(value)] : [bare(value), bare(decoded)];
}

// ---- derived-text redaction ----
//
// The scanner reads the RAW bytes; every DERIVED surface (display_messages, the
// summary, the Mode B half of searchText) renders a TRANSFORMED view of them —
// content blocks joined, JSON structure dropped, escapes decoded, a non-string
// tool argument re-serialized canonically. Where the transform changes more
// than escaping, NO expansion of the value-form list above can reach it, and in
// the worst case the transform MANUFACTURES a secret: flattenPromptText joins
// adjacent content blocks with no separator, so a key split across two blocks
// exists in the transcript and the search index while the scanned bytes hold
// nothing a rule matches — no value to scrub, and no alert. The only sound
// answer is to scan the derived text itself and splice ITS offsets, which is
// what these two do together (the caller owns the scan; see Daemon.redactDerived).
//
// The parts are scanned JOINED, one per line, because a rule must see a secret
// whole and the transcript renders these strings adjacently — a PEM whose BEGIN
// and END sit in two messages is readable to whoever opens the call, so it is
// found here even though neither message alone holds it.
//
// What the join must NOT do is INVENT one, and a bare "\n" did: the quiet
// rules' delimiter classes accept whitespace — generic-api-key is
// `(?:…|key|secret|token|…)["':=\s]{1,5}(value)` — so a message ending "…needs
// an API token" followed by one starting with a base64-ish word matched ACROSS
// the newline. Nothing like it was ever sent; the two are adjacent only in this
// rendering. The cost was paid twice: a bogus leak event, and the genuinely
// sent text replaced by a placeholder in the search index — a false negative on
// the one question `beagle search` answers definitively.
//
// The NUL fixes that structurally, which is the only way it can be fixed here:
// a finding's span is its capture GROUP (engine.scan), i.e. the value alone, so
// it sits wholly inside one part even when the delimiter that matched it
// crossed the join — a filter on the span cannot even see the fusion. No rule's
// delimiter or value class contains NUL, so nothing matches across it, while
// `[\s\S]`-style rules (the PEM) still span it exactly as before, because that
// class is every character.
const DERIVED_SEP = "\n\u0000\n";

/** The exact text `redactDerivedParts` assumes its findings were scanned over.
 *  NOT the search text: the NUL has no business in fts5 content, and the index
 *  needs no offset agreement because masking already happened per part. */
export function derivedScanText(parts: string[]): string {
  return parts.join(DERIVED_SEP);
}

/** Where `rest` begins in `derivedScanText([...head, ...rest])`, so a caller can
 *  split findings between the two halves without joining `head` a second time
 *  just to measure it — on a long conversation that join is megabytes. The
 *  offset is one past the separator FOLLOWING the last head part — the index of
 *  `rest[0]`'s first character — so the daemon's strict `f.start <
 *  derivedSplitAt(head)` assigns a finding starting exactly there to `rest`.
 *  That is the correct side, not a fail-safe hedge: the character at that
 *  position is rest's first byte, so a finding starting on it IS rest content. */
export function derivedSplitAt(head: string[]): number {
  return head.reduce((n, p) => n + p.length + DERIVED_SEP.length, 0);
}

/** Splice each finding out of every part it overlaps. Findings carry offsets
 *  into `derivedScanText(parts)`; a finding that spans the join is spliced out
 *  of BOTH parts it touches, so neither is left holding a readable half —
 *  two placeholders for one secret, which is over-redaction, the fail-safe
 *  direction. Returns the redacted parts plus the values, in the DERIVED form,
 *  for scrubbing text built from these parts that isn't one of them (the
 *  summary's quoted ask, a truncated display copy). */
export function redactDerivedParts(
  parts: string[],
  findings: Finding[],
): { parts: string[]; values: Array<{ value: string; type: string }> } {
  if (findings.length === 0) return { parts, values: [] };
  const joined = derivedScanText(parts);
  // Where each part starts in `joined`, so a finding's span can be clipped to it.
  const starts: number[] = [];
  for (let i = 0, at = 0; i < parts.length; i++) {
    starts.push(at);
    at += parts[i]!.length + DERIVED_SEP.length;
  }
  const out = [...parts];
  const values: Array<{ value: string; type: string }> = [];
  // Descending, with the same overlap guard as redactBody: splicing from the
  // end keeps every lower offset valid, and two rules flagging the same bytes
  // must not double-splice. The skipped finding's value is still recorded.
  //
  // `hi` rides that same descending order — the highest part a finding can
  // touch only ever falls — so parts are walked once across the whole loop
  // rather than rescanned per finding. Not a micro-optimization: the input is
  // attacker-shaped (a long conversation saturated with secret-shaped values
  // hits the scanner's per-rule finding cap in every rule), and the quadratic
  // form costs ~100ms of the single-writer daemon's time per such call where
  // this costs ~4ms.
  let lastStart = Infinity;
  let hi = parts.length - 1;
  for (const f of [...findings].sort((a, b) => b.start - a.start)) {
    const value = joined.slice(f.start, f.end);
    values.push({ value, type: f.secretType });
    while (hi > 0 && starts[hi]! >= f.end) hi--; // begins at/after the span: no overlap
    if (f.end > lastStart) continue;
    const placeholder = redactionPlaceholder(f.secretType, value);
    for (let i = hi; i >= 0; i--) {
      const s = starts[i]!;
      const e = s + parts[i]!.length;
      if (f.start >= e) break; // this part ends before the span, as do all below it
      if (f.end <= s) continue;
      out[i] = out[i]!.slice(0, Math.max(f.start, s) - s) + placeholder + out[i]!.slice(Math.min(f.end, e) - s);
    }
    lastStart = f.start;
  }
  return { parts: out, values };
}

// A placeholder in full, anchored — NOT just the `[REDACTED:` opener, which is
// an ordinary literal any captured tool output may contain. Matching the opener
// alone and running to its next `]` let content defeat the cap outright: a
// result holding `[REDACTED:` before the cut and its next bracket megabytes
// later was stored whole. secretType is a rule id from the pinned corpus, and
// the hash is six hex, so the shape is exact and short.
const PLACEHOLDER_RE = /^\[REDACTED:[^\s:\]]+:[0-9a-f]{6}\]/;

/** Bound redacted text to `max` without cutting a placeholder in half. Callers
 *  clamp AFTER redacting (clamping first spares the raw head of a secret that
 *  straddles the cap), which makes a placeholder straddling it the normal case
 *  — and `…ffff [REDACTED:` reads as a corrupted transcript rather than as a
 *  masked secret. Run past the closing bracket instead, but only for a
 *  well-formed placeholder: the overshoot is then bounded by the shape itself,
 *  so the cap stays a cap no matter what the captured content says. */
export function clampRedacted(text: string, max: number): string {
  if (text.length <= max) return text;
  const open = text.lastIndexOf("[REDACTED:", max - 1);
  if (open >= 0) {
    // 128 is comfortably past the longest possible placeholder, and bounds the
    // slice so a huge tail is never copied just to test its head.
    const m = PLACEHOLDER_RE.exec(text.slice(open, open + 128));
    if (m && open + m[0].length > max) return text.slice(0, open + m[0].length);
  }
  return text.slice(0, max);
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

// The raw event stream kept beside a streamed response (the Layer 2 fidelity
// view). Despite the name it is not a RENDER of the response body — for a
// stream carrying no content-encoding the two hold the SAME BYTES: the capture
// path content-decodes into bodyBytes and reassembles nothing, so both are
// copies of one buffer (core/proxy/server.ts). Nothing scans this column on its
// own; it borrows the response scan's verdict, which is sound only because of
// that. Borrowing the SPANS as well as the values is the point: redactValuesInText
// carries an 8-char floor, and connection-string's secretGroup captures the
// password alone — `postgres://u:pw12@host/db` yields a FOUR-char value, spliced
// out of the body and, until this ran, silently left raw here.
//
// Spans first, then the value scrub for echoes of secrets found elsewhere — the
// order applyCaptureRedaction uses on the two bodies. That second pass inherits
// the floor it just indicted, so read it as best-effort, not a second guarantee:
// what makes this column safe is the span pass, and only for what the response
// scan itself matched in these bytes.
//
// The spans hold only while the two really are the same bytes. If that ever
// stops being true — a capture path that reassembles deltas into bodyBytes —
// a splice would land at the wrong offset and corrupt the stream rather than
// fail, so verify instead of assuming, and withhold the stream when the check
// fails: never store bytes whose redaction nothing vouched for (§4).
export function redactRawStream(
  sseRaw: Uint8Array | null,
  scannedBody: Uint8Array | null,
  findings: Finding[],
  values: Array<{ value: string; type: string }>,
): Uint8Array | null {
  if (!sseRaw || !scannedBody || !sameBytes(sseRaw, scannedBody)) return null;
  const spanned = findings.length > 0 ? redactBody(sseRaw, findings).bytes : sseRaw;
  return redactValues(spanned, values) ?? spanned;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export interface CaptureRedaction {
  /** True only when these BODIES were actually rewritten — measured, not
   *  claimed. NOT the row's `redacted` column and NOT the viewer highlight:
   *  those answer "was any stored content rewritten", and the DERIVED surfaces
   *  (display_messages, summary, search index) are stored content this field
   *  says nothing about. A secret the display manufactured by joining two
   *  content blocks rewrites those three and no body, so it reads false here
   *  and true on the row. The caller owns that OR — it is the half that knows
   *  what it did with its own parts (daemon.ts, both capture paths). */
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
// plus (`extraValues`) the values of secrets another scan of the same call
// found where no span here can reach them, and the caller scrubs its derived
// text with the returned values.
export function applyCaptureRedaction(o: {
  incomplete: boolean;
  requestBytes: Uint8Array;
  requestFindings: Finding[];
  responseBody: Uint8Array | null;
  responseFindings?: Finding[];
  /** Secrets some OTHER scan of this call reported — the derived-text pass —
   *  so no span in THESE bytes covers them. The findings lists above are what
   *  the body scan matched IN the bodies; a derived-only finding is absent from
   *  them, so without this redactBody masks nothing and the row claims
   *  `redacted` over a payload still holding the value (35 of 35 derived-only
   *  findings measured over 671 real wire calls sat verbatim in the body —
   *  usually because JSON escaping pushed the rule's context out of reach, not
   *  because the display manufactured anything).
   *
   *  BY VALUE, deliberately, and never by an offset re-anchored into these
   *  bytes: a splice offset must come from the regex's own `d`-flag indices
   *  (engine.scan), because a value recovered by SEARCHING for the match picks
   *  whichever occurrence comes first — for `mongodb://root:root@host` that was
   *  the USERNAME's span, and redaction shipped the password in cleartext. A
   *  value is insensitive to which occurrence wins; a span is not.
   *
   *  So it inherits both of redactValuesInText's residuals, documented on the
   *  functions that own them — the 8-char floor and the fixed list of value
   *  forms. Both are LIVE here, not theoretical, because this is the one caller
   *  with no span to fall back on. Pinned by tests rather than left to be
   *  rediscovered:
   *
   *  - Under the floor only connection-string can go (it captures the bare
   *    password). The tempting mitigation — "the password class eats JSON
   *    structure up to the `@`, so the body matches too and a span covers it" —
   *    is FALSE: that class is `[^\s@\/]{4,}`, so any space, `/` or `@` in the
   *    bytes between two content blocks stops it, and python's json.dumps
   *    writes `", "` by default. An ordinary Python client whose connection
   *    string straddles two blocks therefore stores a 4-char password in the
   *    clear on a row that reads `redacted`. Not floor-exempted, because
   *    scrubbing a four-char string out of a whole request body blanks
   *    unrelated text with it — `root` inside a path, an id, a timestamp — and
   *    over-redacting the Layer-2 fidelity view that far is its own harm.
   *  - A serializer escaping what JSON.stringify leaves alone (`\/`, `\u0041`)
   *    writes a form no re-encoding produces, and that one loses the WHOLE
   *    value, not a short one. Reachable from a general HTTP client rather than
   *    from the agents beagle ships shims for.
   *
   *  REQUIRED, not optional, though `[]` is a perfectly good answer. A new
   *  ingest path that simply forgot this would compile clean while reopening
   *  exactly the hole it closes — an omission no type checker and no test would
   *  report. Spelling `[]` is a decision; leaving it out was an accident. */
  extraValues: Array<{ value: string; type: string }>;
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
  // No fast path for "nothing to do": every step below returns its input BY
  // REFERENCE when its list is empty (redactBody, redactValues), so the
  // fall-through already is that path — `redacted` then measures false and the
  // caller gets its own bytes back. A guard here would have to enumerate every
  // input source to stay correct, and getting that enumeration wrong is silent.
  // That is this fix one level up: the guard read the two findings lists, so
  // adding a third source of secrets would have skipped the scrub entirely.
  const req = redactBody(o.requestBytes, o.requestFindings);
  // spans first: offsets index the original bytes
  const resp = respFindings.length > 0 && o.responseBody ? redactBody(o.responseBody, respFindings) : null;
  // Span redaction only masks the ONE occurrence the scanner reported, but a
  // secret can appear more than once in a body (the codex request echoes the
  // prompt across several fields) and an echoed key can reappear in the
  // response. Value-scrub BOTH bodies with every detected value so no raw copy
  // of a detected secret survives — in the stored bytes or the search index
  // derived from them. Placeholders match redactBody's, so the viewer still
  // highlights them.
  //
  // extraValues ride the SAME pass, which is the whole of their fix: they have
  // no span here by construction, so the scrub is not a backstop for them the
  // way it is for the spanned values — it is the only thing that masks them.
  // Returned in `values` as well, so the surfaces the caller redacts from these
  // same bytes (the raw SSE stream, the search text, the summary's backstop)
  // cover them without a second list to keep in step.
  //
  // Deduped by VALUE, because these lists overlap BY CONSTRUCTION: a secret
  // matched in both views is in req.values and again in extraValues (the
  // derived pass reports every finding, not only the derived-only ones), a body
  // echoing one key reports it once per occurrence, and two rules on the same
  // bytes report it twice. Every copy after the first is a guaranteed MISS in
  // redactValuesInText — the first pass already replaced every occurrence — and
  // a miss is the most expensive search there is, a full pass over the body.
  // Measured on an 8 MiB body: 1000 identical values cost 346 ms where one
  // costs 0.31 ms. Output is unchanged, because the first entry already won —
  // its type picks the placeholder and the duplicates no-op behind it. The
  // dedup lands HERE and not per consumer because the list leaves through
  // `values` into five of them (both bodies, the raw stream, the summary, the
  // transcript), and it rides the array copy those spreads already pay for.
  //
  // Sorted LONGEST FIRST for the reason the form list is (see
  // redactValuesInText): one value can be a SUBSTRING of another — two rules
  // matching the same bytes at different widths is the ordinary case, e.g.
  // aws-access-key-id's 20 chars inside generic-api-key's 28 — and scrubbing
  // the short one first leaves the long one's tail in the clear beside a
  // placeholder. Sorted once here rather than inside the scrub, which runs per
  // message. Stable, so equal-length duplicates keep the order the dedup
  // filtered on.
  const seen = new Set<string>();
  const values = [...req.values, ...(resp?.values ?? []), ...o.extraValues]
    .filter((v) => {
      if (seen.has(v.value)) return false;
      seen.add(v.value);
      return true;
    })
    .sort((a, b) => b.value.length - a.value.length);
  const requestBody = redactValues(req.bytes, values) ?? req.bytes;
  const responseBody = redactValues(resp?.bytes ?? o.responseBody, values);
  // Measured, not assumed. A finding always rewrites the body it was found in,
  // but an extraValue need not appear in these bytes at all — a secret the display
  // MANUFACTURED by joining two content blocks exists only in the derived text
  // — and claiming a rewrite that didn't happen would put the viewer's
  // highlight on unredacted bytes and switch the caller's search text to a body
  // nothing touched. Identity holds because redactValues returns its input when
  // it changes nothing.
  const redacted = requestBody !== o.requestBytes || responseBody !== o.responseBody;
  return { redacted, heldOut: false, requestBody, responseBody, values };
}
