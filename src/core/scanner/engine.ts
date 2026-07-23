// Scanner engine (design §6.3): a pure, bounded-time function — no I/O, no
// global state. Pipeline: keyword prescan → regex → entropy gate → checksum
// validators → auth annotation → tier + fingerprint. Hosted in a worker by
// the adapter; the deadline is enforced there (a sync regex can't be
// interrupted from its own thread).
import { createHmac } from "node:crypto";
import type { RuleSpec } from "./rules";

export interface CompiledRules {
  rules: Array<{ spec: RuleSpec; re: RegExp }>;
  hmacKey: Uint8Array;
}

export interface Finding {
  detector: string;
  secretType: string;
  severity: string;
  tier: "structured" | "possible";
  alert?: boolean;
  start: number;
  end: number;
  fingerprint: string;
  destinationOwnKey: boolean;
}

export interface ScanCtx {
  authValue?: string;
}

export interface ScanReport {
  findings: Finding[];
  cappedRules: string[];
  probeBudgetExhausted: boolean;
}

// Placeholder values that are overwhelmingly documentation, not leaks —
// the main FP source on coding-agent traffic (R5).
const STOPWORDS = ["example", "sample", "placeholder", "dummy", "xxxxxx", "changeme"];

const MAX_FINDINGS_PER_RULE = 500;
const MAX_PROBES = 1 << 16;

// Bodies are scanned as raw wire bytes — nothing on the scan path decodes them
// — so every secret arrives wrapped in however many layers of JSON string
// escaping the client applied, and the rules see the ESCAPES, not the decoded
// text. Two shapes were missed outright:
//
//   depth 1  {"content":"# creds\nAKIA…"}          wire: `\` `n` AKIA…
//   depth 2  {"arguments":"{\"content\":\"…\\nAKIA…"}  wire: `\` `\` `n` AKIA…
//
// In both, the char immediately before the secret is `n` — a word char — so a
// rule anchored `\b(AKIA…)` finds no boundary and reports nothing at all.
// Depth 2 is not exotic: OpenAI-style tool calls put their arguments in a JSON
// string nested inside the request JSON, so "the agent writes a .env file" —
// the mainstream form of the leak this tool exists to catch — lands there.
// Depth grows with relaying (a sub-agent forwarding a tool call adds a layer),
// so the MASKING below assumes no maximum. Detection does not follow it all the
// way: a `\b`-anchored rule needs one separator and is depth-independent, but a
// keyword-adjacency rule (generic-api-key, aws-secret-access-key) matches at
// most 5 separator chars between keyword and value, and every layer of encoding
// DOUBLES the backslashes in `":"` — 3 chars at depth 1, 5 at depth 2, 9 at
// depth 3. So those rules reach depth 2 and stop, and a PRETTY-PRINTED file
// stops one depth sooner still, because the space after the colon spends one of
// the five. Both pinned by tests; widening the quantifier is a rules-data
// change, not an engine one.
//
// Fixed by masking rather than by loosening the rules: an escape run is blanked
// to spaces before matching, so the separator the rules already expect is
// really there. Three properties make this safe:
//   - Length is preserved, so match offsets still index the raw bytes that
//     redaction splices and the store slices.
//   - Masking only ever writes spaces, so it can add a boundary but never
//     fabricate a non-space character inside a value. It CAN still shorten one:
//     two rules admit a backslash in what they capture (`private-key` via
//     `[\s\S]`, and `connection-string`'s password group via the negated
//     `[^\s@\/]`), so a password holding a literal `\n` is truncated in this
//     view. That is not a gap only because the raw view below also runs — it
//     is one of the concrete reasons that second pass is not optional.
//   - Every rule regex is left untouched. Anchoring rules with a leading
//     lookaround instead costs ~100x scan time (V8 can no longer fast-scan for
//     the literal prefix) and blows the R5 budget.
//
// The whole backslash run is consumed as ONE token, which is what makes depth
// fall out for free. Pairing backslashes off left-to-right instead (the
// single-encoding reading, where `\\` is one escaped backslash and the `n`
// after it is literal) is precisely what misses depth 2.
//
// But the run alone does not say how much of it is escape. The letter escapes
// (`\n` `\t` `\uXXXX`) at depth d carry 2^(d-1) backslashes — 1, 2, 4, 8,
// always a power of two — but a nested QUOTE carries 2^d - 1 — 1, 3, 7,
// always ODD, because every layer must re-escape the quote it wraps (`\/` does
// not share this: no standard encoder re-escapes a slash, so its runs just
// double like the letters') — and a literal backslash the sender typed adds
// 2^d in front of whatever follows. So `\\\"` is BOTH a pure depth-2 quote and a typed
// backslash before a depth-1 quote; the bytes cannot tell them apart. maskRun
// resolves every run toward the literal reading: only the trailing 2^k
// backslashes are treated as escape and blanked with their escape char, and
// the rest are kept. Keeping them is load-bearing — `C:\aws\` + newline + a
// 40-char digest arrives as a 3-run, and blanking all three erases the
// backslash that stops the digest reading as an aws-keyed secret at HIGH
// severity. The letter family loses nothing (its pure runs ARE the 2^k
// suffix, at every depth), but the quote family pays from depth 2 up: the
// quoted .env form `KEY=\"…\"` arrives at depth 2 as `KEY=\\\"…`, and the
// kept backslash is a phantom between `=` and the value that no separator
// class admits — the one-unit `\"` alternate in aws-secret-access-key reaches
// depth 1 only. So the QUOTED .env form gets one less depth of loud detection
// than the unquoted (HIGH through depth 1, only the quiet aws-secret-shape
// tier from depth 2) — the same asymmetry that rule's description records for
// the raw/depth-1 pair, moved one depth up. Extending it is separator data on
// that rule, not a different split here: run arithmetic cannot tell a phantom
// from a typed backslash.
//
// That reading cannot be the only one, because nothing on the wire tells an
// escape apart from a literal backslash in a body that is not JSON:
// `C:\creds\redis://u:pw@h/0` loses the `r` of `redis` and the high-severity
// connection-string rule misses it, and `C:\\npm_A7hK…` loses the `n` of the
// token. It also blanks the `t` of a literal `\token`, destroying the keyword
// the prescan needs. That is why scan() runs the rules over BOTH the masked
// and the unmasked view and unions the results — the two readings bracket an
// ambiguity the bytes genuinely do not resolve.
//
// Only the escapes JSON actually defines are recognized. A backslash before
// anything else is literal text — a Windows path, a regex, a LaTeX macro — and
// blanking it would EAT the secret's own first character, turning a detection
// into a miss.
//
// `\"` and `\/` are blanked even though their tail is already a non-word char,
// because a keyword-adjacency rule matches a keyword, a short run of separator
// chars, then the value: at depth 2, `"key":"…"` is on the wire as
// `\"key\":\"…` and backslash is in no rule's separator class, so those rules
// missed too. Blanking leaves `  key  :  …`, which they do match. Both chars
// are non-word, so this only ever adds separators.
const ESCAPE_RUN = /\\+(?:u[0-9a-fA-F]{4}|[bfnrt"/])?/g;

// Hot path: an escape-dense 8 MiB body runs the replacer millions of times, so
// blanking returns a shared, prebuilt string rather than building one per match
// (~28% faster than slicing a longer one). Runs are short in practice — 2 for
// `\n`, 3 for `\\n`, 7 for `\\uXXXX` — so the table covers every real case.
//
// The `repeat` fallback is NOT redundant, and dropping it would fail SILENTLY:
// a body padded with more than 32 consecutive backslashes would blank to a
// shorter string, and length preservation is what every span offset, redaction
// splice and store slice depends on.
const BLANKS = Array.from({ length: 33 }, (_, n) => " ".repeat(n));
const BACKSLASH = 92;

// Keeping the leading literals is not on its own enough, because a raw Windows
// path is bytewise a row of escapes with nothing left over to keep:
// `C:\aws\n3f9c…d5x\blob.bin` is a path holding no secret, and every run in it
// is a clean 1-backslash escape, so the split above has no literal to preserve.
// Blanking rewrites it to `C:\aws  3f9c…d5x  lob.bin`, which stands the `aws`
// keyword two spaces from a 40-char run and fires aws-secret-access-key at HIGH
// — the same alert the 3-run case above avoids, arriving by a different route.
//
// So the run is not the only unit. What tells the two apart is PARITY of the
// runs around it. JSON spells a literal backslash `\\`, and every further layer
// doubles that, so a run that opens no escape is 2, 4, 8 — always EVEN — in
// anything that was ever JSON-escaped. A bare ODD run is a lone backslash the
// sender typed, which no encoder produces: the text is raw. `C:\aws\n…` has a
// bare 1-run at `\a`, and that is the tell the path's own `\n` does not carry.
//
// The tell is then applied per TOKEN — a run of non-whitespace — all-or-nothing:
// one bare odd run anywhere in a token means every backslash in it is literal,
// including the ones that would have parsed. This composes with the split rather
// than replacing it: the split decides how much of a run is escape, parity
// decides whether the token is escaped text at all.
//
// The token is the right scope because it is the FP's own scope. Masking can
// only invent a keyword/value pair that was never adjacent by blanking what
// sits between them, and a keyword-adjacency rule reaches across at most 5
// separator chars, so both sides must share a token for anything to be
// manufactured. Whitespace already separated everything else.
//
// Parity is what keeps this from costing depth. A minified body is one long
// whitespace-free token, so a coarser test — "some run here opens nothing" —
// would let one Windows path in a sibling field silence the whole body:
// `{"path":"C:\\proj","content":"key:\nAKIA…"}` measurably lost its secret that
// way. Those runs are EVEN, correctly-encoded literal backslashes, so parity
// passes them and the nested secret still masks.
//
// It also narrows the ambiguity the union exists to bracket rather than widening
// it: `C:\creds\redis://u:pw@h/0` is one token with a bare 1-run, so it no
// longer loses the `r` of `redis` in this view. The union still runs — a token
// whose runs are all even is still indistinguishable from JSON — but it is
// asked to rescue less.

// Whitespace by code unit. `\s` would disagree on NUL, which separates the
// derived text's parts. NaN — charCodeAt past the end — counts, so a token cut
// off by the capture cap still ends.
const isBoundary = (c: number) => c <= 32 || Number.isNaN(c);

// A private twin of ESCAPE_RUN: the outer replace() owns that one's lastIndex,
// and reusing it here would corrupt the walk in progress.
const RUNS = /\\+(?:u[0-9a-fA-F]{4}|[bfnrt"/])?/g;

// One run is exempt from the tell: the one the CUT ITSELF writes. The proxy
// keeps at most captureBufferCap bytes of a body and drops the rest, and the
// cut lands wherever the chunk boundary fell — including between a backslash
// and its escape char. A body ending `…\` with the `n` dropped, or `…\u00`
// with the last hex digits dropped, ends in a bare odd run that no sender
// typed. Reading it as the raw-text tell un-masks the run's whole token, and a
// minified body is ONE token, so a cut inside any escape near the tail
// silently unmasked every escape-nested secret BEFORE the cut — unalerted,
// stored in cleartext, on a row whose scanState still read "ok". Measured with
// the real rules before this exemption: {"content":"key:\nAKIA…"} detected,
// and the same token with a trailing backslash detected nothing.
//
// So a bare odd run does not poison when nothing follows it but the end of the
// input — or `u` plus at most three hex digits there, the head of a \uXXXX the
// cut beheaded (RUNS consumes a whole uXXXX, so a bare run wearing a u+hex
// tail can only be a partial one). Forgiving it is safe on both sides:
//   - The stub itself is never blanked either way — maskRun already leaves any
//     run ending in a backslash untouched — so forgiveness only re-enables
//     masking of the token BEFORE the cut, the part still holding data.
//   - Only the input-terminal run is forgiven. A Windows path carries its tell
//     mid-token (`C:\aws\n…` poisons at `\a`), so the FP the parity rule
//     exists for stays silent even when the path is what the cap cut.
// The residue is a raw body whose final token's only lone backslash is its
// very last byte (`…aws\n<digest>\` ending the capture): bytewise identical to
// truncated JSON, and on the ambiguity this file trades toward the miss being
// the costlier failure.
const CUT_ESCAPE_TAIL = /^u[0-9a-fA-F]{0,3}$/;
// The length guard is not redundant with the regex's anchors: this runs for
// EVERY bare odd run in a raw body, mid-token ones included, and without the
// bound each call would slice the body's whole remainder — quadratic on
// backslash-dense raw text wherever substrings copy. Bound first, slice ≤4.
const cutMidEscape = (text: string, after: number): boolean =>
  after === text.length ||
  (text.length - after <= 4 && CUT_ESCAPE_TAIL.test(text.slice(after)));

function tokenPoisoned(text: string, start: number, end: number): boolean {
  RUNS.lastIndex = start;
  for (let m = RUNS.exec(text); m !== null && m.index < end; m = RUNS.exec(text)) {
    const run = m[0];
    if (run.charCodeAt(run.length - 1) !== BACKSLASH || run.length % 2 === 0) continue;
    if (cutMidEscape(text, m.index + run.length)) continue; // truncation stub, not a tell
    return true;
  }
  return false;
}

export function maskJsonEscapes(text: string): string {
  if (!text.includes("\\")) return text; // fast path: nothing to mask
  // The verdict is cached per token, not recomputed per run, so a body whose
  // runs all sit in one long token is walked twice over rather than once per
  // backslash. It cannot be decided lazily as each run arrives: the poison may
  // sit AFTER the run being masked, so the whole token is read up front.
  let tokenEnd = -1, poisoned = false;
  return text.replace(ESCAPE_RUN, (run, at: number) => {
    if (at >= tokenEnd) {
      let start = at;
      while (start > 0 && !isBoundary(text.charCodeAt(start - 1))) start--;
      tokenEnd = at;
      while (tokenEnd < text.length && !isBoundary(text.charCodeAt(tokenEnd))) tokenEnd++;
      poisoned = tokenPoisoned(text, start, tokenEnd);
    }
    return poisoned ? run : maskRun(run);
  });
}

function maskRun(run: string): string {
  // A run ending in a backslash consumed no escape char, so it is literal
  // text at every depth — leave it exactly as it arrived.
  if (run.charCodeAt(run.length - 1) === BACKSLASH) return run;
  // The literal reading: treat only the trailing 2^k backslashes as escape
  // and keep the rest. That preserves typed backslashes (separators the rules
  // rely on) at the price of a phantom backslash when a quote escape nests —
  // see ESCAPE_RUN for the ambiguity and what each side costs.
  let bs = 0;
  while (run.charCodeAt(bs) === BACKSLASH) bs++;
  let used = 1;
  while (used * 2 <= bs) used *= 2;
  const keep = bs - used;
  const blank = run.length - keep;
  return run.slice(0, keep) + (BLANKS[blank] ?? " ".repeat(blank));
}

export function compileRules(specs: RuleSpec[], hmacKey: Uint8Array): CompiledRules {
  // `d` (hasIndices) is added to every rule so matchAll can read a capture
  // group's REAL offsets instead of searching for its text — see the span
  // comment there for the leak that search caused. Rule data is untouched, so
  // the file's sha256 pin still validates.
  return {
    rules: specs.map((spec) => ({ spec, re: new RegExp(spec.regex, (spec.flags ?? "g") + "d") })),
    hmacKey,
  };
}

export function scan(bytes: Uint8Array, ctx: ScanCtx, compiled: CompiledRules): ScanReport {
  const raw = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const masked = maskJsonEscapes(raw);
  // Both readings of the bytes, unioned — see ESCAPE_RUN for why neither alone
  // is sound. Offsets agree because masking is length-preserving, so a finding
  // from either view indexes the same raw bytes and dedupes by span. The second
  // pass only runs when the views actually differ, i.e. when the body contains a
  // backslash followed by an escape character — whether that is a real escape or
  // literal text is exactly what cannot be known here, which is the point. A
  // miss costs far more than the extra pass.
  //
  // The caps are shared ACROSS both passes, not per pass. They are stated per
  // rule per body, and a second view silently doubling them would double what a
  // crafted body can push into suppressOverlaps below — the opposite of what a
  // deadline backstop is for.
  const budget: ScanBudget = {
    probes: MAX_PROBES,
    perRule: new Map(),
    cappedRules: new Set(),
    probeBudgetExhausted: false,
  };
  const findings = matchAll(raw, masked, ctx, compiled, budget);
  if (masked !== raw) {
    // Keyed dedup, not a scan of `findings` per candidate: both views can hit
    // the per-rule cap, and pairwise comparison would square that into a
    // pathological body's cheapest way to burn the scan deadline.
    const key = (f: Finding) => `${f.start}:${f.end}:${f.detector}`;
    const seen = new Set(findings.map(key));
    for (const f of matchAll(raw, raw, ctx, compiled, budget)) {
      if (!seen.has(key(f))) findings.push(f);
    }
  }
  return {
    findings: suppressOverlaps(findings),
    cappedRules: [...budget.cappedRules],
    probeBudgetExhausted: budget.probeBudgetExhausted,
  };
}

/** Per-body caps, shared by both views so each means what its name says. */
interface ScanBudget {
  probes: number;
  perRule: Map<string, number>;
  cappedRules: Set<string>;
  probeBudgetExhausted: boolean;
}

// Run every rule over `text` (one view of the body), reporting spans that index
// `raw`. Split out of scan() only so both views share one implementation.
function matchAll(raw: string, text: string, ctx: ScanCtx, compiled: CompiledRules, budget: ScanBudget): Finding[] {
  const lower = text.toLowerCase();
  const authNorm = ctx.authValue ? normalize(ctx.authValue) : undefined;
  const findings: Finding[] = [];

  for (const { spec, re } of compiled.rules) {
    // Keyword prescan: rules with no anchor keyword in the body never run
    // their regex — the lever that keeps scan time flat as rules grow.
    // An empty keyword list opts out: some secret shapes (telegram tokens,
    // anchor-free entropy rules) have no anchor substring to prescan for.
    if (spec.keywords.length > 0 && !spec.keywords.some((k) => lower.includes(k))) continue;
    re.lastIndex = 0;
    // Decode-probe attempts are capped per body because rejected candidates
    // don't count toward MAX_FINDINGS_PER_RULE. It sits far above any realistic
    // blob count; if reached, the report is explicitly incomplete rather than
    // claiming no wrapped secret exists behind the unchecked candidates.
    //
    // It is NOT cheap enough to ignore, which an earlier version of this note
    // claimed — it put a probe at ~0.35µs and concluded a saturated 8 MiB body
    // stayed "well under 50ms". Measured here: 0.84µs for a 16-char blob, 2.64µs
    // at 256 chars. A saturated budget is therefore on the order of 100ms+, i.e.
    // a real fraction of the 500ms worker deadline rather than a rounding error.
    // The deadline, not this cap, is what actually bounds a pathological body.
    let ruleFindings = budget.perRule.get(spec.id) ?? 0;
    let m: RegExpExecArray | null;
    while (ruleFindings < MAX_FINDINGS_PER_RULE && (m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; } // zero-width guard
      // Span the capture group, not the whole match: consumed leading
      // delimiters and keyword prefixes must not leak into the span, or
      // redact-on-capture splices them out too (e.g. eating a quote corrupts
      // the stored JSON) and echo-scrubbing fails to match the bare secret.
      //
      // Read the group's REAL offsets from the `d` flag. This used to search the
      // match for the group's text, which silently spans the WRONG occurrence
      // when a capture repeats text appearing earlier in the match — and that is
      // not a curiosity: `mongodb://root:root@host` (password same as username,
      // an ordinary dev-config shape) reported the USERNAME's span, so redaction
      // spliced the username and left the password in cleartext. Only the
      // 8-char floor on echo-scrubbing hid it for longer passwords.
      const at = m.indices?.[spec.secretGroup] ?? m.indices?.[0];
      const [start, end] = at ?? [m.index, m.index + m[0].length];
      // Masking is length-preserving, so the span maps straight back onto the
      // unmasked bytes — every gate below judges the value that really shipped,
      // and the finding reports the bytes redaction will splice.
      const secretRaw = raw.slice(start, end);
      const secret = normalize(secretRaw);
      if (secret.length === 0) continue;
      const secretLower = secret.toLowerCase();
      if (STOPWORDS.some((w) => secretLower.includes(w))) continue;
      if (spec.entropy !== undefined && shannonEntropy(secret) < spec.entropy) continue;
      if (spec.validators?.includes("luhn") && !luhnValid(secret)) continue;
      // base64-secret validator: the blob only counts if it DECODES to
      // something an alertable structured rule recognizes — base64 of anything
      // else stays silent, which is what keeps this rule viable on agent traffic
      // full of benign base64. Non-secret identifiers must not become a
      // "wrapped secret" merely because they were encoded. The decoded text
      // runs the SAME stopword gate as a direct match, so a wrapped documentation
      // key is suppressed just like the plaintext one. Validator-bearing rules are
      // excluded from the probe, so it can't recurse and the base64 rule's own
      // in-flight cursor is never touched; probed regexes need no lastIndex
      // restore because this loop resets lastIndex before every rule's scan.
      if (spec.validators?.includes("base64-secret")) {
        if (budget.probes === 0) {
          budget.probeBudgetExhausted = true;
          continue;
        }
        budget.probes--;
        const decoded = Buffer.from(secret, "base64").toString("utf8");
        if (decoded.length < 8 || STOPWORDS.some((w) => decoded.toLowerCase().includes(w)) || !compiled.rules.some(({ spec: s, re: r }) =>
          s.tier === "structured" && s.alert !== false && !s.validators?.length &&
          ((r.lastIndex = 0), r.test(decoded)))) continue;
      }
      ruleFindings++;
      findings.push({
        detector: spec.id,
        secretType: spec.id,
        severity: spec.severity,
        tier: spec.tier,
        alert: spec.alert,
        start,
        end,
        fingerprint: fingerprint(secretRaw, compiled.hmacKey),
        destinationOwnKey:
          authNorm !== undefined && (authNorm === secret || authNorm.includes(secret)),
      });
    }
    // Reaching the limit stops before another re.exec can prove the rule has no
    // unchecked tail. Conservatively report that rule as capped even when the
    // body happened to contain exactly 500 accepted matches.
    if (ruleFindings >= MAX_FINDINGS_PER_RULE) budget.cappedRules.add(spec.id);
    budget.perRule.set(spec.id, ruleFindings); // carries into the second view
  }

  return findings;
}

// Overlap suppression: a structured hit owns its span; possible-tier findings
// on the same bytes are noise (the generic rule re-matching an AWS key must
// not double-report). Runs on the UNION of both views, so a structured hit
// found only in the raw view still silences a quiet-tier hit from the masked
// one.
//
// This is O(possible x structured) and stays that way. What bounds it is
// MAX_FINDINGS_PER_RULE, which is per rule PER BODY — shared across both views
// on purpose (see scan). That caps the union at rules x 500 ≈ 15k findings,
// where this measures ~30ms, comfortably inside the worker's 500ms deadline.
// Were the cap ever made per-view again, or raised, this is the term that grows
// quadratically and the one to rewrite as a sweep over sorted spans.
function suppressOverlaps(findings: Finding[]): Finding[] {
  const structuredSpans = findings.filter((f) => f.tier === "structured");
  const result = findings.filter(
    (f) =>
      f.tier === "structured" ||
      !structuredSpans.some((s) => f.start < s.end && s.start < f.end),
  );
  return result.sort((a, b) => a.start - b.start || a.detector.localeCompare(b.detector));
}

export function normalize(s: string): string {
  return s.trim().replace(/^["']+|["']+$/g, "").trim();
}

// A SINGLE escape, tokenized one level deep — deliberately not ESCAPE_RUN, and
// the two must not be merged. Masking asks "could an escape at ANY depth be
// gluing a word char to this secret", and answers by consuming a whole
// backslash run; fingerprinting asks "what one level of JSON encoding did this
// value pick up in transit", and must decode exactly one, left to right. Using
// the run form here would collapse `\\n` to a newline and merge two values that
// really did differ on the wire.
const JSON_ESCAPE = /\\(?:u[0-9a-fA-F]{4}|[bfnrt"\\/])/g;

// Only the escapes that decode to a DIFFERENT character. `\"` `\\` `\/` — the
// other three JSON_ESCAPE admits — decode to themselves and fall through below.
const ESCAPE_CHARS: Record<string, string> = { b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

// Transport noise dropped before hashing: JSON string escapes decoded, THEN
// surrounding quotes and all whitespace stripped. The same PEM must fingerprint
// identically re-wrapped AND carried in a JSON body, or R6 dedup re-alerts on
// the one key — matchAll() hands us its RAW capture (the gates judge the
// normalize()d value; the hash canonicalizes from what really shipped), so the
// newlines arrive as the two characters \ + n.
// The decode runs BEFORE normalize()'s quote-strip because the decoration
// itself can arrive encoded: a password ending in `"` ships JSON-encoded as
// `pass\"`, and stripping the bare quote first left the dangling `pass\` — one
// secret, a fingerprint per encoding (`\u0022` split a third way). Decoded
// first, every arrival reaches the strip in its raw spelling and converges.
// Decoding, not maskJsonEscapes(): the mask BLANKS `\/` and `\"` (it used to
// leave them, which is what an earlier version of this note said), so reusing it
// here would delete the escaped character outright — the whitespace strip then
// eats the blank, and two values differing only by a slash would hash the same.
// Wrong direction: this function must not merge values that really did differ.
// ONE left-to-right pass, so `\\n` stays a backslash then `n`; collapsing `\\`
// in an earlier pass would merge it with a real newline.
//
// Stored fingerprints are NOT migrated. Only a capture containing a backslash
// hashes differently than before; every other rule's alphabet excludes one, so
// those rows keep the value they were written with. (Today that is just
// private-key and connection-string — and private-key cannot rotate: its
// captures are anchored by `-----` at both ends, so the quote-strip never
// fires and decode order is invisible to it. Rules are data on their own
// cadence — the invariant is the guarantee, not that census.) Re-deriving the
// rest would mean re-scanning stored bodies, which redact-on-capture masks by
// default; not re-deriving costs one re-alert per secret still in flight.
//
// Undecidable residue, in both directions, for a secret holding a REAL backslash:
// `hun\ter2secret` sent raw decodes to a tab that /\s+/ then eats, but sent
// JSON-encoded decodes to `\t`, so it still fingerprints twice — and it can
// equally MERGE with a different password whose literal spelling matches the
// decoded one. Both are far narrower than the systematic split fixed here, which
// hits every JSON-encoded PEM.
//
// One more instance of that residue, reachable only since the scanner started
// finding secrets nested inside tool-call arguments: at depth 2 the capture
// carries `\\n`, which this ONE pass decodes to a literal backslash + `n` that
// the whitespace strip does not eat, so a PEM sent inside a tool call
// fingerprints apart from the same PEM sent in an ordinary body. Deliberately
// not fixed by decoding to a fixpoint — that is the merge direction this
// function must not fail in, per the paragraph above. It costs one extra alert
// on the same two rules named above, private-key and connection-string, since
// only a capture that can contain a backslash is affected; every fixed-alphabet
// secret (AKIA…, ghp_…, sk-ant-…) still fingerprints identically at every depth.
// Both halves are pinned by tests.
export function fingerprint(secretRaw: string, hmacKey: Uint8Array): string {
  const decoded = secretRaw.replace(JSON_ESCAPE, (esc) => {
    if (esc.length !== 6) return ESCAPE_CHARS[esc[1]!] ?? esc[1]!; // \X, not \uXXXX
    const cp = parseInt(esc.slice(2), 16);
    // Surrogates stay as written. Decoded, every lone one UTF-8-encodes to the
    // same U+FFFD, so distinct secrets would share a fingerprint and the second
    // would dedup as the first and never alert — a miss, the one direction this
    // must not fail in. Leaving them costs at worst a re-alert on a non-ASCII
    // secret sent both escaped and raw, and secrets in scope are ASCII.
    return cp >= 0xd800 && cp <= 0xdfff ? esc : String.fromCharCode(cp);
  });
  return createHmac("sha256", hmacKey).update(normalize(decoded).replace(/\s+/g, "")).digest("hex");
}

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function luhnValid(s: string): boolean {
  const digits = s.replace(/\D/g, "");
  if (digits.length < 12) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}
