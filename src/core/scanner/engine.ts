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
  start: number;
  end: number;
  fingerprint: string;
  destinationOwnKey: boolean;
}

export interface ScanCtx {
  authValue?: string;
}

// Placeholder values that are overwhelmingly documentation, not leaks —
// the main FP source on coding-agent traffic (R5).
const STOPWORDS = ["example", "sample", "placeholder", "dummy", "xxxxxx", "changeme"];

const MAX_FINDINGS_PER_RULE = 500;

// Bodies are scanned as raw bytes — nothing on the scan path JSON-unescapes
// them — so a secret pasted at the start of a line arrives preceded by the
// TWO-character sequence `\n`, not a newline. Its `n` is a word character, so
// a rule anchored with a leading `\b` finds no boundary and misses outright:
// "here is the key\nAKIA…" reported nothing at all. That shape — secret first
// on a line — is exactly how a key gets pasted into a chat prompt.
//
// Fixed by masking rather than by loosening the rules: every escape whose
// final character is a word char is blanked to spaces before matching, so the
// separator the rules already expect is really there. Two properties make
// this safe:
//   - Length is preserved, so match offsets still index the raw bytes that
//     redaction and the store slice (values are re-read from the raw text).
//   - Masking only ever turns word chars into spaces, so it can add a
//     boundary but never fabricate one inside a secret — no rule's charset
//     contains a backslash, so no secret can span an escape.
// It also leaves every rule regex untouched, which matters: anchoring a rule
// with a leading lookaround instead costs ~100x scan time (V8 can no longer
// fast-scan for the literal prefix) and blows the R5 budget.
//
// Only the escapes JSON actually defines are recognized. A backslash before
// anything else is literal text — a Windows path (`C:\creds\AKIA…`), a regex,
// a LaTeX macro — and blanking it would EAT the secret's own first character
// and turn a detection into a miss.
//
// `\\`, `\"` and `\/` are matched but left alone: they already end in a
// non-word char. Consuming them still matters for correct left-to-right
// tokenizing — in `\\n` the `n` is literal text, not an escape, and must keep
// suppressing the boundary.
//
// Masking alone is still not enough, because a body that is NOT JSON can carry
// a bare backslash that looks exactly like an escape and nothing here can tell
// the two apart. `C:\creds\redis://u:pw@h/0` loses the `r` of `redis` and the
// high-severity connection-string rule misses it; the same rule's password
// group accepts backslashes, so `mongodb://u:ab\ncd@h/db` loses a character
// mid-value. That is why scan() runs the rules over BOTH views and unions the
// results rather than trusting the masked view alone.
const JSON_ESCAPE = /\\(?:u[0-9a-fA-F]{4}|[bfnrt"\\/])/g;

// Hot path: an 8 MiB escape-dense body runs this millions of times, so the
// replacement avoids a per-match regex test. A match is either a 6-char
// `\uXXXX` or a 2-char `\X`; only `"`, `\` and `/` end in a non-word char.
const SPACES_2 = "  ";
const SPACES_6 = "      ";
const QUOTE = 34, BACKSLASH = 92, SLASH = 47;

export function maskJsonEscapes(text: string): string {
  if (!text.includes("\\")) return text; // fast path: nothing to mask
  return text.replace(JSON_ESCAPE, (esc) => {
    if (esc.length === 6) return SPACES_6; // \uXXXX — tail is a hex digit
    const c = esc.charCodeAt(1);
    return c === QUOTE || c === BACKSLASH || c === SLASH ? esc : SPACES_2;
  });
}

export function compileRules(specs: RuleSpec[], hmacKey: Uint8Array): CompiledRules {
  return {
    rules: specs.map((spec) => ({ spec, re: new RegExp(spec.regex, spec.flags ?? "g") })),
    hmacKey,
  };
}

export function scan(bytes: Uint8Array, ctx: ScanCtx, compiled: CompiledRules): Finding[] {
  const raw = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const masked = maskJsonEscapes(raw);
  // Both views, unioned. The masked view finds a secret whose separator is a
  // JSON escape; the raw view finds one whose backslash was literal text after
  // all. Neither view alone is sound — see JSON_ESCAPE — and a miss costs more
  // than the second pass, which only runs when the views actually differ.
  // Offsets agree because masking is length-preserving, so a finding from
  // either view indexes the same raw bytes and dedupes by span.
  const findings = matchAll(raw, masked, ctx, compiled);
  if (masked !== raw) {
    for (const f of matchAll(raw, raw, ctx, compiled)) {
      if (!findings.some((g) => g.start === f.start && g.end === f.end && g.detector === f.detector)) {
        findings.push(f);
      }
    }
  }
  return suppressOverlaps(findings);
}

// Run every rule over `view`, reporting spans into `raw`. Split out of scan()
// only so both views share one implementation.
function matchAll(raw: string, view: string, ctx: ScanCtx, compiled: CompiledRules): Finding[] {
  const text = view;
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
    // probeBudget: decode-probe attempts are capped per rule pass because
    // rejected candidates don't count toward MAX_FINDINGS_PER_RULE. The cap is
    // a deadline backstop, not a detection limit: a probe is ~0.35µs, so even
    // an 8 MB body (the capture cap) full of ~134k base64 runs adds well under
    // 50ms — the cap is set far above any realistic blob count so a genuine
    // wrapped secret isn't lost behind a wall of benign base64, while a truly
    // pathological body still can't ride the probe past the scan deadline.
    let ruleFindings = 0, probeBudget = 1 << 16;
    let m: RegExpExecArray | null;
    while (ruleFindings < MAX_FINDINGS_PER_RULE && (m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; } // zero-width guard
      // Span the capture group, not the whole match: consumed leading
      // delimiters and keyword prefixes must not leak into the span, or
      // redact-on-capture splices them out too (e.g. eating a quote corrupts
      // the stored JSON) and echo-scrubbing fails to match the bare secret.
      // indexOf is exact when the group text appears once in the match; on a
      // duplicate it still spans an identical occurrence of the same value.
      const matched = m[spec.secretGroup] ?? m[0];
      const start = m.index + m[0].indexOf(matched);
      // Masking is length-preserving, so the span maps straight back onto the
      // unmasked bytes — every gate below judges the value that really shipped.
      const secretRaw = raw.slice(start, start + matched.length);
      const secret = normalize(secretRaw);
      if (secret.length === 0) continue;
      const secretLower = secret.toLowerCase();
      if (STOPWORDS.some((w) => secretLower.includes(w))) continue;
      if (spec.entropy !== undefined && shannonEntropy(secret) < spec.entropy) continue;
      if (spec.validators?.includes("luhn") && !luhnValid(secret)) continue;
      // base64-secret validator: the blob only counts if it DECODES to
      // something a structured rule recognizes — base64 of anything else stays
      // silent, which is what keeps this rule viable on agent traffic full of
      // benign base64. The decoded text runs the SAME stopword gate as a direct
      // match, so a wrapped documentation key (base64 of AKIA…EXAMPLE) is
      // suppressed just like the plaintext one. Validator-bearing rules are
      // excluded from the probe, so it can't recurse and the base64 rule's own
      // in-flight cursor is never touched; probed regexes need no lastIndex
      // restore because this loop resets lastIndex before every rule's scan.
      if (spec.validators?.includes("base64-secret")) {
        const decoded = --probeBudget >= 0 ? Buffer.from(secret, "base64").toString("utf8") : "";
        if (decoded.length < 8 || STOPWORDS.some((w) => decoded.toLowerCase().includes(w)) || !compiled.rules.some(({ spec: s, re: r }) =>
          s.tier === "structured" && !s.validators?.length && ((r.lastIndex = 0), r.test(decoded)))) continue;
      }
      ruleFindings++;
      findings.push({
        detector: spec.id,
        secretType: spec.id,
        severity: spec.severity,
        tier: spec.tier,
        start,
        end: start + secretRaw.length,
        fingerprint: fingerprint(secret, compiled.hmacKey),
        destinationOwnKey:
          authNorm !== undefined && (authNorm === secret || authNorm.includes(secret)),
      });
    }
  }

  return findings;
}

// Overlap suppression: a structured hit owns its span; possible-tier findings
// on the same bytes are noise (the generic rule re-matching an AWS key must
// not double-report). Runs on the UNION of both views, so a structured hit
// found only in the raw view still silences a quiet-tier hit from the masked
// one.
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

// Only the escapes that decode to a DIFFERENT character. `\"` `\\` `\/` — the
// other three JSON_ESCAPE admits — decode to themselves and fall through below.
const ESCAPE_CHARS: Record<string, string> = { b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

// Transport noise dropped before hashing: JSON string escapes decoded, then all
// whitespace stripped. The same PEM must fingerprint identically re-wrapped AND
// carried in a JSON body, or R6 dedup re-alerts on the one key — matchAll() hands
// us the RAW slice on purpose (every gate judges what really shipped), so there
// the newlines are still the two characters \ + n and /\s+/ alone keeps both.
// Decoding, not maskJsonEscapes(): the mask leaves `\/` `\"` `\\` in place, right
// for its boundary job, wrong here, where a slash-escaping encoder would still
// split a base64 body's fingerprint. ONE left-to-right pass, so `\\n` stays a
// backslash then `n`; collapsing `\\` in an earlier pass would merge it with a
// real newline.
//
// Stored fingerprints are NOT migrated. Only a capture containing a backslash
// hashes differently than before; every other rule's alphabet excludes one, so
// those rows keep the value they were written with. (Today that is just
// private-key and connection-string, but rules are data on their own cadence —
// the invariant is the guarantee, not that census.) Re-deriving the rest would
// mean re-scanning stored bodies, which redact-on-capture masks by default;
// not re-deriving costs one re-alert per secret still in flight.
//
// Undecidable residue, in both directions, for a secret holding a REAL backslash:
// `hun\ter2secret` sent raw decodes to a tab that /\s+/ then eats, but sent
// JSON-encoded decodes to `\t`, so it still fingerprints twice — and it can
// equally MERGE with a different password whose literal spelling matches the
// decoded one. Both are far narrower than the systematic split fixed here, which
// hits every JSON-encoded PEM.
export function fingerprint(normalizedSecret: string, hmacKey: Uint8Array): string {
  const decoded = normalizedSecret.replace(JSON_ESCAPE, (esc) => {
    if (esc.length !== 6) return ESCAPE_CHARS[esc[1]!] ?? esc[1]!; // \X, not \uXXXX
    const cp = parseInt(esc.slice(2), 16);
    // Surrogates stay as written. Decoded, every lone one UTF-8-encodes to the
    // same U+FFFD, so distinct secrets would share a fingerprint and the second
    // would dedup as the first and never alert — a miss, the one direction this
    // must not fail in. Leaving them costs at worst a re-alert on a non-ASCII
    // secret sent both escaped and raw, and secrets in scope are ASCII.
    return cp >= 0xd800 && cp <= 0xdfff ? esc : String.fromCharCode(cp);
  });
  return createHmac("sha256", hmacKey).update(decoded.replace(/\s+/g, "")).digest("hex");
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
