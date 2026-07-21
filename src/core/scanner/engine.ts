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
// so nothing here assumes a maximum.
//
// Fixed by masking rather than by loosening the rules: an escape run is blanked
// to spaces before matching, so the separator the rules already expect is
// really there. Three properties make this safe:
//   - Length is preserved, so match offsets still index the raw bytes that
//     redaction splices and the store slices.
//   - Masking only ever writes spaces, so it can add a boundary but never
//     fabricate one inside a secret — no rule's charset contains a backslash,
//     so no secret can span an escape run.
//   - Every rule regex is left untouched. Anchoring rules with a leading
//     lookaround instead costs ~100x scan time (V8 can no longer fast-scan for
//     the literal prefix) and blows the R5 budget.
//
// The run is consumed ATOMICALLY — all consecutive backslashes, then one
// escape char — which is what makes depth fall out for free. Pairing them off
// left-to-right instead (the single-encoding reading, where `\\` is one
// escaped backslash and the `n` after it is literal) is precisely what misses
// depth 2. So the masked view deliberately takes the MAXIMALLY-DECODED reading
// of every run.
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
// blanking indexes a prebuilt string rather than allocating per match. Runs are
// short in practice (2 for `\n`, 3 for `\\n`, 7 for `\\uXXXX`); the fallback
// covers a pathological body padded with backslashes.
const SPACES = "                ";

export function maskJsonEscapes(text: string): string {
  if (!text.includes("\\")) return text; // fast path: nothing to mask
  return text.replace(ESCAPE_RUN, (run) => {
    // A run with no escape char after it is literal text at every depth.
    if (run.endsWith("\\")) return run;
    return run.length <= SPACES.length ? SPACES.slice(0, run.length) : " ".repeat(run.length);
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
  // Both readings of the bytes, unioned — see ESCAPE_RUN for why neither alone
  // is sound. Offsets agree because masking is length-preserving, so a finding
  // from either view indexes the same raw bytes and dedupes by span. The second
  // pass only runs when the views actually differ, i.e. when the body contains
  // a real escape; a miss costs far more than the extra pass.
  const findings = matchAll(raw, masked, ctx, compiled);
  if (masked !== raw) {
    // Keyed dedup, not a scan of `findings` per candidate: both views can hit
    // the per-rule cap, and pairwise comparison would square that into a
    // pathological body's cheapest way to burn the scan deadline.
    const seen = new Set(findings.map((f) => `${f.start}:${f.end}:${f.detector}`));
    for (const f of matchAll(raw, raw, ctx, compiled)) {
      if (!seen.has(`${f.start}:${f.end}:${f.detector}`)) findings.push(f);
    }
  }
  return suppressOverlaps(findings);
}

// Run every rule over `text` (one view of the body), reporting spans that index
// `raw`. Split out of scan() only so both views share one implementation.
function matchAll(raw: string, text: string, ctx: ScanCtx, compiled: CompiledRules): Finding[] {
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
      // unmasked bytes — every gate below judges the value that really shipped,
      // and the finding reports the bytes redaction will splice.
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

export function fingerprint(normalizedSecret: string, hmacKey: Uint8Array): string {
  // All whitespace stripped: the same PEM block re-sent with different line
  // wrapping must fingerprint identically or R6 dedup re-alerts on it.
  return createHmac("sha256", hmacKey)
    .update(normalizedSecret.replace(/\s+/g, ""))
    .digest("hex");
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
