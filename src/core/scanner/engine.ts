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

export function compileRules(specs: RuleSpec[], hmacKey: Uint8Array): CompiledRules {
  return {
    rules: specs.map((spec) => ({ spec, re: new RegExp(spec.regex, spec.flags ?? "g") })),
    hmacKey,
  };
}

export function scan(bytes: Uint8Array, ctx: ScanCtx, compiled: CompiledRules): Finding[] {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
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
    let ruleFindings = 0;
    let m: RegExpExecArray | null;
    while (ruleFindings < MAX_FINDINGS_PER_RULE && (m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; } // zero-width guard
      const secretRaw = m[spec.secretGroup] ?? m[0];
      const secret = normalize(secretRaw);
      if (secret.length === 0) continue;
      const secretLower = secret.toLowerCase();
      if (STOPWORDS.some((w) => secretLower.includes(w))) continue;
      if (spec.entropy !== undefined && shannonEntropy(secret) < spec.entropy) continue;
      if (spec.validators?.includes("luhn") && !luhnValid(secret)) continue;
      // base64-secret validator: the blob only counts if it DECODES to
      // something a structured rule recognizes — base64 of anything else stays
      // silent, which is what keeps this rule viable on agent traffic full of
      // benign base64. Validator-bearing rules are excluded from the probe, so
      // it can't recurse and the base64 rule's own in-flight cursor is never
      // touched; probed regexes need no lastIndex restore because this loop
      // resets lastIndex before every rule's scan.
      if (spec.validators?.includes("base64-secret")) {
        const decoded = Buffer.from(secret, "base64").toString("utf8");
        if (decoded.length < 8 || !compiled.rules.some(({ spec: s, re: r }) =>
          s.tier === "structured" && !s.validators?.length && ((r.lastIndex = 0), r.test(decoded)))) continue;
      }
      const start = m.index;
      ruleFindings++;
      findings.push({
        detector: spec.id,
        secretType: spec.id,
        severity: spec.severity,
        tier: spec.tier,
        start,
        end: start + m[0].length,
        fingerprint: fingerprint(secret, compiled.hmacKey),
        destinationOwnKey:
          authNorm !== undefined && (authNorm === secret || authNorm.includes(secret)),
      });
    }
  }

  // Overlap suppression: a structured hit owns its span; possible-tier
  // findings on the same bytes are noise (the generic rule re-matching an
  // AWS key must not double-report).
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
