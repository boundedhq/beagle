// redact-on-capture (design §4/R11): drop the raw secret value at capture
// time, keeping a stable typed placeholder. The single biggest store-liability
// reducer; off by default in v1 (raw fidelity serves the parity story).
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
  for (const f of ordered) {
    const value = text.slice(f.start, f.end);
    values.push({ value, type: f.secretType });
    out = out.slice(0, f.start) + redactionPlaceholder(f.secretType, value) + out.slice(f.end);
  }
  return { bytes: new TextEncoder().encode(out), values };
}

// Scrub known secret values by literal match wherever they appear — used on
// derived text (summary, search text) built from parsed messages rather than
// the stored bytes, so a body-side redaction can't be undone by a re-derive.
// The 8-char floor avoids mangling unrelated text on common substrings; a
// shorter value is still span-redacted from the body it was found in but
// would survive here — no rule matches anything that short today, so revisit
// the floor before adding one that does.
export function redactValuesInText(
  text: string,
  values: Array<{ value: string; type: string }>,
): string {
  for (const { value, type } of values) {
    if (value.length >= 8 && text.includes(value)) {
      text = text.split(value).join(redactionPlaceholder(type, value));
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
  if (o.requestFindings.length === 0 && respFindings.length === 0) {
    return { redacted: false, heldOut: false, requestBody: o.requestBytes, responseBody: o.responseBody, values: [] };
  }
  const req = redactBody(o.requestBytes, o.requestFindings);
  let responseBody = o.responseBody;
  let values = req.values;
  if (respFindings.length > 0 && responseBody) {
    const resp = redactBody(responseBody, respFindings); // spans first: offsets index the original bytes
    responseBody = resp.bytes;
    values = [...req.values, ...resp.values];
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
  return { redacted: true, heldOut: false, requestBody, responseBody, values };
}
