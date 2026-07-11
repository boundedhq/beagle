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

// Scrub known secret values by literal match wherever they appear — used on the
// response body so an echoed key doesn't survive request-side redaction.
export function redactValues(
  bytes: Uint8Array | null,
  values: Array<{ value: string; type: string }>,
): Uint8Array | null {
  if (!bytes || values.length === 0) return bytes;
  let text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  let changed = false;
  for (const { value, type } of values) {
    if (value.length >= 8 && text.includes(value)) {
      text = text.split(value).join(redactionPlaceholder(type, value));
      changed = true;
    }
  }
  return changed ? new TextEncoder().encode(text) : bytes;
}
