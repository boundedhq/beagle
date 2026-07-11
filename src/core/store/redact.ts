// redact-on-capture (design §4/R11): drop the raw secret value at capture
// time, keeping a stable typed placeholder. The single biggest store-liability
// reducer; off by default in v1 (raw fidelity serves the parity story).
import { createHash } from "node:crypto";
import type { Finding } from "../scanner/engine";

export function redactionPlaceholder(secretType: string, secretValue: string): string {
  const shorthash = createHash("sha256").update(secretValue).digest("hex").slice(0, 6);
  return `[REDACTED:${secretType}:${shorthash}]`;
}

// Replace each finding's byte span with a placeholder. Findings carry offsets
// into the decoded text; we splice on the string then re-encode.
export function redactBody(bytes: Uint8Array, findings: Finding[]): Uint8Array {
  if (findings.length === 0) return bytes;
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  // Apply from the end so earlier offsets stay valid as we splice.
  const ordered = [...findings].sort((a, b) => b.start - a.start);
  let out = text;
  for (const f of ordered) {
    const value = text.slice(f.start, f.end);
    out = out.slice(0, f.start) + redactionPlaceholder(f.secretType, value) + out.slice(f.end);
  }
  return new TextEncoder().encode(out);
}
