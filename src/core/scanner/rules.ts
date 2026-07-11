// Rule loading (design §6.11): rules are data, not code — vendored, pinned
// by content hash, verified at load.
import { createHash } from "node:crypto";

export interface RuleSpec {
  id: string;
  description: string;
  regex: string;
  /** Regex flags; defaults to "g". Case-insensitivity is opt-in — structured
   *  detectors are case-exact by design (an AKIA prefix is uppercase). */
  flags?: string;
  keywords: string[];
  secretGroup: number;
  severity: "high" | "medium" | "low";
  tier: "structured" | "possible";
  entropy?: number;
  validators?: string[];
}

export function loadRuleFile(json: string, sha256Pin?: string): RuleSpec[] {
  if (sha256Pin) {
    const actual = createHash("sha256").update(json).digest("hex");
    if (actual !== sha256Pin.trim()) {
      throw new Error(
        `rule file failed integrity check: hash ${actual} does not match pin — refusing to load tampered rules`,
      );
    }
  }
  const parsed = JSON.parse(json) as { version: number; rules: RuleSpec[] };
  if (!Array.isArray(parsed.rules)) throw new Error("rule file has no rules[]");
  for (const r of parsed.rules) {
    if (!r.id || !r.regex || !Array.isArray(r.keywords)) {
      throw new Error(`malformed rule: ${JSON.stringify(r).slice(0, 120)}`);
    }
    try {
      new RegExp(r.regex, r.flags ?? "g");
    } catch (e) {
      throw new Error(`rule '${r.id}' has an invalid regex: ${(e as Error).message}`);
    }
  }
  return parsed.rules;
}
