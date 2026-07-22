import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { compileRules, scan } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";

// Detection-precision regression gate (R5): every curated coding-agent
// negative must avoid the loud (structured) tier. These hand-written fixtures
// pin known cases; they are not a sample from which to estimate a population
// false-positive rate.
const rules = compileRules(
  loadRuleFile(readFileSync("rules/beagle-rules.json", "utf8")),
  new Uint8Array(32).fill(3),
);

// Negatives: normal agent traffic that must NOT produce a structured alert.
const NEGATIVES: string[] = [
  'import { readFile } from "node:fs";',
  'const apiUrl = "https://api.example.com/v1/users";',
  'export const MAX_RETRIES = 5; // retry budget',
  'AWS_REGION=us-east-1',
  'the access key format looks like AKIA followed by 16 chars',
  'set your OPENAI_API_KEY environment variable before running',
  'password field must be at least 8 characters',
  'git commit -m "fix: handle token refresh in auth middleware"',
  'a UUID like 550e8400-e29b-41d4-a716-446655440000 identifies the row',
  'const hash = "d41d8cd98f00b204e9800998ecf8427e"; // md5 of empty string',
  'example: export GITHUB_TOKEN=ghp_your_token_here',
  'the sha is 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  'run `stripe listen --forward-to localhost:4242/webhook`',
  'connection pooling keeps up to 20 sockets open',
  'base64 encode the payload before sending',
  'aws_secret_access_key is stored in the vault, not here',
  'TODO: rotate the database password next sprint',
  'a bearer token goes in the Authorization header',
  'the private key lives in ~/.ssh/id_ed25519',
  'card numbers are validated with the Luhn algorithm',
  // Both fire under a looser hyphen window, so both hold this corpus to the
  // formulation that shipped. A negative no candidate ever trips would only
  // pad the denominator and make this gate easier to pass.
  'aws-cdk-lib-construct-x 3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5e',
  'aws-object-key: 3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5e',
];

// Positives: bodies that SHOULD trip the structured tier.
const POSITIVES: string[] = [
  'AKIAZQ3DRSTUVWXY2345',
  'export GH_TOKEN=ghp_A7hK9mP2qR5tW8xZ1cV4bN6jL3gF0dSe2aYb',
  'anthropic_key = "sk-ant-api03-Zx9Yw8Vu7Tt6Ss5Rr4Qq3Pp2Oo1Nn0Mm"',
  'DATABASE_URL=postgres://admin:hunter2secret@db.internal:5432/prod',
  '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----',
  'stripe live sk_live_A7hK9mP2qR5tW8xZ1cV4bN6j',
  'card 4111111111111111 on file',
  '      aws-secret-access-key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYZZZZZKEY42',
];

function structuredHits(text: string): number {
  return scan(new TextEncoder().encode(text), {}, rules).findings.filter((f) => f.tier === "structured").length;
}

describe("detection precision regression gate", () => {
  test("every curated negative stays free of structured alerts", () => {
    const fps = NEGATIVES.filter((s) => structuredHits(s) > 0);
    if (fps.length > 0) console.error("false positives:", fps);
    expect(fps).toEqual([]);
  });

  test("recall: every positive trips the structured tier", () => {
    const misses = POSITIVES.filter((s) => structuredHits(s) === 0);
    if (misses.length > 0) console.error("missed:", misses);
    expect(misses).toEqual([]);
  });

  test("public docs do not present curated fixtures as a false-positive rate", () => {
    const readme = readFileSync("README.md", "utf8");
    const publicDocs = readme + "\n" + readFileSync("CONTRIBUTING.md", "utf8");
    const percentageClaim =
      /(?:false[- ]positives?[\s\S]{0,80}%|%[\s\S]{0,80}false\s*positives?)/i;
    expect(percentageClaim.test(publicDocs)).toBe(false);
    expect(readme).toContain("not a measured false-positive rate");
  });
});
