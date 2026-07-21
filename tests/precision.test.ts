import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { compileRules, scan } from "../src/core/scanner/engine";
import { loadRuleFile } from "../src/core/scanner/rules";

// Detection-precision ship gate (R5): FP rate < 5% on a curated corpus of
// realistic coding-agent traffic that should NOT trip the loud (structured)
// tier. Example keys in code are the main FP source, so the corpus is built
// from exactly those.
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
];

function structuredHits(text: string): number {
  return scan(new TextEncoder().encode(text), {}, rules).filter((f) => f.tier === "structured").length;
}

describe("detection precision (ship gate)", () => {
  test("false-positive rate on realistic negatives is < 5%", () => {
    const fps = NEGATIVES.filter((s) => structuredHits(s) > 0);
    const rate = fps.length / NEGATIVES.length;
    if (fps.length > 0) console.error("false positives:", fps);
    expect(rate).toBeLessThan(0.05);
  });

  test("recall: every positive trips the structured tier", () => {
    const misses = POSITIVES.filter((s) => structuredHits(s) === 0);
    if (misses.length > 0) console.error("missed:", misses);
    expect(misses).toEqual([]);
  });
});

// Flattening a serialized message list (flattenPromptText) drops the JSON
// structure BETWEEN messages, which is what lets the daemon's derived-text scan
// see a keyword and its value as adjacent — the detection gap it exists to
// close. The same drop MANUFACTURES adjacencies that were never on the wire:
// a message ending in a bare keyword ("…configure aws") followed by one
// starting with a hash reads exactly like a real assignment. These are the
// cases that made the loud tier unsafe for a flatten-only finding, which is why
// the daemon caps those at `possible`. This suite is the ceiling's regression
// gate: it asserts the rules' behavior on the joined text, so if a future rule
// or a lifted cap would turn one of these into an OS alert, it fails here.
const JOINED_NEGATIVES: Array<[string, string[]]> = [
  ["hash after a token question", ["can you refresh the auth token", "the sha is 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]],
  ["uuid after a token question", ["look at this session token", "550e8400-e29b-41d4-a716-446655440000"]],
  ["md5 after a password mention", ["the password hashing looks wrong", "d41d8cd98f00b204e9800998ecf8427e is what it produced"]],
  ["commit sha after a secret mention", ["where did we add the secret", "in commit a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"]],
  // The two that actually fire: aws-secret-access-key is the one LOUD rule with
  // a `keyword <separator> value` shape, so it is the whole reason for the cap.
  ["40-hex after an aws question", ["how do I configure aws", "0123456789abcdef0123456789abcdef01234567"]],
  ["40-char b64 after an aws question", ["remind me how to set up aws", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd"]],
];

describe("what flattening a message list manufactures", () => {
  // Neither assertion below is the behavioral gate — the daemon's cap is what
  // actually keeps these quiet, and that is asserted end-to-end in
  // tests/otlp-daemon.test.ts. These two pin the FACTS that make the cap
  // necessary, so that if either stops being true the cap gets re-examined
  // rather than silently outliving its reason.
  test("the raw serialized form raises nothing loud — the join is what escalates", () => {
    // Not "clean at every tier": an anchor-free shape rule (aws-secret-shape)
    // still fires on a 40-char blob wherever it sits, and the daemon's dedup
    // recognises that value as already-proven and adds nothing. What no raw
    // form here produces is a STRUCTURED hit — the keyword that would escalate
    // one is stranded behind the JSON structure. That escalation is exactly
    // what flattening hands over, and exactly what the cap takes back.
    const loudRaw = JOINED_NEGATIVES.filter(([, messages]) =>
      structuredHits(JSON.stringify(messages.map((content) => ({ role: "user", content })))) > 0,
    );
    expect(loudRaw.map(([name]) => name)).toEqual([]);
  });

  test("joining them DOES manufacture loud hits — why flatten-only findings are capped", () => {
    // If this list ever shrinks to empty, the rules themselves stopped
    // manufacturing loud hits across a message boundary and the cap could be
    // reconsidered. Today it is aws-secret-access-key: the one structured rule
    // shaped `keyword <separator> value`, which a "\n" join lets a bare "aws"
    // in one message reach across into the next message's 40-char run.
    const loud = JOINED_NEGATIVES.filter(
      ([, messages]) => structuredHits(messages.join("\n")) > 0,
    ).map(([name]) => name);
    expect(loud).toEqual([
      "40-hex after an aws question",
      "40-char b64 after an aws question",
    ]);
  });
});
