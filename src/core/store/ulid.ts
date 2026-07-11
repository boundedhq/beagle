// Minimal ULID: 10 chars Crockford-base32 timestamp + 16 chars randomness.
// Time-sortable exchange ids (design §4), stdlib-only.
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function ulid(now: number = Date.now()): string {
  let ts = "";
  let t = now;
  for (let i = 0; i < 10; i++) {
    ts = B32[t % 32] + ts;
    t = Math.floor(t / 32);
  }
  const rand = new Uint8Array(16);
  crypto.getRandomValues(rand);
  let rs = "";
  for (let i = 0; i < 16; i++) rs += B32[rand[i]! % 32];
  return ts + rs;
}
