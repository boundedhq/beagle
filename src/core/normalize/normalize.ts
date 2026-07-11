// Capture normalizer (design §4/§5): auth-header scrub is unconditional —
// the provider credential rides every exchange and must never reach disk.
// Content decoding happens only on the capture copy, never the live path.
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import { createHash } from "node:crypto";
import type { HeaderList } from "../proxy/http1";

export function scrubAuthHeaders(
  headers: HeaderList,
  authLocation: string | undefined,
  provider: string,
): HeaderList {
  const authNames = new Set(["authorization", "proxy-authorization", "cookie"]);
  if (authLocation) authNames.add(authLocation.toLowerCase());
  return headers.map(([name, value]) => {
    if (!authNames.has(name.toLowerCase())) return [name, value];
    const hash = createHash("sha256").update(value).digest("hex").slice(0, 8);
    return [name, `[AUTH:${provider}:${hash}]`];
  });
}

export function decodeBody(bytes: Uint8Array, contentEncoding: string | undefined): Uint8Array {
  const enc = contentEncoding?.trim().toLowerCase();
  try {
    if (enc === "gzip") return gunzipSync(bytes);
    if (enc === "br") return brotliDecompressSync(bytes);
    if (enc === "deflate") return inflateSync(bytes);
  } catch {
    // corrupt or truncated encoding: keep the raw bytes rather than lose capture
  }
  return bytes;
}
