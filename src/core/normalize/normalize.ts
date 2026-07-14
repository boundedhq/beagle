// Capture normalizer (design §4/§5): auth-header scrub is unconditional —
// the provider credential rides every call and must never reach disk.
// Content decoding happens only on the capture copy, never the live path.
import * as zlib from "node:zlib";
import { createHash } from "node:crypto";
import type { HeaderList } from "../proxy/http1";

export function scrubAuthHeaders(
  headers: HeaderList,
  authLocation: string | undefined,
  provider: string,
): HeaderList {
  // Well-known credential headers are scrubbed unconditionally — defense in
  // depth against a misregistered authLocation.
  const authNames = new Set([
    "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key",
  ]);
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
    if (enc === "gzip") return zlib.gunzipSync(bytes);
    if (enc === "br") return zlib.brotliDecompressSync(bytes);
    if (enc === "deflate") return zlib.inflateSync(bytes);
    // zstd rides pi's ChatGPT/codex request bodies (and some responses); a
    // compressed body the scanner can't read hides secrets from R7's "was this
    // ever sent?". A namespace import (not a named one) keeps this a runtime
    // feature check: on a runtime whose node:zlib lacks zstd the property is
    // just undefined and we fall through to raw bytes — a named import of a
    // missing export would instead be a module-load SyntaxError.
    if (enc === "zstd" && typeof zlib.zstdDecompressSync === "function") return zlib.zstdDecompressSync(bytes);
  } catch {
    // corrupt or truncated encoding: keep the raw bytes rather than lose capture
  }
  return bytes;
}
