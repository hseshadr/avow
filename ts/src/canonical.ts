/**
 * Deterministic serialization + content hashing — the browser twin of Python
 * `avow.canonical`.
 *
 * RFC 8785 (JCS) gives a byte-stable canonical form for any JSON value: object
 * keys sorted, numbers in shortest ECMAScript round-trip form. Two payloads that
 * are equal as JSON produce identical bytes — and therefore an identical
 * content-hash — which is what makes a receipt reproducible and tamper-evident.
 * The `canonicalize` package is the reference JCS implementation and matches
 * Python's `rfc8785` byte-for-byte (gated by the golden-vector conformance
 * suite), including the number-formatting hazards (`-0.0` -> `0`, `1e21` ->
 * `1e+21`, `1e-7` -> `1e-7`).
 */

import canonicalize from "canonicalize";
import { CanonicalizationFailed } from "./errors.js";

/**
 * Any JSON value. This is the one place a string-keyed record is a value, not a
 * typed model — it is the serialization I/O boundary.
 */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Return the RFC 8785 JCS canonical bytes for `payload`. */
export function canonicalBytes(payload: JsonValue): Uint8Array {
  const canonical = canonicalize(payload);
  if (canonical === undefined) {
    throw new CanonicalizationFailed(
      "payload is not a canonicalizable JSON value",
    );
  }
  return new TextEncoder().encode(canonical);
}

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/** Return `"sha256:<hex>"` over the canonical bytes of `payload`. */
export async function contentHash(payload: JsonValue): Promise<string> {
  const bytes = canonicalBytes(payload);
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return `sha256:${toHex(new Uint8Array(digest))}`;
}
