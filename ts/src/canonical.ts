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

function invalidJson(cause?: unknown): CanonicalizationFailed {
  return new CanonicalizationFailed(
    "payload is not a canonicalizable JSON value",
    cause === undefined ? undefined : { cause },
  );
}

function hasValidUnicodeScalars(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isSupportedNumber(value: number): boolean {
  if (!Number.isFinite(value)) return false;
  return !Number.isInteger(value) || Number.isSafeInteger(value);
}

function snapshotArray(
  value: JsonValue[],
  ancestors: Set<object>,
): JsonValue[] {
  if (Reflect.ownKeys(value).length !== value.length + 1) throw invalidJson();
  return Array.from({ length: value.length }, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !("value" in descriptor))
      throw invalidJson();
    return snapshotValue(descriptor.value as JsonValue, ancestors);
  });
}

function snapshotObject(
  value: { [key: string]: JsonValue },
  ancestors: Set<object>,
): { [key: string]: JsonValue } {
  const entries: [string, JsonValue][] = [];
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") throw invalidJson();
    if (!hasValidUnicodeScalars(key)) throw invalidJson();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !("value" in descriptor))
      throw invalidJson();
    entries.push([
      key,
      snapshotValue(descriptor.value as JsonValue, ancestors),
    ]);
  }
  return Object.fromEntries(entries);
}

function snapshotValue(value: JsonValue, ancestors: Set<object>): JsonValue {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (!hasValidUnicodeScalars(value)) throw invalidJson();
    return value;
  }
  if (typeof value === "number") {
    if (!isSupportedNumber(value)) throw invalidJson();
    return value;
  }
  if (typeof value !== "object") throw invalidJson();
  if (ancestors.has(value)) throw invalidJson();
  ancestors.add(value);
  try {
    if (Array.isArray(value)) return snapshotArray(value, ancestors);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
      throw invalidJson();
    return snapshotObject(value, ancestors);
  } finally {
    ancestors.delete(value);
  }
}

/** Validate and recursively detach one value in the closed JSON data model. */
export function snapshotJsonValue(payload: JsonValue): JsonValue {
  try {
    return snapshotValue(payload, new Set());
  } catch (cause) {
    if (cause instanceof CanonicalizationFailed) throw cause;
    throw invalidJson(cause);
  }
}

/** Return the RFC 8785 JCS canonical bytes for `payload`. */
export function canonicalBytes(payload: JsonValue): Uint8Array {
  let canonical: string | undefined;
  try {
    canonical = canonicalize(snapshotJsonValue(payload));
  } catch (cause) {
    if (cause instanceof CanonicalizationFailed) throw cause;
    throw invalidJson(cause);
  }
  if (canonical === undefined) throw invalidJson();
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
