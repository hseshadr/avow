import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalBytes, contentHash, type JsonValue } from "./canonical.js";
import { CanonicalizationFailed } from "./errors.js";

interface CanonicalVector {
  name: string;
  payload: JsonValue;
  canonical_hex: string;
  content_hash: string;
}

const vectors: CanonicalVector[] = JSON.parse(
  readFileSync(
    new URL("../../testdata/vectors/canonical.json", import.meta.url),
    "utf8",
  ),
);

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

describe("RFC-8785 byte identity with the Python rfc8785 kernel", () => {
  it("has the full stress set (floats, unicode, nesting, primitives)", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(8);
  });

  for (const v of vectors) {
    it(`vector ${v.name}: canonical bytes are byte-identical`, () => {
      expect(toHex(canonicalBytes(v.payload))).toBe(v.canonical_hex);
    });

    it(`vector ${v.name}: content hash is identical`, async () => {
      expect(await contentHash(v.payload)).toBe(v.content_hash);
    });
  }
});

describe("canonicalBytes fail-closed", () => {
  it("throws a coded CanonicalizationFailed on a non-JSON value", () => {
    // `undefined` is not a JSON value; canonicalize returns undefined for it.
    const bad = undefined as unknown as JsonValue;
    expect(() => canonicalBytes(bad)).toThrow(CanonicalizationFailed);
    try {
      canonicalBytes(bad);
    } catch (err) {
      expect((err as CanonicalizationFailed).code).toBe(
        "avow.canonicalization_failed",
      );
    }
  });
});
