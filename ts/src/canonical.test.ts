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

function jsonShape(value: JsonValue): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

describe("RFC-8785 byte identity with the Python rfc8785 kernel", () => {
  it("has the full stress set (floats, unicode, nesting, primitives)", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(8);
  });

  it("covers every supported top-level JSON shape", () => {
    const shapes = new Set(vectors.map((vector) => jsonShape(vector.payload)));
    expect([...shapes].sort()).toEqual([
      "array",
      "boolean",
      "null",
      "number",
      "object",
      "string",
    ]);
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

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "rejects non-finite number %s",
    (value) => {
      expect(() => canonicalBytes(value)).toThrow(CanonicalizationFailed);
    },
  );

  it("rejects a nested non-finite number", () => {
    expect(() => canonicalBytes({ nested: [1, Number.NaN] })).toThrow(
      CanonicalizationFailed,
    );
  });

  it("rejects circular JSON instead of recursing forever", () => {
    const circular: { self?: JsonValue } = {};
    circular.self = circular;
    expect(() => canonicalBytes(circular)).toThrow(CanonicalizationFailed);
  });

  it("rejects non-JSON object instances", () => {
    const date = new Date("2026-08-15T00:00:00Z") as unknown as JsonValue;
    expect(() => canonicalBytes(date)).toThrow(CanonicalizationFailed);
  });

  it("accepts a null-prototype JSON object", () => {
    const payload = Object.create(null) as Record<string, JsonValue>;
    payload.answer = 42;
    expect(toHex(canonicalBytes(payload))).toBe("7b22616e73776572223a34327d");
  });

  it("wraps property-read failures as a coded canonicalization error", () => {
    const payload = Object.defineProperty({}, "broken", {
      enumerable: true,
      get() {
        throw new Error("caller data must not escape");
      },
    }) as JsonValue;
    expect(() => canonicalBytes(payload)).toThrow(CanonicalizationFailed);
  });
});
