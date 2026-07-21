import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { JsonValue } from "./canonical.js";
import { ReplayMismatch, SignatureInvalid } from "./errors.js";
import { generateSeedHex, publicKeyHex } from "./keys.js";
import { signPayload, verifySignature } from "./receipt.js";

interface ReceiptVector {
  payload: JsonValue;
  payload_hash: string;
  signature: string;
}

interface ReceiptVectors {
  seed_hex: string;
  public_key: string;
  receipts: ReceiptVector[];
}

const data: ReceiptVectors = JSON.parse(
  readFileSync(
    new URL("../../testdata/vectors/receipts.json", import.meta.url),
    "utf8",
  ),
);

const WRONG_KEY =
  "0000000000000000000000000000000000000000000000000000000000000000";

describe("Python-signed receipts verify in TypeScript", () => {
  for (const [i, r] of data.receipts.entries()) {
    it(`receipt ${i} verifies under the pinned key`, async () => {
      await expect(
        verifySignature(
          {
            payload: r.payload,
            payload_hash: r.payload_hash,
            public_key: data.public_key,
            signature: r.signature,
          },
          data.public_key,
        ),
      ).resolves.toBeUndefined();
    });

    it(`receipt ${i} is REJECTED under a wrong pinned key`, async () => {
      await expect(
        verifySignature(
          {
            payload: r.payload,
            payload_hash: r.payload_hash,
            public_key: data.public_key,
            signature: r.signature,
          },
          WRONG_KEY,
        ),
      ).rejects.toThrow(SignatureInvalid);
    });

    it(`receipt ${i} is REJECTED when the payload is tampered`, async () => {
      const tampered = {
        ...(r.payload as Record<string, JsonValue>),
        kind: "forged",
      };
      await expect(
        verifySignature(
          {
            payload: tampered,
            payload_hash: r.payload_hash,
            public_key: data.public_key,
            signature: r.signature,
          },
          data.public_key,
        ),
      ).rejects.toThrow(ReplayMismatch);
    });
  }
});

describe("TypeScript signing reproduces Python signatures byte-for-byte", () => {
  it("re-signs each vector with the fixed seed to the identical signature", async () => {
    for (const r of data.receipts) {
      const receipt = await signPayload(r.payload, data.seed_hex);
      expect(receipt.signature).toBe(r.signature);
      expect(receipt.payload_hash).toBe(r.payload_hash);
      expect(receipt.public_key).toBe(data.public_key);
    }
  });

  it("derives the vector public key from the fixed seed", async () => {
    expect(await publicKeyHex(data.seed_hex)).toBe(data.public_key);
  });
});

describe("round-trip with a freshly generated key", () => {
  it("signs and verifies a subject, and a swapped signer is rejected", async () => {
    const seed = generateSeedHex();
    const subject: JsonValue = { kind: "score", score: 0.5, tags: ["a", "b"] };
    const receipt = await signPayload(subject, seed);
    await expect(
      verifySignature(receipt, receipt.public_key),
    ).resolves.toBeUndefined();

    const other = await publicKeyHex(generateSeedHex());
    await expect(verifySignature(receipt, other)).rejects.toThrow(
      SignatureInvalid,
    );
  });

  it("rejects a valid-hash receipt whose signature is corrupted", async () => {
    const seed = generateSeedHex();
    const subject: JsonValue = { kind: "score", score: 0.25, tags: [] };
    const receipt = await signPayload(subject, seed);
    // Replace the whole signature with a fixed all-zero 64-byte signature —
    // never coincidentally equal to a real one — matching the Python side
    // (tests/test_verify.py: `"signature": "00" * 64`). Flipping only the
    // final byte is unsound: Ed25519 signatures satisfy S < L ≈ 2^252, so
    // that byte is already 0x00 roughly 1 in 16 times, making the
    // "corruption" a no-op and the test flaky.
    const corrupted = {
      ...receipt,
      signature: "00".repeat(64),
    };
    await expect(
      verifySignature(corrupted, receipt.public_key),
    ).rejects.toThrow(SignatureInvalid);
  });

  it("fails closed (coded) when the signature hex is malformed", async () => {
    const seed = generateSeedHex();
    const subject: JsonValue = { kind: "score", score: 0.75, tags: [] };
    const receipt = await signPayload(subject, seed);
    // Not valid signature bytes — the verify call throws; we must catch and
    // re-raise a coded SignatureInvalid, never leak the raw error.
    const malformed = { ...receipt, signature: "zz" };
    await expect(
      verifySignature(malformed, receipt.public_key),
    ).rejects.toMatchObject({ code: "avow.signature_invalid" });
  });
});
