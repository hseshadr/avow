import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { JsonValue } from "./canonical.js";
import {
  type AvowError,
  PayloadHashMismatch,
  SignatureBytesInvalid,
  SignatureInvalid,
  SignerMismatch,
} from "./errors.js";
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
      ).rejects.toThrow(PayloadHashMismatch);
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

  it("verifies when the pinned key differs only in hex case", async () => {
    // Mirrors Python tests/test_receipt.py: hex identity is case-insensitive,
    // not spelling-bound, so an UPPERCASE pinned key and the lowercase embedded
    // key are the SAME signer and must verify — not read as a SignerMismatch.
    const seed = generateSeedHex();
    const subject: JsonValue = { kind: "score", score: 0.5, tags: ["a"] };
    const receipt = await signPayload(subject, seed);
    await expect(
      verifySignature(receipt, receipt.public_key.toUpperCase()),
    ).resolves.toBeUndefined();
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

// Mirrors Python tests/test_verify.py. The `code` strings are a cross-language
// contract (see ts/README.md), so the provenance/tamper split must be identical
// on both sides: an untrusted signer is `avow.signer_mismatch` in either language.
describe("a wrong signer is coded apart from wrong signature bytes", () => {
  it("codes a pinned-key mismatch as a provenance failure", async () => {
    const receipt = await signPayload(
      { kind: "score", score: 0.5 } satisfies JsonValue,
      generateSeedHex(),
    );
    const untrusted = await publicKeyHex(generateSeedHex());
    await expect(verifySignature(receipt, untrusted)).rejects.toMatchObject({
      code: "avow.signer_mismatch",
    });
    await expect(verifySignature(receipt, untrusted)).rejects.toThrow(
      SignerMismatch,
    );
  });

  it("codes corrupted signature bytes as a tamper failure", async () => {
    const seed = generateSeedHex();
    const receipt = await signPayload(
      { kind: "score", score: 0.25 } satisfies JsonValue,
      seed,
    );
    const corrupted = { ...receipt, signature: "00".repeat(64) };
    // Keeps the published `avow.signature_invalid` — the code this case has
    // always carried; only the provenance case above gets a new one.
    await expect(
      verifySignature(corrupted, receipt.public_key),
    ).rejects.toMatchObject({ code: "avow.signature_invalid" });
    await expect(
      verifySignature(corrupted, receipt.public_key),
    ).rejects.toThrow(SignatureBytesInvalid);
  });

  it("keeps both causes catchable as the published SignatureInvalid base", () => {
    // The split is additive: `instanceof SignatureInvalid` still catches both,
    // so code written against the published 0.1.0 base keeps working.
    expect(new SignerMismatch("x")).toBeInstanceOf(SignatureInvalid);
    expect(new SignatureBytesInvalid("x")).toBeInstanceOf(SignatureInvalid);
    expect(new SignerMismatch("x").code).not.toBe(
      new SignatureBytesInvalid("x").code,
    );
  });
});

// Mirrors Python tests/test_verify.py. A signature binds content to a signer; it
// cannot bind it to an OCCASION. This package ships the envelope ONLY — there is no
// ledger in the browser build — so a browser caller who needs replay defence must
// hold that state itself. Saying so is the whole point of these two tests.
describe("freshness is outside what a signature can prove", () => {
  it("re-verifies a replayed receipt forever, because it holds no memory", async () => {
    const seed = generateSeedHex();
    const receipt = await signPayload(
      { kind: "score", score: 0.5 } satisfies JsonValue,
      seed,
    );
    // Captured on the wire by anyone who saw it, then presented again, unchanged.
    const replayed = JSON.parse(JSON.stringify(receipt));
    expect(JSON.stringify(replayed)).toBe(JSON.stringify(receipt));
    for (let i = 0; i < 50; i += 1) {
      await expect(
        verifySignature(replayed, receipt.public_key),
      ).resolves.toBeUndefined();
    }
  });

  it("never names or codes a tamper failure as 'replay'", async () => {
    const seed = generateSeedHex();
    const receipt = await signPayload(
      { kind: "score", score: 0.5 } satisfies JsonValue,
      seed,
    );
    // A payload edited behind its untouched hash field: TAMPER, not replay.
    const tampered = { ...receipt, payload: { kind: "score", score: 0.99 } };
    let caught: AvowError | undefined;
    try {
      await verifySignature(tampered as typeof receipt, receipt.public_key);
    } catch (error) {
      caught = error as AvowError;
    }
    // The name is a claim, held to the same bar as a sentence in the README: this
    // envelope detects replay nowhere, so nothing in it may be called "replay".
    expect(caught).toBeInstanceOf(PayloadHashMismatch);
    expect(caught?.constructor.name.toLowerCase()).not.toContain("replay");
    expect(caught?.code).not.toContain("replay");
    expect(caught?.code).toBe("avow.payload_hash_mismatch");
  });
});
