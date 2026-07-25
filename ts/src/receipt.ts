/**
 * The signed-receipt envelope — the browser twin of Python `avow.envelope`.
 *
 * The envelope signs the canonical JSON of a subject without inspecting its
 * fields. Because the signed content is a pure function of the subject (no
 * timestamps), identical subjects yield an identical payload-hash and — Ed25519
 * being deterministic — an identical signature. So a receipt signed by the
 * Python kernel verifies here, and a receipt signed here verifies in Python,
 * byte-for-byte. The golden-vector suite gates that guarantee.
 *
 * Verification recomputes the hash (catching tampered content) and checks the
 * detached signature under a *pinned* key (catching a forged or swapped key),
 * mirroring `avow.envelope.verify_signature` step-for-step and error-for-error.
 */

import { etc, signAsync, verifyAsync } from "@noble/ed25519";
import { canonicalBytes, contentHash, type JsonValue } from "./canonical.js";
import {
  ReplayMismatch,
  SignatureBytesInvalid,
  SignerMismatch,
} from "./errors.js";
import { publicKeyHex } from "./keys.js";

/** A signed subject: the subject plus its content-hash, public key and signature. */
export interface SignedReceipt<S extends JsonValue> {
  payload: S;
  payload_hash: string;
  public_key: string;
  signature: string;
}

/** Hash and Ed25519-sign a subject into a verifiable receipt, using a hex seed. */
export async function signPayload<S extends JsonValue>(
  payload: S,
  seedHex: string,
): Promise<SignedReceipt<S>> {
  const message = canonicalBytes(payload);
  const signature = await signAsync(message, etc.hexToBytes(seedHex));
  return {
    payload,
    payload_hash: await contentHash(payload),
    public_key: await publicKeyHex(seedHex),
    signature: etc.bytesToHex(signature),
  };
}

async function checkSignatureBytes(
  message: Uint8Array,
  signatureHex: string,
  publicKeyHexPinned: string,
): Promise<void> {
  let ok: boolean;
  try {
    ok = await verifyAsync(
      etc.hexToBytes(signatureHex),
      message,
      etc.hexToBytes(publicKeyHexPinned),
    );
  } catch (cause) {
    throw new SignatureBytesInvalid("signature does not match payload", {
      cause,
    });
  }
  if (!ok) {
    throw new SignatureBytesInvalid("signature does not match payload");
  }
}

/**
 * Verify a receipt against a *pinned* signer key. Fail-closed: throws a coded
 * `ReplayMismatch` (content hash disagrees), `SignerMismatch` (embedded key is
 * not the pinned signer), or `SignatureBytesInvalid` (the signature does not
 * verify). The latter two both extend the published `SignatureInvalid` base.
 *
 * The order mirrors Python exactly: recompute the hash first, then reject any
 * receipt whose embedded `public_key` is not the caller-pinned key — independent
 * of the signature, because that field lives outside the signed payload and a
 * re-signed forgery can swap it in — then verify the detached signature under
 * the pinned key.
 */
export async function verifySignature<S extends JsonValue>(
  receipt: SignedReceipt<S>,
  expectedPublicKey: string,
): Promise<void> {
  if ((await contentHash(receipt.payload)) !== receipt.payload_hash) {
    throw new ReplayMismatch("payload hash does not match payload content");
  }
  // Hex is case-insensitive, so pin by value, not by spelling (mirrors Python
  // avow.envelope): a lowercase embedded key and an uppercase pinned key are the
  // SAME signer and must not read as a mismatch.
  if (receipt.public_key.toLowerCase() !== expectedPublicKey.toLowerCase()) {
    // Provenance failure, coded apart from a bytes failure: signed by a key
    // the caller does not trust, so the signature is never even checked.
    throw new SignerMismatch("receipt public key is not the expected signer");
  }
  await checkSignatureBytes(
    canonicalBytes(receipt.payload),
    receipt.signature,
    expectedPublicKey,
  );
}
