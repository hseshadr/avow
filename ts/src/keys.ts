/**
 * Ed25519 key helpers — the browser twin of Python `avow.keys`.
 *
 * The private key is a 32-byte seed, carried as lowercase hex. The public verify
 * key is derived from the seed and travels inside each receipt. Ed25519 seed and
 * public-key conventions are identical across `@noble/ed25519` and Python's
 * pynacl, so a seed generated here derives the same public key CPython would.
 */

import { etc, getPublicKeyAsync } from "@noble/ed25519";

const SEED_BYTES = 32;

/** Generate a fresh random 32-byte Ed25519 seed as lowercase hex. */
export function generateSeedHex(): string {
  return etc.bytesToHex(etc.randomBytes(SEED_BYTES));
}

/** Derive the hex-encoded Ed25519 public verify key for a hex seed. */
export async function publicKeyHex(seedHex: string): Promise<string> {
  const publicKey = await getPublicKeyAsync(etc.hexToBytes(seedHex));
  return etc.bytesToHex(publicKey);
}
