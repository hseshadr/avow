# Avow for TypeScript

## TL;DR

Avow creates signed, tamper-evident records. Give it any JSON evidence; it
returns a receipt that another machine can verify offline.

This is the `0.5.0` release of `@edgeproc/avow`, the first built from this repository.

## Usage

```ts
import {
  generateSeedHex,
  publicKeyHex,
  signPayload,
  verifySignature,
} from "@edgeproc/avow";

const signingSeed = generateSeedHex();
const pinnedPublicKey = await publicKeyHex(signingSeed);
const receipt = await signPayload({ artifact: "sha256:abc" }, signingSeed);
await verifySignature(receipt, pinnedPublicKey);
```

The example derives the public key before the receipt exists. In a real verifier,
obtain `pinnedPublicKey` independently through a trusted configuration or distribution
channel—never from `receipt.public_key`. Every emitted receipt has schema
`avow.receipt/v1`.

Verification proves that the payload is unchanged and was signed by the caller-pinned
key. It does not prove correctness, freshness, wall-clock time, or the honesty of the
signer.

Not a replay defence: a valid receipt verifies identically every time it is presented.
Callers needing replay protection sign their own nonce, audience, and expiry claims
into the payload and check them after `verifySignature`; the repository's
`docs/OPERATIONS.md` ("Replay protection is caller-owned") has the recipe.

The signing seed is unencrypted hex held by the caller. This package never reads key
files, so seed storage is the integrating application's responsibility; there is no
KMS/HSM seam. The Python package's file-mode check (`avow.key_permissions_insecure`,
raised by `load_signing_key` for a group- or other-accessible key file) has no
TypeScript counterpart because no TypeScript API loads a key from disk.
