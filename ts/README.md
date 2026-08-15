# Avow for TypeScript

## TL;DR

Avow creates signed, tamper-evident records. Give it any JSON evidence; it
returns a receipt that another machine can verify offline.

This source package is an unpublished extraction candidate. No registry release
is implied.

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
