# Avow for TypeScript

## TL;DR

Avow creates signed, tamper-evident records. Give it any JSON evidence; it
returns a receipt that another machine can verify offline.

This source package is an unpublished extraction candidate. No registry release
is implied.

## Usage

```ts
import { generateSeedHex, signPayload, verifySignature } from "@edgeproc/avow";

const key = generateSeedHex();
const receipt = await signPayload({ artifact: "sha256:abc" }, key);
await verifySignature(receipt, receipt.public_key);
```

Verification proves that the payload is unchanged and was signed by the
caller-pinned key. It does not prove correctness, freshness, wall-clock time, or
the honesty of the signer.
