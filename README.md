# Avow

## TL;DR

Avow creates signed, tamper-evident records. Give it any JSON evidence; it
returns a receipt that another machine can verify offline.

This repository is an unpublished extraction candidate. Its version is
`0.5.0.dev0`; no registry release is implied.

## Quickstart

```bash
uv sync
uv run python - <<'PY'
from pydantic import BaseModel, ConfigDict
from avow import generate_signing_key, public_key_hex, sign_payload, verify_signature
class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    artifact: str
key = generate_signing_key()
receipt = sign_payload(Evidence(artifact="sha256:abc"), key)
verify_signature(receipt, expected_public_key=public_key_hex(key))
print(receipt.payload_hash)
PY
```

## Architecture

The Python package under `src/avow` owns canonical JSON, content hashes,
Ed25519 keys and signatures, generic receipts, and an append-only receipt
ledger. The TypeScript sources under `ts/src` preserve the portable canonical
JSON and receipt core. Scoring and action-policy implementations are outside
this repository.

## What this proves

Successful verification proves that the payload is unchanged and was signed by
the caller-pinned key.

## What this does not prove

A valid receipt does not prove correctness, freshness, wall-clock time, or the
honesty of its signer.
