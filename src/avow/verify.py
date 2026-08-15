"""Offline verifier. Given a receipt and the signer's pinned public key (both held
without any network or original inputs), confirm the receipt's content-hash matches
its payload, its embedded key is the expected signer, and its Ed25519 signature is
valid under that pinned key.

The verifier is generic over the subject because the envelope signs canonical JSON
without inspecting its fields."""

from __future__ import annotations

from avow.envelope import SignedReceipt, Subject, verify_signature


def verify_receipt[SubjectT: Subject](
    receipt: SignedReceipt[SubjectT], *, expected_public_key: str
) -> None:
    """Verify any signed receipt offline against a pinned signer; raises a typed error
    on any failure (bad hash, wrong signer, or invalid signature).

    Proves **who signed it** and **that it is unmodified**. Does NOT prove freshness or
    that the receipt has not been presented before — a replayed receipt is byte-identical
    to the original and verifies. A ledger detects encoded-line reinsertion, while
    semantic replay needs caller-owned nonce/request-ID state."""
    verify_signature(receipt, expected_public_key=expected_public_key)
