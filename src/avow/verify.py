"""Offline verifier. Given a receipt and the signer's pinned public key (both held
without any network or original inputs), confirm the receipt's content-hash matches
its payload, its embedded key is the expected signer, and its Ed25519 signature is
valid under that pinned key.

Generic over the subject: the score face passes a scoring receipt and the effect
face passes an effect receipt. One public verifier serves both, because the envelope
signs a subject's canonical JSON without inspecting its fields."""

from __future__ import annotations

from pydantic import BaseModel

from avow.envelope import SignedReceipt, verify_signature


def verify_receipt[SubjectT: BaseModel](
    receipt: SignedReceipt[SubjectT], *, expected_public_key: str
) -> None:
    """Verify any signed receipt offline against a pinned signer; raises a typed error
    on any failure (bad hash, wrong signer, or invalid signature).

    Proves **who signed it** and **that it is unmodified**. Does NOT prove freshness or
    that the receipt has not been presented before — a replayed receipt is byte-identical
    to the original and verifies. Use ``avow.ledger`` for replay defence."""
    verify_signature(receipt, expected_public_key=expected_public_key)
