from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from assay.errors import ReplayMismatch, SignatureInvalid
from assay.receipt import (
    ReceiptPayload,
    ScoreReceipt,
    payload_digest,
    sign_payload,
    verify_signature,
)

_SEED = bytes(range(32))
_EXPECTED = bytes(SigningKey(_SEED).verify_key).hex()


def _payload() -> ReceiptPayload:
    return ReceiptPayload(
        assay_version="0.0.1",
        metric="binary",
        metric_version="1",
        inputs_hash="sha256:abc",
        score=0.8,
        interval_low=0.7,
        interval_high=0.9,
    )


def test_should_verify_a_freshly_signed_receipt() -> None:
    # Given a payload signed with a deterministic key
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    # When verified against the pinned expected signer
    # Then verification passes (no exception) and fields are populated
    verify_signature(receipt, expected_public_key=_EXPECTED)
    assert len(receipt.signature) == 128  # 64 bytes hex
    assert len(receipt.public_key) == 64  # 32 bytes hex


def test_should_be_byte_identical_when_signed_twice() -> None:
    # Given the same payload and key signed twice (Ed25519 is deterministic)
    first = sign_payload(_payload(), SigningKey(_SEED))
    second = sign_payload(_payload(), SigningKey(_SEED))
    # Then the receipts are identical, hash and signature included
    assert first == second


def test_should_raise_replay_mismatch_when_hash_is_tampered() -> None:
    # Given a receipt with a corrupted payload_hash
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    tampered = receipt.model_copy(update={"payload_hash": "sha256:deadbeef"})
    # When verified
    # Then the hash check fails first
    with pytest.raises(ReplayMismatch):
        verify_signature(tampered, expected_public_key=_EXPECTED)


def test_should_raise_signature_invalid_when_payload_is_tampered() -> None:
    # Given a receipt whose payload was swapped but hash re-derived to match
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    swapped = receipt.payload.model_copy(update={"score": 0.999})
    tampered = receipt.model_copy(
        update={"payload": swapped, "payload_hash": payload_digest(swapped)}
    )
    # When verified — hash matches the new payload, but the signature does not
    with pytest.raises(SignatureInvalid):
        verify_signature(tampered, expected_public_key=_EXPECTED)


def test_should_fail_closed_on_malformed_signature_hex() -> None:
    # Given a receipt whose signature is not valid hex
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    bad = receipt.model_copy(update={"signature": "zz"})
    # When verified against the correct pinned signer
    # Then it fails closed with a coded SignatureInvalid — never a raw ValueError
    with pytest.raises(SignatureInvalid):
        verify_signature(bad, expected_public_key=_EXPECTED)


def test_should_expose_score_receipt_as_public_symbol() -> None:
    # Given the signed receipt type
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    # Then it is a ScoreReceipt carrying the signed payload as its subject
    assert isinstance(receipt, ScoreReceipt)
    assert receipt.payload.score == 0.8
