from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from assay.errors import SignatureInvalid
from assay.receipt import ReceiptPayload, ScoreReceipt, sign_payload
from assay.verify import verify_receipt

_SEED = bytes(range(32))
_EXPECTED = bytes(SigningKey(_SEED).verify_key).hex()


def _receipt() -> ScoreReceipt:
    payload = ReceiptPayload(
        assay_version="0.0.1",
        metric="binary",
        metric_version="1",
        inputs_hash="sha256:abc",
        score=0.8,
    )
    return sign_payload(payload, SigningKey(_SEED))


def test_should_pass_offline_for_an_untouched_receipt() -> None:
    # Given a valid receipt and no network
    receipt = _receipt()
    # When verified offline against the pinned expected signer
    # Then no exception is raised
    verify_receipt(receipt, expected_public_key=_EXPECTED)


def test_should_fail_offline_for_a_forged_signature() -> None:
    # Given a receipt whose signature bytes were flipped
    receipt = _receipt()
    forged = receipt.model_copy(update={"signature": "00" * 64})
    # When verified offline against the pinned expected signer
    # Then it fails closed
    with pytest.raises(SignatureInvalid):
        verify_receipt(forged, expected_public_key=_EXPECTED)


def test_should_reject_a_receipt_resigned_by_a_different_key() -> None:
    # Given a genuine receipt whose signer pubkey the verifier pins out-of-band
    receipt = _receipt()
    # When an attacker flips the signed score, re-signs with their OWN key,
    # and swaps in their own public key (probe-1 forgery)
    attacker = SigningKey(bytes(range(1, 33)))
    forged_payload = receipt.payload.model_copy(update={"score": 0.999})
    forgery = sign_payload(forged_payload, attacker)
    # Then verification rejects it: the embedded key is not the expected signer,
    # even though the forgery's own signature is internally valid
    assert forgery.public_key != _EXPECTED
    with pytest.raises(SignatureInvalid):
        verify_receipt(forgery, expected_public_key=_EXPECTED)
