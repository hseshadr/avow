from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from assay.errors import SignatureInvalid
from assay.receipt import ReceiptPayload, ScoreReceipt, sign_payload
from assay.verify import verify_receipt

_SEED = bytes(range(32))


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
    # When verified offline
    # Then no exception is raised
    verify_receipt(receipt)


def test_should_fail_offline_for_a_forged_signature() -> None:
    # Given a receipt whose signature bytes were flipped
    receipt = _receipt()
    forged = receipt.model_copy(update={"signature": "00" * 64})
    # When verified offline
    # Then it fails closed
    with pytest.raises(SignatureInvalid):
        verify_receipt(forged)
