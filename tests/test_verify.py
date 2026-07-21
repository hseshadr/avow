from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from assay.receipt import ReceiptPayload, ScoreReceipt, sign_payload
from avow.errors import SignatureBytesInvalid, SignatureInvalid, SignerMismatch
from avow.verify import verify_receipt
from writ import Allowlist, EffectReceipt, EffectRequest, KeyholderEffector, gate

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


def _effect_receipt(action: str) -> EffectReceipt:
    def _noop(_: EffectRequest) -> None:
        return None

    effector = KeyholderEffector(effect=_noop, signing_key=SigningKey(_SEED))
    request = EffectRequest(action=action, target="account-7", args_digest="sha256:abc")
    return gate(request, Allowlist(frozenset({"read"})), effector)


def test_should_pass_offline_for_an_untouched_receipt() -> None:
    # Given a valid receipt and no network
    receipt = _receipt()
    # When verified offline against the pinned expected signer
    # Then it returns nothing and raises nothing — the fail-closed contract is
    # "silence means valid", so asserting the None pins that contract explicitly.
    assert verify_receipt(receipt, expected_public_key=_EXPECTED) is None


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


def test_should_verify_both_faces_with_the_one_public_verifier() -> None:
    # Given a score receipt AND an effect (Writ) receipt — allow and deny
    score = _receipt()
    allow = _effect_receipt("read")
    deny = _effect_receipt("delete")
    # When the SAME public verify_receipt checks all three under the pinned signer
    # Then all three pass: one envelope, one verifier, both faces
    assert verify_receipt(score, expected_public_key=_EXPECTED) is None
    assert verify_receipt(allow, expected_public_key=_EXPECTED) is None
    assert verify_receipt(deny, expected_public_key=_EXPECTED) is None
    # ...and they really were the two different faces carrying two different subjects
    assert allow.payload.decision == "allow"
    assert deny.payload.decision == "deny"
    assert score.payload.metric == "binary"


def test_should_reject_an_effect_receipt_under_the_wrong_signer() -> None:
    # Given a genuine effect receipt
    receipt = _effect_receipt("read")
    # Then pinning a different signer rejects it — the effect face fails closed too
    with pytest.raises(SignatureInvalid):
        verify_receipt(receipt, expected_public_key="ab" * 32)


# Two security-distinct failures, two codes. "Signed by a key you do not trust" is a
# PROVENANCE failure; "these bytes do not check out" is a TAMPER failure. A caller may
# reasonably alert, log or retry differently for each, so neither may be reachable only
# by string-matching an English message.


def test_should_code_a_pinned_key_mismatch_as_a_signer_mismatch() -> None:
    # Given a receipt validly self-signed by an attacker's own key
    attacker = SigningKey(bytes(range(1, 33)))
    forgery = sign_payload(_receipt().payload, attacker)
    # When verified against the pinned signer
    with pytest.raises(SignerMismatch) as caught:
        verify_receipt(forgery, expected_public_key=_EXPECTED)
    # Then it is coded as a provenance failure, distinctly from a bad-bytes failure
    assert caught.value.code == "avow.signer_mismatch"
    assert caught.value.code != SignatureBytesInvalid.code


def test_should_code_corrupted_signature_bytes_distinctly_from_a_signer_mismatch() -> None:
    # Given a receipt from the pinned signer whose signature bytes were flipped
    forged = _receipt().model_copy(update={"signature": "00" * 64})
    # When verified against that same pinned signer (so the key matches; only bytes fail)
    with pytest.raises(SignatureBytesInvalid) as caught:
        verify_receipt(forged, expected_public_key=_EXPECTED)
    # Then it keeps the published `avow.signature_invalid` code, distinct from the
    # provenance code — this is the case that string has always named
    assert caught.value.code == "avow.signature_invalid"
    assert caught.value.code != SignerMismatch.code


@pytest.mark.parametrize("error_cls", [SignerMismatch, SignatureBytesInvalid])
def test_should_keep_both_causes_catchable_as_signature_invalid(
    error_cls: type[SignatureInvalid],
) -> None:
    # Given either specific cause
    # Then an existing `except SignatureInvalid:` still catches it — the split is
    # additive, so callers written against the published base keep working
    assert issubclass(error_cls, SignatureInvalid)
    with pytest.raises(SignatureInvalid):
        raise error_cls("boom")
