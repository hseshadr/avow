from __future__ import annotations

import importlib
import sys

import pytest
from nacl.signing import SigningKey
from pydantic import BaseModel, ConfigDict

import avow
from avow.canonical import JsonValue
from avow.envelope import SignedReceipt, payload_digest, sign_payload, verify_signature
from avow.errors import (
    AvowError,
    CanonicalizationFailed,
    LedgerConfigurationInvalid,
    LedgerEntryMalformed,
    LedgerHeadUnreadable,
    LedgerHeadWriteFailed,
    LedgerIntegrityError,
    LedgerLimitExceeded,
    LedgerLockTimeout,
    LedgerRecoveryRequired,
    LedgerUnreadable,
    PayloadHashMismatch,
    SignatureBytesInvalid,
    SignatureInvalid,
    SignerMismatch,
)
from avow.verify import verify_receipt

_SEED = bytes(range(32))
_EXPECTED = bytes(SigningKey(_SEED).verify_key).hex()
_AVOW_CODES: tuple[tuple[type[AvowError], str], ...] = (
    (CanonicalizationFailed, "avow.canonicalization_failed"),
    (SignatureInvalid, "avow.signature_invalid"),
    (SignerMismatch, "avow.signer_mismatch"),
    (SignatureBytesInvalid, "avow.signature_invalid"),
    (PayloadHashMismatch, "avow.payload_hash_mismatch"),
    (LedgerIntegrityError, "avow.ledger_integrity"),
    (LedgerUnreadable, "avow.ledger_unreadable"),
    (LedgerEntryMalformed, "avow.ledger_entry_malformed"),
    (LedgerHeadUnreadable, "avow.ledger_head_unreadable"),
    (LedgerHeadWriteFailed, "avow.ledger_head_write_failed"),
    (LedgerLockTimeout, "avow.ledger_lock_timeout"),
    (LedgerConfigurationInvalid, "avow.ledger_configuration_invalid"),
    (LedgerLimitExceeded, "avow.ledger_limit_exceeded"),
    (LedgerRecoveryRequired, "avow.ledger_recovery_required"),
)


class _EvidenceSubject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str
    value: float
    interval_low: float | None = None
    interval_high: float | None = None


class _ActionSubject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    target: str


class _ScoreResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str
    result: float


class _PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy: str
    decision: str


def _payload() -> _EvidenceSubject:
    return _EvidenceSubject(kind="measurement", value=0.8, interval_low=0.7, interval_high=0.9)


def test_should_verify_a_freshly_signed_receipt() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))

    verify_signature(receipt, expected_public_key=_EXPECTED)

    assert len(receipt.signature) == 128
    assert len(receipt.public_key) == 64


def test_should_be_byte_identical_when_signed_twice() -> None:
    first = sign_payload(_payload(), SigningKey(_SEED))

    second = sign_payload(_payload(), SigningKey(_SEED))

    assert first == second


def test_should_verify_when_the_pinned_key_case_differs() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))

    result = verify_signature(receipt, expected_public_key=_EXPECTED.upper())

    assert result is None


def test_should_raise_payload_hash_mismatch_when_hash_is_tampered() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    tampered = receipt.model_copy(update={"payload_hash": "sha256:deadbeef"})

    with pytest.raises(PayloadHashMismatch):
        verify_signature(tampered, expected_public_key=_EXPECTED)


def test_should_raise_signature_invalid_when_payload_is_tampered() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    swapped = receipt.payload.model_copy(update={"value": 0.999})
    tampered = receipt.model_copy(
        update={"payload": swapped, "payload_hash": payload_digest(swapped)}
    )

    with pytest.raises(SignatureInvalid):
        verify_signature(tampered, expected_public_key=_EXPECTED)


def test_should_fail_closed_on_malformed_signature_hex() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    malformed = receipt.model_copy(update={"signature": "zz"})

    with pytest.raises(SignatureInvalid):
        verify_signature(malformed, expected_public_key=_EXPECTED)


def test_should_expose_signed_receipt_as_public_symbol() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))

    assert isinstance(receipt, SignedReceipt)
    assert receipt.payload.value == 0.8


def test_should_sign_and_verify_an_unrelated_subject_with_the_same_envelope() -> None:
    subject = _ActionSubject(action="revoke", target="key-7")

    receipt = sign_payload(subject, SigningKey(_SEED))

    assert receipt.payload == subject
    assert receipt.payload_hash == payload_digest(subject)
    assert verify_signature(receipt, expected_public_key=_EXPECTED) is None
    with pytest.raises(SignatureInvalid):
        verify_signature(receipt, expected_public_key="ab" * 32)


def test_should_seal_opaque_subjects_without_domain_specific_adapters() -> None:
    subjects: tuple[BaseModel | dict[str, JsonValue], ...] = (
        _ScoreResult(method="weighted_mean/v1", result=0.82),
        {"artifact": "web.tar", "digest": "sha256:abc", "environment": "production"},
        _PolicyDecision(policy="retention/v3", decision="delete"),
    )

    for subject in subjects:
        first = sign_payload(subject, SigningKey(_SEED))
        second = sign_payload(subject, SigningKey(_SEED))
        assert first.model_dump_json() == second.model_dump_json()
        assert verify_receipt(first, expected_public_key=_EXPECTED) is None


def test_should_export_the_complete_envelope_surface() -> None:
    exports = (
        avow.canonical_bytes,
        avow.content_hash,
        avow.generate_signing_key,
        avow.payload_digest,
        avow.public_key_hex,
        avow.sign_payload,
        avow.verify_ledger,
        avow.verify_receipt,
        avow.verify_signature,
    )

    assert avow.SignedReceipt is SignedReceipt
    assert all(callable(exported) for exported in exports)


def test_should_load_no_domain_or_scientific_runtime_dependency() -> None:
    forbidden = ("assay", "writ", "sklearn", "scipy", "numpy")
    for module in [name for name in sys.modules if name.startswith(forbidden)]:
        del sys.modules[module]

    importlib.reload(avow)

    assert not any(name.startswith(forbidden) for name in sys.modules)


def test_should_fail_offline_for_forged_signature_bytes() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    forged = receipt.model_copy(update={"signature": "00" * 64})

    with pytest.raises(SignatureBytesInvalid) as caught:
        verify_receipt(forged, expected_public_key=_EXPECTED)

    assert caught.value.code == "avow.signature_invalid"
    assert caught.value.code != SignerMismatch.code


def test_should_reject_a_receipt_resigned_by_a_different_key() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    attacker = SigningKey(bytes(range(1, 33)))
    forgery = sign_payload(receipt.payload.model_copy(update={"value": 0.999}), attacker)

    with pytest.raises(SignerMismatch) as caught:
        verify_receipt(forgery, expected_public_key=_EXPECTED)

    assert forgery.public_key != _EXPECTED
    assert caught.value.code == "avow.signer_mismatch"


@pytest.mark.parametrize("error_cls", [SignerMismatch, SignatureBytesInvalid])
def test_should_keep_specific_signature_failures_catchable_by_the_base(
    error_cls: type[SignatureInvalid],
) -> None:
    assert issubclass(error_cls, SignatureInvalid)

    with pytest.raises(SignatureInvalid):
        raise error_cls("boom")


def test_should_verify_an_unchanged_receipt_on_every_replay() -> None:
    receipt_type = SignedReceipt[_EvidenceSubject]
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    captured = receipt_type.model_validate_json(receipt.model_dump_json())

    results = [verify_receipt(captured, expected_public_key=_EXPECTED) for _ in range(100)]

    assert captured.model_dump_json() == receipt.model_dump_json()
    assert results == [None] * 100


def test_should_name_tampering_without_claiming_replay_detection() -> None:
    receipt = sign_payload(_payload(), SigningKey(_SEED))
    tampered = receipt.model_copy(
        update={"payload": receipt.payload.model_copy(update={"value": 0.99})}
    )

    with pytest.raises(AvowError) as caught:
        verify_receipt(tampered, expected_public_key=_EXPECTED)

    assert "replay" not in type(caught.value).__name__.lower()
    assert caught.value.code == "avow.payload_hash_mismatch"


@pytest.mark.parametrize(("error_cls", "code"), _AVOW_CODES)
def test_should_carry_a_stable_avow_code_when_raised(error_cls: type[AvowError], code: str) -> None:
    with pytest.raises(AvowError) as caught:
        raise error_cls("boom")

    assert isinstance(caught.value, AvowError)
    assert caught.value.code == code
    assert "replay" not in caught.value.code
