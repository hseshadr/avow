from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator, Mapping

import pytest
from nacl.signing import SigningKey
from pydantic import BaseModel, ConfigDict, field_validator

import avow
import avow.errors as errors_module
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
    SubjectNotFrozen,
)
from avow.verify import verify_receipt

_SEED = bytes(range(32))
_EXPECTED = bytes(SigningKey(_SEED).verify_key).hex()
_PUBLIC_FUNCTIONS = frozenset(
    {
        "append",
        "append_and_save_head",
        "canonical_bytes",
        "content_hash",
        "generate_signing_key",
        "load_signing_key",
        "payload_digest",
        "public_key_hex",
        "read_entries",
        "read_public_key",
        "save_head",
        "save_public_key",
        "save_signing_key",
        "sign_payload",
        "verify_ledger",
        "verify_receipt",
        "verify_signature",
    }
)
_AVOW_CODES: tuple[tuple[type[AvowError], str], ...] = (
    (CanonicalizationFailed, "avow.canonicalization_failed"),
    (SubjectNotFrozen, "avow.subject_not_frozen"),
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


class _MutableSubject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str


class _NestedSubject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    metadata: dict[str, str]


class _ValidatedNestedSubject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    metadata: dict[str, str]

    @field_validator("label")
    @classmethod
    def append_marker(cls, value: str) -> str:
        return f"{value}!"


class _ChangingMapping(Mapping[str, JsonValue]):
    def __init__(self) -> None:
        self.reads = 0

    def __getitem__(self, key: str) -> JsonValue:
        if key != "revision":
            raise KeyError(key)
        self.reads += 1
        return self.reads

    def __iter__(self) -> Iterator[str]:
        return iter(("revision",))

    def __len__(self) -> int:
        return 1


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


def test_should_snapshot_a_stateful_mapping_once_before_signing() -> None:
    subject = _ChangingMapping()

    receipt = sign_payload(subject, SigningKey(_SEED))
    result = verify_receipt(receipt, expected_public_key=_EXPECTED)

    assert result is None
    assert receipt.payload == {"revision": 1}
    assert subject.reads == 1


def test_should_reject_a_mutable_pydantic_subject_with_a_typed_code() -> None:
    subject = _MutableSubject(value="mutable")

    with pytest.raises(AvowError) as caught:
        sign_payload(subject, SigningKey(_SEED))

    assert type(caught.value).__name__ == "SubjectNotFrozen"
    assert caught.value.code == "avow.subject_not_frozen"


def test_should_snapshot_nested_state_from_a_frozen_pydantic_subject() -> None:
    subject = _NestedSubject(metadata={"region": "us-west"})
    receipt = sign_payload(subject, SigningKey(_SEED))

    subject.metadata["region"] = "changed"

    assert receipt.payload.metadata == {"region": "us-west"}
    assert verify_receipt(receipt, expected_public_key=_EXPECTED) is None


def test_should_snapshot_an_already_validated_model_without_revalidation() -> None:
    subject = _ValidatedNestedSubject(label="a", metadata={"region": "us-west"})

    receipt = sign_payload(subject, SigningKey(_SEED))
    subject.metadata["region"] = "changed"

    assert receipt.payload.label == "a!"
    assert receipt.payload.metadata == {"region": "us-west"}
    assert verify_receipt(receipt, expected_public_key=_EXPECTED) is None


def test_should_export_the_complete_envelope_surface() -> None:
    assert avow.SignedReceipt is SignedReceipt
    assert _PUBLIC_FUNCTIONS <= set(avow.__all__)
    assert all(callable(getattr(avow, name)) for name in _PUBLIC_FUNCTIONS)


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


def _published_error_types() -> set[type[AvowError]]:
    return {
        value
        for value in vars(errors_module).values()
        if isinstance(value, type) and issubclass(value, AvowError) and value is not AvowError
    }


def test_should_cover_every_published_avow_error_type() -> None:
    covered = {error_cls for error_cls, _ in _AVOW_CODES}

    assert covered == _published_error_types()


def test_should_publish_no_error_code_that_claims_replay_detection() -> None:
    codes = {error_type.code for error_type in _published_error_types()}

    assert codes
    assert all("replay" not in code for code in codes)
