from __future__ import annotations

import pytest

from assay.errors import (
    AssayError,
    CanonicalizationFailed,
    InsufficientSamples,
    InvalidScoreRequest,
    LedgerIntegrityError,
    ReplayMismatch,
    SignatureInvalid,
    UnknownMetric,
)

_EXPECTED_CODES = [
    (InvalidScoreRequest, "assay.invalid_request"),
    (UnknownMetric, "assay.unknown_metric"),
    (InsufficientSamples, "assay.insufficient_samples"),
    (CanonicalizationFailed, "assay.canonicalization_failed"),
    (SignatureInvalid, "assay.signature_invalid"),
    (ReplayMismatch, "assay.replay_mismatch"),
    (LedgerIntegrityError, "assay.ledger_integrity"),
]


@pytest.mark.parametrize(("error_cls", "code"), _EXPECTED_CODES)
def test_should_carry_stable_code_when_raised(error_cls: type[AssayError], code: str) -> None:
    # Given a domain error class
    # When it is instantiated and raised
    with pytest.raises(AssayError) as caught:
        raise error_cls("boom")
    # Then it is an AssayError carrying its stable code
    assert isinstance(caught.value, AssayError)
    assert caught.value.code == code
