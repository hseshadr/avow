from __future__ import annotations

import pytest

from assay.errors import (
    AssayError,
    InsufficientSamples,
    InvalidScoreRequest,
    ScoringExtraMissing,
    UnknownMetric,
)
from avow.errors import (
    AvowError,
    CanonicalizationFailed,
    LedgerEntryMalformed,
    LedgerHeadUnreadable,
    LedgerIntegrityError,
    LedgerUnreadable,
    ReplayMismatch,
    SignatureBytesInvalid,
    SignatureInvalid,
    SignerMismatch,
)

# The scoring face keeps its own ``assay.*`` catalog under ``AssayError``.
_ASSAY_CODES = [
    (InvalidScoreRequest, "assay.invalid_request"),
    (UnknownMetric, "assay.unknown_metric"),
    (InsufficientSamples, "assay.insufficient_samples"),
    (ScoringExtraMissing, "assay.scoring_extra_missing"),
]

# The trust envelope keeps its own ``avow.*`` catalog under ``AvowError``.
_AVOW_CODES = [
    (CanonicalizationFailed, "avow.canonicalization_failed"),
    (SignatureInvalid, "avow.signature_invalid"),
    # A provenance failure (untrusted signer) is coded apart from a tamper failure
    # (bad bytes); the tamper case keeps the published `avow.signature_invalid`.
    (SignerMismatch, "avow.signer_mismatch"),
    (SignatureBytesInvalid, "avow.signature_invalid"),
    (ReplayMismatch, "avow.replay_mismatch"),
    (LedgerIntegrityError, "avow.ledger_integrity"),
    (LedgerUnreadable, "avow.ledger_unreadable"),
    (LedgerEntryMalformed, "avow.ledger_entry_malformed"),
    (LedgerHeadUnreadable, "avow.ledger_head_unreadable"),
]


@pytest.mark.parametrize(("error_cls", "code"), _ASSAY_CODES)
def test_should_carry_stable_assay_code_when_raised(error_cls: type[AssayError], code: str) -> None:
    # Given a scoring-face domain error class
    # When it is instantiated and raised
    with pytest.raises(AssayError) as caught:
        raise error_cls("boom")
    # Then it is an AssayError carrying its stable code
    assert isinstance(caught.value, AssayError)
    assert caught.value.code == code


@pytest.mark.parametrize(("error_cls", "code"), _AVOW_CODES)
def test_should_carry_stable_avow_code_when_raised(error_cls: type[AvowError], code: str) -> None:
    # Given an envelope domain error class
    # When it is instantiated and raised
    with pytest.raises(AvowError) as caught:
        raise error_cls("boom")
    # Then it is an AvowError carrying its stable code
    assert isinstance(caught.value, AvowError)
    assert caught.value.code == code
