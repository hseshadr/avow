from __future__ import annotations

from pathlib import Path

import pytest
from nacl.signing import SigningKey

from assay.errors import LedgerIntegrityError
from assay.ledger import append, read_all, verify_integrity
from assay.receipt import ReceiptPayload, ScoreReceipt, sign_payload

_SEED = bytes(range(32))


def _receipt(score: float) -> ScoreReceipt:
    payload = ReceiptPayload(
        assay_version="0.0.1",
        metric="binary",
        metric_version="1",
        inputs_hash="sha256:abc",
        score=score,
    )
    return sign_payload(payload, SigningKey(_SEED))


def test_should_append_only_and_read_back_in_order(tmp_path: Path) -> None:
    # Given two receipts appended to a fresh ledger
    path = tmp_path / "ledger.jsonl"
    append(_receipt(0.1), path=path)
    append(_receipt(0.2), path=path)
    # When read back
    entries = read_all(path)
    # Then both survive, in append order (append-only, nothing overwritten)
    assert len(entries) == 2
    assert entries[0].payload.score == 0.1
    assert entries[1].payload.score == 0.2


def test_should_return_empty_when_ledger_absent(tmp_path: Path) -> None:
    # Given no ledger file
    # When read
    # Then the result is empty, not an error
    assert read_all(tmp_path / "missing.jsonl") == ()


def test_should_raise_integrity_error_when_a_line_is_tampered(tmp_path: Path) -> None:
    # Given a ledger whose stored hash was corrupted on disk
    path = tmp_path / "ledger.jsonl"
    append(_receipt(0.1), path=path)
    corrupted = path.read_text().replace('"score":0.1', '"score":0.999')
    path.write_text(corrupted)
    # When integrity is verified
    # Then it fails closed
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(path)
