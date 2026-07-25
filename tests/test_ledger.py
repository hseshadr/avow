from __future__ import annotations

import os
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from assay.receipt import ReceiptPayload, ScoreReceipt, payload_digest, sign_payload
from avow.errors import LedgerEntryMalformed, LedgerIntegrityError, LedgerUnreadable
from avow.ledger import append, read_all, verify_integrity

_SEED = bytes(range(32))
_EXPECTED = bytes(SigningKey(_SEED).verify_key).hex()


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
    entries = read_all(path, ScoreReceipt)
    # Then both survive, in append order (append-only, nothing overwritten)
    assert len(entries) == 2
    assert entries[0].payload.score == 0.1
    assert entries[1].payload.score == 0.2


def test_should_fail_closed_when_ledger_is_absent(tmp_path: Path) -> None:
    # Given no ledger file at the given path (a typo, or a file never written)
    missing = tmp_path / "missing.jsonl"
    # When integrity is verified
    # Then it fails closed: an unanswered question is not a clean bill of health
    with pytest.raises(LedgerUnreadable):
        verify_integrity(missing, ScoreReceipt, expected_public_key=_EXPECTED)
    with pytest.raises(LedgerUnreadable):
        read_all(missing, ScoreReceipt)


def test_should_fail_closed_when_ledger_path_is_a_directory(tmp_path: Path) -> None:
    # Given a directory where a ledger file was expected
    directory = tmp_path / "ledger.jsonl"
    directory.mkdir()
    # When integrity is verified
    # Then it fails closed rather than crashing uncoded
    with pytest.raises(LedgerUnreadable):
        verify_integrity(directory, ScoreReceipt, expected_public_key=_EXPECTED)


def test_should_fail_closed_when_ledger_is_unreadable(tmp_path: Path) -> None:
    # Given a ledger whose permissions deny reading
    path = tmp_path / "ledger.jsonl"
    append(_receipt(0.1), path=path)
    path.chmod(0o000)
    if os.access(path, os.R_OK):  # root ignores the mode; the case cannot be staged
        pytest.skip("running as root: unreadable files are still readable")
    # When integrity is verified
    # Then it fails closed with the coded cause
    with pytest.raises(LedgerUnreadable):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)


def test_should_fail_closed_when_a_line_is_malformed(tmp_path: Path) -> None:
    # Given a ledger with a corrupted (non-receipt) line
    path = tmp_path / "ledger.jsonl"
    append(_receipt(0.1), path=path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{not a receipt}\n")
    # When integrity is verified
    # Then it names the coded cause instead of leaking a parse traceback
    with pytest.raises(LedgerEntryMalformed):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)


def test_should_verify_an_existing_empty_ledger_as_zero_entries(tmp_path: Path) -> None:
    # Given a ledger file that exists but holds no entries yet
    path = tmp_path / "ledger.jsonl"
    path.touch()
    # When integrity is verified
    # Then it passes with zero entries — an empty ledger is a legitimate initial
    # state, unlike an absent one, which answers nothing
    assert verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED) == ()


def test_should_raise_integrity_error_when_a_line_is_tampered(tmp_path: Path) -> None:
    # Given a ledger whose stored hash was corrupted on disk
    path = tmp_path / "ledger.jsonl"
    append(_receipt(0.1), path=path)
    corrupted = path.read_text().replace('"score":0.1', '"score":0.999')
    path.write_text(corrupted)
    # When integrity is verified
    # Then it fails closed
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)


def test_should_reject_a_rehashed_tampered_entry_without_the_signing_key(tmp_path: Path) -> None:
    # Given a ledger entry an adversary edited AND re-hashed. With no signing key they
    # can still recompute the PUBLIC payload_hash, so a hash-only check would wave the
    # forgery through — the exact laundering a real tamper-evidence check must catch.
    path = tmp_path / "ledger.jsonl"
    append(_receipt(0.1), path=path)
    stored = ScoreReceipt.model_validate_json(path.read_text())
    forged_payload = stored.payload.model_copy(update={"score": 0.999})
    forged = stored.model_copy(
        update={"payload": forged_payload, "payload_hash": payload_digest(forged_payload)}
    )
    path.write_text(forged.model_dump_json() + "\n")
    # Then integrity verification REJECTS it: the Ed25519 signature no longer matches the
    # payload, and a recomputed hash cannot launder a forged entry past the pinned key.
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)
