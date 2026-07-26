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


def test_an_existing_empty_ledger_verifies_as_zero_entries_which_is_a_known_gap(
    tmp_path: Path,
) -> None:
    # Given a ledger file that exists but holds no entries yet
    path = tmp_path / "ledger.jsonl"
    path.touch()
    # When integrity is verified
    # Then it passes with zero entries. This documents CURRENT behaviour, it does not
    # endorse it: a legitimately-fresh ledger and one an attacker truncated to nothing
    # are byte-identical, so this call cannot tell them apart. See the xfail
    # `..._truncated_to_nothing` case below — the fix is a chain whose head is pinned
    # outside the file, not a special case for length zero.
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


# ---------------------------------------------------------------------------
# Whole-entry attacks: the ledger has no chain, so these all pass verification today.
#
# Every test below asserts the behaviour we WANT and is expected to fail until a chain
# (prev_hash + sequence number, with the head pinned out-of-band) lands. `strict=True`
# makes each one a ratchet: the day the chain ships, these turn XPASS and the suite goes
# red until the markers come off. They are executable disclosure, not aspiration.
# ---------------------------------------------------------------------------

_NO_CHAIN_YET = pytest.mark.xfail(
    strict=True,
    reason=(
        "No hash chain: entries are signed independently, so verify_integrity proves "
        "'every line I was shown is genuine' and never 'these are the lines, in this "
        "order, and all of them'. Disclosed in README 'Honest limits'."
    ),
)


def _ledger_of(path: Path, *scores: float) -> None:
    """Write a ledger of genuine, distinguishable entries signed by the pinned key."""
    for value in scores:
        append(_receipt(value), path=path)


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _rewrite(path: Path, lines: list[str]) -> None:
    """Replace the ledger's contents wholesale — the file-level edit an attacker makes."""
    body = "\n".join(lines) + "\n" if lines else ""
    path.write_text(body, encoding="utf-8")


@_NO_CHAIN_YET
def test_should_reject_a_ledger_with_an_entry_deleted(tmp_path: Path) -> None:
    # Given a 3-entry ledger whose MIDDLE entry was removed — the record of the one
    # decision somebody would rather nobody audited. Every surviving line is genuine.
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1, 0.2, 0.3)
    lines = _lines(path)
    _rewrite(path, [lines[0], lines[2]])
    # Then integrity verification must fail: a log that cannot notice a removal is not
    # tamper-evident, whatever each remaining signature says about itself.
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)


@_NO_CHAIN_YET
def test_should_reject_a_ledger_truncated_at_the_end(tmp_path: Path) -> None:
    # Given a 3-entry ledger cut back to its first entry — the cheapest edit of all,
    # and the one that erases whatever happened most recently
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1, 0.2, 0.3)
    _rewrite(path, _lines(path)[:1])
    # Then integrity verification must fail: "how many entries should be here" is a
    # question the file alone can never answer without a chain and a pinned head.
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)


@_NO_CHAIN_YET
def test_should_reject_a_ledger_truncated_to_nothing(tmp_path: Path) -> None:
    # Given a ledger emptied outright — the terminal case of truncation, and today
    # byte-for-byte indistinguishable from a ledger nobody has written to yet
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1, 0.2, 0.3)
    _rewrite(path, [])
    # Then it must fail rather than report a clean bill of health for an erased audit
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)


@_NO_CHAIN_YET
def test_should_reject_a_ledger_whose_entries_were_reordered(tmp_path: Path) -> None:
    # Given a ledger whose entries were swapped so a later decision reads as the earlier
    # one — order is the whole point of a log, and no signature carries it
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1, 0.2)
    first, second = _lines(path)
    _rewrite(path, [second, first])
    # Then integrity verification must fail
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)


@_NO_CHAIN_YET
def test_should_reject_a_ledger_with_a_replayed_entry(tmp_path: Path) -> None:
    # Given a genuine entry copied and appended a second time — a signature is
    # replayable forever precisely because it is a pure function of its payload
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1, 0.2)
    lines = _lines(path)
    _rewrite(path, [*lines, lines[1]])
    # Then integrity verification must fail: a duplicated record inflates the history
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED)


@_NO_CHAIN_YET
def test_should_reject_an_entry_spliced_in_from_another_ledger(tmp_path: Path) -> None:
    # Given two ledgers written by the SAME signer — a staging run and production — and a
    # genuine staging entry moved into production. Nothing is forged: the signature is
    # real, the entry simply never belonged to this log.
    production = tmp_path / "production.jsonl"
    staging = tmp_path / "staging.jsonl"
    _ledger_of(production, 0.1, 0.2)
    _ledger_of(staging, 0.9)
    _rewrite(production, _lines(production) + _lines(staging))
    # Then it must fail: a signature binds an entry to a signer, never to a ledger
    with pytest.raises(LedgerIntegrityError):
        verify_integrity(production, ScoreReceipt, expected_public_key=_EXPECTED)
