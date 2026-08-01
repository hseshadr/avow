from __future__ import annotations

import os
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from assay.receipt import ReceiptPayload, ScoreReceipt, payload_digest, sign_payload
from avow.errors import (
    LedgerEntryMalformed,
    LedgerHeadUnreadable,
    LedgerIntegrityError,
    LedgerUnreadable,
)
from avow.ledger import (
    EMPTY_HEAD,
    LedgerHead,
    append,
    current_head,
    entry_hash,
    read_all,
    read_entries,
    read_head,
    save_head,
    verify_integrity,
)

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


def _ledger_of(path: Path, *scores: float) -> LedgerHead:
    """Write a ledger of genuine, distinguishable entries and return its pinned head.

    The head is what the operator carries out-of-band; every attack below happens
    *after* this returns, so the pin describes the history as it really was."""
    head = EMPTY_HEAD
    for value in scores:
        head = append(_receipt(value), path=path)
    return head


def _verify(path: Path, head: LedgerHead) -> tuple[ScoreReceipt, ...]:
    return verify_integrity(path, ScoreReceipt, expected_public_key=_EXPECTED, expected_head=head)


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _rewrite(path: Path, lines: list[str]) -> None:
    """Replace the ledger's contents wholesale — the file-level edit an attacker makes."""
    body = "\n".join(lines) + "\n" if lines else ""
    path.write_text(body, encoding="utf-8")


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


def test_should_return_a_head_that_advances_with_every_append(tmp_path: Path) -> None:
    # Given a fresh ledger
    path = tmp_path / "ledger.jsonl"
    # When receipts are appended
    first = append(_receipt(0.1), path=path)
    second = append(_receipt(0.2), path=path)
    # Then each append reports the ledger's new head: the count grows and the hash moves,
    # so the operator always has a fresh 32 bytes to pin
    assert (first.count, second.count) == (1, 2)
    assert first.head_hash != second.head_hash
    assert second != EMPTY_HEAD
    # And a ledger verifies against the head its last append returned
    assert len(_verify(path, second)) == 2


def test_should_fail_closed_when_ledger_is_absent(tmp_path: Path) -> None:
    # Given no ledger file at the given path (a typo, or a file never written)
    missing = tmp_path / "missing.jsonl"
    # When integrity is verified
    # Then it fails closed: an unanswered question is not a clean bill of health
    with pytest.raises(LedgerUnreadable):
        _verify(missing, EMPTY_HEAD)
    with pytest.raises(LedgerUnreadable):
        read_all(missing, ScoreReceipt)


def test_should_fail_closed_when_ledger_path_is_a_directory(tmp_path: Path) -> None:
    # Given a directory where a ledger file was expected
    directory = tmp_path / "ledger.jsonl"
    directory.mkdir()
    # When integrity is verified
    # Then it fails closed rather than crashing uncoded
    with pytest.raises(LedgerUnreadable):
        _verify(directory, EMPTY_HEAD)


def test_should_fail_closed_when_ledger_is_unreadable(tmp_path: Path) -> None:
    # Given a ledger whose permissions deny reading
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1)
    path.chmod(0o000)
    if os.access(path, os.R_OK):  # root ignores the mode; the case cannot be staged
        pytest.skip("running as root: unreadable files are still readable")
    # When integrity is verified
    # Then it fails closed with the coded cause
    with pytest.raises(LedgerUnreadable):
        _verify(path, head)


def test_should_fail_closed_when_a_line_is_malformed(tmp_path: Path) -> None:
    # Given a ledger with a corrupted (non-entry) line
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{not an entry}\n")
    # When integrity is verified
    # Then it names the coded cause instead of leaking a parse traceback
    with pytest.raises(LedgerEntryMalformed):
        _verify(path, head)


def test_should_fail_closed_when_a_line_is_not_a_receipt_of_the_expected_type(
    tmp_path: Path,
) -> None:
    # Given a well-formed chain entry whose receipt is not a ScoreReceipt at all
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1)
    _rewrite(path, ['{"seq":0,"prev_hash":"sha256:' + "0" * 64 + '","receipt":{"nope":1}}'])
    # When integrity is verified against the head that file itself claims — so only the
    # receipt parse can fail
    # Then it fails closed with the coded cause
    with pytest.raises(LedgerEntryMalformed):
        _verify(path, current_head(path))


def test_a_fresh_empty_ledger_verifies_only_against_the_empty_head(tmp_path: Path) -> None:
    # Given a ledger file that exists but holds no entries yet
    path = tmp_path / "ledger.jsonl"
    path.touch()
    # When integrity is verified against the head a fresh ledger really has
    # Then it passes with zero entries — an unwritten ledger is a legitimate state
    assert _verify(path, EMPTY_HEAD) == ()
    # And that pass is now conditional, which is the whole point: the same empty file
    # checked against a head that says "three entries" FAILS. This inverts the old
    # `..._which_is_a_known_gap` test, which asserted the unconditional zero-entry pass
    # as the requirement — the exact behaviour that let a wiped audit read as clean.
    with pytest.raises(LedgerIntegrityError):
        _verify(path, LedgerHead(count=3, head_hash="sha256:" + "ab" * 32))


def test_should_raise_integrity_error_when_a_line_is_tampered(tmp_path: Path) -> None:
    # Given a ledger whose stored payload was corrupted on disk
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1)
    corrupted = path.read_text().replace('"score":0.1', '"score":0.999')
    path.write_text(corrupted)
    # When integrity is verified against the head the DOCTORED file claims — so the chain
    # walk and the head comparison both pass and only the per-entry check can object
    # Then it still fails closed: the payload no longer hashes to its stored hash
    with pytest.raises(LedgerIntegrityError):
        _verify(path, current_head(path))


def test_should_reject_a_rehashed_tampered_entry_without_the_signing_key(tmp_path: Path) -> None:
    # Given a ledger entry an adversary edited AND re-hashed. With no signing key they
    # can still recompute the PUBLIC payload_hash, so a hash-only check would wave the
    # forgery through — the exact laundering a real tamper-evidence check must catch.
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1)
    stored = read_all(path, ScoreReceipt)[0]
    forged_payload = stored.payload.model_copy(update={"score": 0.999})
    forged = stored.model_copy(
        update={"payload": forged_payload, "payload_hash": payload_digest(forged_payload)}
    )
    _rewrite(path, [])
    append(forged, path=path)
    # Then integrity verification REJECTS it even with the chain rebuilt around it and
    # the head recomputed: the Ed25519 signature no longer matches the payload, and a
    # recomputed hash cannot launder a forged entry past the pinned key.
    with pytest.raises(LedgerIntegrityError):
        _verify(path, current_head(path))


def test_should_reject_an_entry_signed_by_another_key(tmp_path: Path) -> None:
    # Given a chain-perfect ledger whose entry was signed by a key nobody pinned
    path = tmp_path / "ledger.jsonl"
    payload = ReceiptPayload(
        assay_version="0.0.1",
        metric="binary",
        metric_version="1",
        inputs_hash="sha256:abc",
        score=0.5,
    )
    append(sign_payload(payload, SigningKey(bytes(range(32, 64)))), path=path)
    # Then the chain being intact does not make the entry trusted
    with pytest.raises(LedgerIntegrityError):
        _verify(path, current_head(path))


# ---------------------------------------------------------------------------
# Whole-entry attacks. Every line is genuine and correctly signed; the attack is on the
# SET and its ORDER, which no per-line signature can speak to. These are the tests the
# chain exists to pass — until it landed, all six returned "verified" and exit 0.
# ---------------------------------------------------------------------------


def test_should_reject_a_ledger_with_an_entry_deleted(tmp_path: Path) -> None:
    # Given a 3-entry ledger whose MIDDLE entry was removed — the record of the one
    # decision somebody would rather nobody audited. Every surviving line is genuine.
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2, 0.3)
    lines = _lines(path)
    _rewrite(path, [lines[0], lines[2]])
    # Then integrity verification must fail: a log that cannot notice a removal is not
    # tamper-evident, whatever each remaining signature says about itself.
    with pytest.raises(LedgerIntegrityError):
        _verify(path, head)


def test_should_reject_a_ledger_re_chained_after_a_deletion(tmp_path: Path) -> None:
    # Given the strongest version of that attacker: one who deletes an entry and then
    # REBUILDS the whole chain over what is left, so every prev_hash and seq is perfect
    # and the file's own arithmetic agrees with itself
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2, 0.3)
    _rewrite(path, [])
    _ledger_of(path, 0.1, 0.3)
    assert current_head(path) != head  # the file now tells a self-consistent lie
    # Then it must STILL fail, because the head it ends at is not the head the operator
    # pinned. This is the case a chain alone cannot catch, and the reason the head must
    # live outside the file.
    with pytest.raises(LedgerIntegrityError):
        _verify(path, head)


def test_should_reject_a_ledger_truncated_at_the_end(tmp_path: Path) -> None:
    # Given a 3-entry ledger cut back to its first entry — the cheapest edit of all,
    # and the one that erases whatever happened most recently. What remains is a
    # perfectly valid chain; only its length gives it away.
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2, 0.3)
    _rewrite(path, _lines(path)[:1])
    # Then integrity verification must fail, and specifically at the pinned head: "how
    # many entries should be here" is a question the file alone can never answer.
    with pytest.raises(LedgerIntegrityError, match="but the pinned head is"):
        _verify(path, head)


def test_should_reject_a_ledger_truncated_to_nothing(tmp_path: Path) -> None:
    # Given a ledger emptied outright — the terminal case of truncation, and
    # byte-for-byte indistinguishable from a ledger nobody has written to yet
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2, 0.3)
    _rewrite(path, [])
    # Then it must fail rather than report a clean bill of health for an erased audit
    with pytest.raises(LedgerIntegrityError):
        _verify(path, head)


def test_should_reject_a_ledger_whose_entries_were_reordered(tmp_path: Path) -> None:
    # Given a ledger whose entries were swapped so a later decision reads as the earlier
    # one — order is the whole point of a log, and no signature carries it
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2)
    first, second = _lines(path)
    _rewrite(path, [second, first])
    # Then integrity verification must fail
    with pytest.raises(LedgerIntegrityError):
        _verify(path, head)


def test_should_reject_a_ledger_whose_interior_entries_were_swapped(tmp_path: Path) -> None:
    # Given a 4-entry ledger with its two MIDDLE entries swapped. This is the attack the
    # pinned head cannot see: the entry count is unchanged and the last line is
    # untouched, so the ledger still ends exactly where the operator pinned it. Only
    # walking the links — each entry's prev_hash against its actual predecessor — objects.
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2, 0.3, 0.4)
    lines = _lines(path)
    _rewrite(path, [lines[0], lines[2], lines[1], lines[3]])
    assert current_head(path) == head  # the head check alone would wave this through
    # Then integrity verification must fail
    with pytest.raises(LedgerIntegrityError):
        _verify(path, head)


def test_should_reject_a_ledger_whose_interior_entry_was_replaced(tmp_path: Path) -> None:
    # Given a 3-entry ledger whose MIDDLE entry was swapped out for a genuine entry from
    # another ledger by the same signer, at the position it claims. Count unchanged, last
    # line unchanged — the pinned head still matches, so only the chain link can catch it.
    path = tmp_path / "ledger.jsonl"
    other = tmp_path / "other.jsonl"
    head = _ledger_of(path, 0.1, 0.2, 0.3)
    _ledger_of(other, 0.7, 0.9)
    lines = _lines(path)
    _rewrite(path, [lines[0], _lines(other)[1], lines[2]])
    assert current_head(path) == head  # the head check alone would wave this through
    # Then integrity verification must fail, and specifically because the LINK broke —
    # `match` pins which guard fired, so this cannot silently start passing for an
    # unrelated reason if the head check ever changes
    with pytest.raises(LedgerIntegrityError, match="does not chain to the entry before it"):
        _verify(path, head)


def test_should_reject_an_entry_that_claims_a_position_it_is_not_in(tmp_path: Path) -> None:
    # Given a single genuine entry whose sequence number was edited to claim it is the
    # eighth entry of some longer history, with the head pinned to that exact one-entry
    # file. Chain and head both agree; only the position claim is a lie.
    path = tmp_path / "ledger.jsonl"
    _ledger_of(path, 0.1)
    entry = read_entries(path)[0].model_copy(update={"seq": 7})
    _rewrite(path, [entry.model_dump_json()])
    pinned = LedgerHead(count=1, head_hash=entry_hash(entry))
    # Then verification rejects it: an entry that claims position 7 is not the first
    # entry of anything, whatever the rest of the file says
    with pytest.raises(LedgerIntegrityError, match="claims sequence 7"):
        _verify(path, pinned)


def test_should_reject_a_ledger_with_a_replayed_entry(tmp_path: Path) -> None:
    # Given a genuine entry copied and appended a second time — a signature is
    # replayable forever precisely because it is a pure function of its payload
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2)
    lines = _lines(path)
    _rewrite(path, [*lines, lines[1]])
    # Then integrity verification must fail: a duplicated record inflates the history
    with pytest.raises(LedgerIntegrityError):
        _verify(path, head)


def test_should_reject_an_entry_spliced_in_from_another_ledger(tmp_path: Path) -> None:
    # Given two ledgers written by the SAME signer — a staging run and production — and a
    # genuine staging entry moved into production AT THE POSITION IT CLAIMS, so its
    # sequence number lines up and only the chain link can object. Nothing is forged:
    # the signature is real, the entry simply never belonged to this log.
    production = tmp_path / "production.jsonl"
    staging = tmp_path / "staging.jsonl"
    head = _ledger_of(production, 0.1, 0.2)
    _ledger_of(staging, 0.9, 0.8, 0.7)
    spliced = _lines(staging)[2]
    _rewrite(production, [*_lines(production), spliced])
    # Then it must fail: a signature binds an entry to a signer, never to a ledger
    with pytest.raises(LedgerIntegrityError):
        _verify(production, head)


# ---------------------------------------------------------------------------
# The pinned head itself: a verifier input, held to the same fail-closed bar as the
# pinned public key.
# ---------------------------------------------------------------------------


def test_should_round_trip_a_pinned_head_through_a_file(tmp_path: Path) -> None:
    # Given a head written for the operator to carry out-of-band
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2)
    pin = tmp_path / "ledger.jsonl.head"
    save_head(head, path=pin)
    # When it is read back
    # Then it is the same pin, and the ledger verifies against it
    assert read_head(pin) == head
    assert len(_verify(path, read_head(pin))) == 2


def test_should_fail_closed_when_the_pinned_head_is_missing_or_unusable(
    tmp_path: Path,
) -> None:
    # Given no pin at all, and a pin whose contents are not a head
    junk = tmp_path / "junk.head"
    junk.write_text("not a head", encoding="utf-8")
    # Then reading either fails closed rather than falling back to the file's own head
    with pytest.raises(LedgerHeadUnreadable):
        read_head(tmp_path / "absent.head")
    with pytest.raises(LedgerHeadUnreadable):
        read_head(junk)


def test_current_head_reports_what_the_file_claims_including_when_empty(
    tmp_path: Path,
) -> None:
    # Given an empty ledger and then a written one
    path = tmp_path / "ledger.jsonl"
    path.touch()
    assert current_head(path) == EMPTY_HEAD
    # When entries are appended
    head = _ledger_of(path, 0.1, 0.2)
    # Then the file's own head matches what append reported — this is a convenience for
    # recording a pin, never evidence: it is derived from the very bytes under audit
    assert current_head(path) == head
