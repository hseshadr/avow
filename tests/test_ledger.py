from __future__ import annotations

import fcntl
import json
import multiprocessing
import os
from pathlib import Path

import pytest
from nacl.signing import SigningKey

import avow.ledger as ledger_module
from assay.receipt import ReceiptPayload, ScoreReceipt, payload_digest, sign_payload
from avow.errors import (
    AvowError,
    LedgerEntryMalformed,
    LedgerHeadUnreadable,
    LedgerHeadWriteFailed,
    LedgerIntegrityError,
    LedgerLimitExceeded,
    LedgerLockTimeout,
    LedgerRecoveryRequired,
    LedgerUnreadable,
)
from avow.ledger import (
    EMPTY_HEAD,
    GENESIS_HASH,
    LedgerHead,
    _decode_entry_line,
    _decode_last_line,
    _same_parent,
    append,
    append_and_save_head,
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


def _append_many_process(ledger: Path, head: Path, start: int, count: int) -> None:
    for index in range(start, start + count):
        append_and_save_head(_receipt(index / 1000), path=ledger, head_path=head)


def _hold_ledger_lock(path: Path, ready: object, release: object) -> None:
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        ready.set()  # type: ignore[attr-defined]
        release.wait(timeout=10)  # type: ignore[attr-defined]


def _append_then_exit(path: Path) -> None:
    append(_receipt(0.42), path=path)
    os._exit(0)


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


def test_should_serialize_ledger_and_saved_head_across_real_processes(tmp_path: Path) -> None:
    # Given four independent writers sharing one ledger and one convenience pin
    ledger = tmp_path / "ledger.jsonl"
    head_path = tmp_path / "ledger.head"
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(target=_append_many_process, args=(ledger, head_path, i * 10, 10))
        for i in range(4)
    ]
    # When all writers append concurrently
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=15)
    # Then none deadlocks and the saved pin is exactly the complete serialized history
    assert [worker.exitcode for worker in workers] == [0, 0, 0, 0]
    pinned = read_head(head_path)
    assert pinned.count == 40
    assert len(_verify(ledger, pinned)) == 40


def test_should_time_out_with_a_coded_error_when_another_process_holds_lock(
    tmp_path: Path,
) -> None:
    # Given another real process holds the ledger lock beyond this append's bound
    ledger = tmp_path / "ledger.jsonl"
    context = multiprocessing.get_context("spawn")
    ready, release = context.Event(), context.Event()
    holder = context.Process(target=_hold_ledger_lock, args=(ledger, ready, release))
    holder.start()
    assert ready.wait(timeout=5)
    # When append reaches its 50ms timeout, it fails without writing or deadlocking
    with pytest.raises(LedgerLockTimeout, match=r"0\.050"):
        append(_receipt(0.1), path=ledger, lock_timeout_seconds=0.05)
    assert ledger.read_text(encoding="utf-8") == ""
    release.set()
    holder.join(timeout=5)
    assert holder.exitcode == 0


@pytest.mark.parametrize("timeout", [-0.1, float("inf"), float("nan")])
def test_should_reject_an_unbounded_lock_timeout_before_writing(
    tmp_path: Path, timeout: float
) -> None:
    # Given a timeout that cannot express one finite, non-negative deadline
    ledger = tmp_path / "ledger.jsonl"
    # When append is asked to use it, the malformed boundary fails closed and coded
    with pytest.raises(AvowError) as caught:
        append(_receipt(0.1), path=ledger, lock_timeout_seconds=timeout)
    assert caught.value.code == "avow.ledger_configuration_invalid"
    assert not ledger.exists()


def test_should_bound_ledger_entry_count_without_changing_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a ledger has reached its explicit supported entry ceiling
    ledger = tmp_path / "ledger.jsonl"
    first = append(_receipt(0.1), path=ledger)
    before = ledger.read_bytes()
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_ENTRIES", 1)
    # When one more append is attempted, it fails before changing the file
    with pytest.raises(LedgerLimitExceeded):
        append(_receipt(0.2), path=ledger)
    assert ledger.read_bytes() == before
    assert current_head(ledger) == first


def test_should_bound_total_ledger_bytes_before_reading_or_appending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given an existing ledger exceeds the configured byte ceiling
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_BYTES", 2)
    # Then both read and append fail closed without changing its bytes
    before = ledger.read_bytes()
    with pytest.raises(LedgerLimitExceeded):
        read_entries(ledger)
    with pytest.raises(LedgerLimitExceeded):
        append(_receipt(0.1), path=ledger)
    assert ledger.read_bytes() == before


def test_should_bound_one_ledger_line_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given even one encoded receipt would exceed the supported line ceiling
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_LINE_BYTES", 32)
    # When append serialises it, no partial line is written
    with pytest.raises(LedgerLimitExceeded):
        append(_receipt(0.1), path=ledger)
    assert ledger.read_bytes() == b""


def test_should_bound_the_appended_total_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given the existing ledger fits but the next complete line would cross its byte cap
    ledger = tmp_path / "ledger.jsonl"
    first = append(_receipt(0.1), path=ledger)
    before = ledger.read_bytes()
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_BYTES", len(before) + 1)
    # When another valid receipt is appended, history remains byte-identical
    with pytest.raises(LedgerLimitExceeded):
        append(_receipt(0.2), path=ledger)
    assert ledger.read_bytes() == before
    assert current_head(ledger) == first


def test_should_reject_an_oversized_or_non_utf8_final_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given malformed ledgers end in either a line outside the cap or invalid UTF-8
    oversized, binary = tmp_path / "oversized.jsonl", tmp_path / "binary.jsonl"
    oversized.write_bytes(b"x" * 40)
    binary.write_bytes(b"\xff\n")
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_LINE_BYTES", 32)
    # Then tail recovery rejects both with their typed, fail-closed causes
    with pytest.raises(LedgerLimitExceeded):
        append(_receipt(0.1), path=oversized)
    with pytest.raises(LedgerEntryMalformed, match="UTF-8"):
        append(_receipt(0.1), path=binary)


def test_should_bound_direct_tail_decoding_and_reject_a_blank_line() -> None:
    # The bounded decoder refuses both an over-cap line and a non-entry blank line
    with pytest.raises(LedgerLimitExceeded):
        _decode_entry_line(b"x" * (ledger_module.MAX_LEDGER_LINE_BYTES + 1))
    with pytest.raises(LedgerEntryMalformed, match="blank"):
        _decode_last_line(b"\n", truncated=False)


def test_should_reject_a_blank_tail_without_corrupting_the_chain(tmp_path: Path) -> None:
    # Given a valid chain is followed by more blank bytes than bounded tail recovery reads
    ledger = tmp_path / "ledger.jsonl"
    head = append(_receipt(0.1), path=ledger)
    with ledger.open("ab") as handle:
        handle.write(b"\n" * 70_000)
    before = ledger.read_bytes()
    # Then both full verification and O(1) append reject the same malformed format
    with pytest.raises(LedgerEntryMalformed, match="blank"):
        _verify(ledger, head)
    with pytest.raises(LedgerEntryMalformed, match="blank"):
        append(_receipt(0.2), path=ledger)
    # And a rejected append never resets the head or changes one byte of history
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("ending", [b"\n\n", b"\r\n", b""])
def test_should_reject_noncanonical_line_endings_before_append(
    tmp_path: Path, ending: bytes
) -> None:
    # Given a genuine entry ends in a blank line, CRLF, or an incomplete partial line
    ledger = tmp_path / "ledger.jsonl"
    append(_receipt(0.1), path=ledger)
    ledger.write_bytes(ledger.read_bytes()[:-1] + ending)
    before = ledger.read_bytes()
    # Then streaming read and tail recovery agree it is not canonical JSONL
    with pytest.raises(LedgerEntryMalformed):
        read_entries(ledger)
    with pytest.raises(LedgerEntryMalformed):
        append(_receipt(0.2), path=ledger)
    assert ledger.read_bytes() == before


def test_should_count_both_crlf_bytes_at_the_line_ceiling(tmp_path: Path) -> None:
    # Given a genuine entry is padded to 65,535 content bytes plus two CRLF bytes
    ledger = tmp_path / "ledger.jsonl"
    append(_receipt(0.1), path=ledger)
    content = ledger.read_bytes()[:-1]
    padding = b" " * (ledger_module.MAX_LEDGER_LINE_BYTES - 1 - len(content))
    ledger.write_bytes(content + padding + b"\r\n")
    before = ledger.read_bytes()
    assert len(before) == ledger_module.MAX_LEDGER_LINE_BYTES + 1
    # Then both readers count the actual encoded bytes and append changes nothing
    with pytest.raises(LedgerLimitExceeded):
        read_entries(ledger)
    with pytest.raises(LedgerLimitExceeded):
        append(_receipt(0.2), path=ledger)
    assert ledger.read_bytes() == before


def test_should_bound_streamed_lines_and_entry_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given either an oversized line or too many bounded entries
    oversized, crowded = tmp_path / "oversized.jsonl", tmp_path / "crowded.jsonl"
    oversized.write_text("x" * 40 + "\n", encoding="utf-8")
    _ledger_of(crowded, 0.1, 0.2)
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_LINE_BYTES", 32)
    with pytest.raises(LedgerLimitExceeded):
        read_entries(oversized)
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_LINE_BYTES", 64 * 1024)
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_ENTRIES", 1)
    with pytest.raises(LedgerLimitExceeded):
        read_entries(crowded)


def test_should_enforce_the_byte_cap_against_growth_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given one bounded entry and another writer that grows the opened file immediately
    ledger, addition = tmp_path / "ledger.jsonl", tmp_path / "addition.jsonl"
    _ledger_of(ledger, 0.1)
    _ledger_of(addition, 0.2)
    initial, extra = ledger.read_bytes(), addition.read_bytes()
    monkeypatch.setattr(ledger_module, "MAX_LEDGER_BYTES", len(initial) + 1)
    original = ledger_module._require_ledger_size

    def grow_after_open(size: int) -> None:
        original(size)
        with ledger.open("ab") as handle:
            handle.write(extra)

    monkeypatch.setattr(ledger_module, "_require_ledger_size", grow_after_open)
    with pytest.raises(LedgerLimitExceeded):
        read_entries(ledger)


def test_should_read_the_opened_inode_when_the_path_is_swapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given the path is atomically replaced only after read_entries has opened its inode
    ledger, replacement = tmp_path / "ledger.jsonl", tmp_path / "replacement.jsonl"
    _ledger_of(ledger, 0.1)
    _ledger_of(replacement, 0.9)
    original = ledger_module._require_ledger_size
    swapped = False

    def swap_after_open(size: int) -> None:
        nonlocal swapped
        original(size)
        if not swapped:
            os.replace(replacement, ledger)
            swapped = True

    monkeypatch.setattr(ledger_module, "_require_ledger_size", swap_after_open)
    opened = read_entries(ledger)
    assert ScoreReceipt.model_validate(opened[0].receipt).payload.score == 0.1
    assert read_all(ledger, ScoreReceipt)[0].payload.score == 0.9


def test_should_code_opened_descriptor_and_stream_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _ledger_of(ledger, 0.1)

    def refuse_metadata(_descriptor: int) -> os.stat_result:
        raise OSError("descriptor metadata unavailable")

    def refuse_read(_handle: object) -> list[object]:
        raise OSError("stream read failed")

    with monkeypatch.context() as patched:
        patched.setattr(ledger_module.stat, "S_ISREG", lambda mode: False)
        with pytest.raises(LedgerUnreadable):
            read_entries(ledger)
    with monkeypatch.context() as patched:
        patched.setattr(ledger_module.os, "fstat", refuse_metadata)
        with pytest.raises(LedgerUnreadable):
            read_entries(ledger)
    with monkeypatch.context() as patched:
        patched.setattr(ledger_module, "_read_bounded_entries", refuse_read)
        with pytest.raises(LedgerUnreadable):
            read_entries(ledger)


def test_should_refuse_to_replace_the_ledger_with_its_own_head(tmp_path: Path) -> None:
    # Given one path is mistakenly supplied as both append log and convenience pin
    ledger = tmp_path / "ledger.jsonl"
    # When the combined operation validates its two persistence boundaries
    with pytest.raises(AvowError) as caught:
        append_and_save_head(_receipt(0.1), path=ledger, head_path=ledger)
    # Then it fails before creating or replacing anything, with a stable coded cause
    assert caught.value.code == "avow.ledger_configuration_invalid"
    assert not ledger.exists()


def test_should_refuse_a_head_hard_linked_to_the_existing_ledger(tmp_path: Path) -> None:
    # Given two path spellings are hard links to the same existing ledger inode
    ledger, alias = tmp_path / "ledger.jsonl", tmp_path / "ledger.head"
    first = append(_receipt(0.1), path=ledger)
    os.link(ledger, alias)
    # When the combined operation checks the persistence boundary
    with pytest.raises(AvowError) as caught:
        append_and_save_head(_receipt(0.2), path=ledger, head_path=alias)
    # Then it refuses before either name changes and preserves the original history
    assert caught.value.code == "avow.ledger_configuration_invalid"
    assert current_head(ledger) == first
    assert current_head(alias) == first


def _filesystem_aliases(tmp_path: Path, first_name: str, second_name: str) -> bool:
    """Ask this test volume whether its directory rules collapse two absent names."""
    probe = tmp_path / first_name
    probe.touch()
    aliases = (tmp_path / second_name).exists()
    probe.unlink()
    return aliases


@pytest.mark.parametrize(
    ("ledger_name", "head_name"),
    [("ledger.jsonl", "LEDGER.JSONL"), ("café.jsonl", "cafe\u0301.jsonl")],
)
def test_should_refuse_absent_names_that_this_filesystem_aliases(
    tmp_path: Path, ledger_name: str, head_name: str
) -> None:
    # Given this volume treats two initially absent spellings as one directory entry
    if not _filesystem_aliases(tmp_path, ledger_name, head_name):
        pytest.skip("test volume keeps these names distinct")
    ledger, head = tmp_path / ledger_name, tmp_path / head_name
    # When combined persistence validates the two requested destinations
    with pytest.raises(AvowError) as caught:
        append_and_save_head(_receipt(0.1), path=ledger, head_path=head)
    # Then it refuses before creating either spelling, so no success can hide data loss
    assert caught.value.code == "avow.ledger_configuration_invalid"
    assert not ledger.exists()
    assert not head.exists()


def test_should_code_a_persistence_path_resolution_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given the filesystem refuses to resolve whether the two persistence paths alias
    def refuse_resolution(left: Path, right: Path) -> bool:
        raise OSError("path resolution unavailable")

    monkeypatch.setattr(Path, "samefile", refuse_resolution)
    # When combined persistence validates those paths, it fails closed and coded
    with pytest.raises(AvowError) as caught:
        append_and_save_head(
            _receipt(0.1), path=tmp_path / "ledger.jsonl", head_path=tmp_path / "ledger.head"
        )
    assert caught.value.code == "avow.ledger_configuration_invalid"


def test_should_code_an_absent_parent_identity_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given destination identity lookup reports absence, then its fallback cannot resolve
    def report_absent(left: Path, right: Path) -> bool:
        raise FileNotFoundError

    def refuse_exists(path: Path) -> bool:
        raise OSError("identity unavailable")

    monkeypatch.setattr(Path, "samefile", report_absent)
    monkeypatch.setattr(Path, "exists", refuse_exists)
    with pytest.raises(AvowError) as caught:
        append_and_save_head(
            _receipt(0.1), path=tmp_path / "ledger.jsonl", head_path=tmp_path / "ledger.head"
        )
    assert caught.value.code == "avow.ledger_configuration_invalid"


def test_should_resolve_two_absent_spellings_of_one_parent(tmp_path: Path) -> None:
    # Parent identity fallback is deterministic even before that directory exists
    assert _same_parent(tmp_path / "absent" / "a", tmp_path / "absent" / "b")


def test_should_survive_immediate_process_exit_after_append_returns(tmp_path: Path) -> None:
    # Given a child appends and exits without Python cleanup after append reports success
    ledger = tmp_path / "ledger.jsonl"
    worker = multiprocessing.get_context("spawn").Process(target=_append_then_exit, args=(ledger,))
    worker.start()
    worker.join(timeout=10)
    # Then the returned operation was already durable and forms a verifiable full line
    assert worker.exitcode == 0
    assert len(_verify(ledger, current_head(ledger))) == 1


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


def test_should_reject_a_ledger_whose_chain_link_was_rewritten(tmp_path: Path) -> None:
    # Given a 3-entry ledger whose MIDDLE entry has had its prev_hash rewritten and
    # nothing else touched. This is the one edit the other two pins cannot see: the last
    # entry is untouched, so the pinned head still matches on count AND hash, and
    # prev_hash lives outside the signed receipt, so every signature still verifies.
    path = tmp_path / "ledger.jsonl"
    head = _ledger_of(path, 0.1, 0.2, 0.3)
    lines = _lines(path)
    middle = json.loads(lines[1])
    middle["prev_hash"] = GENESIS_HASH
    _rewrite(path, [lines[0], json.dumps(middle), lines[2]])
    # Then the pinned head still matches this file exactly — the head pin really is
    # blind here, which is why the chain walk has to be its own check and not a
    # restatement of the head ...
    assert current_head(path) == head
    # ... and verification still fails, at the link, because the chain is walked entry by
    # entry from genesis rather than inferred from the last line. Without this case the
    # chain walk is defended only in depth: the splice test above passes on a build with
    # the link check deleted, because the head pin catches the extra entry first.
    with pytest.raises(LedgerIntegrityError, match="does not chain to the entry before it"):
        _verify(path, head)


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


def test_should_keep_old_pin_and_fail_closed_when_atomic_head_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a valid one-entry ledger and pin, and a filesystem that refuses replacement
    ledger = tmp_path / "ledger.jsonl"
    pin = tmp_path / "ledger.head"
    first = append_and_save_head(_receipt(0.1), path=ledger, head_path=pin)

    def refuse_replace(source: Path, target: Path) -> None:
        raise OSError("staged replacement failure")

    monkeypatch.setattr(os, "replace", refuse_replace)
    # When the next durable append cannot atomically replace the convenience pin
    with pytest.raises(LedgerHeadWriteFailed, match="ledger head"):
        append_and_save_head(_receipt(0.2), path=ledger, head_path=pin)
    # Then the old pin remains complete, temporary files are cleaned, and verification
    # fails closed against it instead of blessing a truncated version of the history
    assert read_head(pin) == first
    assert sorted(path.name for path in tmp_path.iterdir()) == ["ledger.head", "ledger.jsonl"]
    with pytest.raises(LedgerIntegrityError):
        _verify(ledger, read_head(pin))
    # Once the simulated fault clears, a later append still cannot absorb the unknown
    # durable entry into a fresh convenience pin.
    monkeypatch.undo()
    before = ledger.read_bytes(), pin.read_bytes()
    with pytest.raises(LedgerRecoveryRequired):
        append_and_save_head(_receipt(0.3), path=ledger, head_path=pin)
    assert (ledger.read_bytes(), pin.read_bytes()) == before


def test_should_refuse_to_absorb_an_unacknowledged_append_into_a_later_pin(
    tmp_path: Path,
) -> None:
    # Given one acknowledged append plus a crash-equivalent durable append whose head
    # was never saved, leaving the old convenience pin behind
    ledger, pin = tmp_path / "ledger.jsonl", tmp_path / "ledger.head"
    acknowledged = append_and_save_head(_receipt(0.1), path=ledger, head_path=pin)
    unknown = append(_receipt(0.2), path=ledger)
    assert acknowledged.count == 1
    assert unknown.count == 2
    before = ledger.read_bytes(), pin.read_bytes()
    # When a later combined append attempts to continue from that mismatch
    with pytest.raises(LedgerRecoveryRequired):
        append_and_save_head(_receipt(0.3), path=ledger, head_path=pin)
    # Then it requires investigation before writing and preserves both artifacts exactly
    assert (ledger.read_bytes(), pin.read_bytes()) == before
    assert read_head(pin) == acknowledged


@pytest.mark.parametrize("pin_state", ["missing", "malformed", "stale-empty"])
def test_should_require_recovery_when_a_nonempty_ledger_has_no_matching_pin(
    tmp_path: Path, pin_state: str
) -> None:
    ledger, pin = tmp_path / "ledger.jsonl", tmp_path / "ledger.head"
    append(_receipt(0.1), path=ledger)
    if pin_state == "malformed":
        pin.write_text("not a head", encoding="utf-8")
    elif pin_state == "stale-empty":
        save_head(EMPTY_HEAD, path=pin)
    before = ledger.read_bytes(), pin.read_bytes() if pin.exists() else None
    with pytest.raises(LedgerRecoveryRequired):
        append_and_save_head(_receipt(0.2), path=ledger, head_path=pin)
    assert (ledger.read_bytes(), pin.read_bytes() if pin.exists() else None) == before


def test_should_clean_staged_head_and_preserve_pin_when_file_sync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given one complete pin and a filesystem that refuses to sync its replacement
    pin = tmp_path / "ledger.head"
    save_head(EMPTY_HEAD, path=pin)

    def refuse_sync(descriptor: int) -> None:
        raise OSError("staged sync failure")

    monkeypatch.setattr(os, "fsync", refuse_sync)
    # When save attempts a new head, it reports a coded failure
    with pytest.raises(LedgerHeadWriteFailed, match="ledger head"):
        save_head(LedgerHead(count=1, head_hash="sha256:" + "ab" * 32), path=pin)
    # Then the previous pin is intact and no partial temporary file remains
    assert read_head(pin) == EMPTY_HEAD
    assert tuple(tmp_path.iterdir()) == (pin,)


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
