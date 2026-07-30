"""Content-addressed receipt ledger (JSONL) of independently signed entries, subject-agnostic.

Each line is one ``SignedReceipt`` of some subject ``S``; its identity is the
``payload_hash``. Writes are ``O_APPEND`` under a lock, so appending never rewrites
history. ``verify_integrity`` re-derives each payload's hash AND verifies its Ed25519
signature against a pinned public key, failing closed on the first disagreement — so
on-disk tampering *within an entry* is detectable with the signer's *public* key alone,
never the secret signing key. A hash-only check would be fooled by an adversary who edits
a payload and recomputes its (public) content hash; the detached signature is the thing
they cannot forge without the private seed.

KNOWN GAP — this ledger is NOT append-only in the tamper-evident sense. Entries are not
chained: there is no ``prev_hash``, sequence number, or root anywhere here. The audit
therefore proves "every line I was shown is genuine" and NEVER "these are the lines, in
this order, and all of them". Deleting, truncating (including to empty), reordering,
replaying, and splicing in a same-signer entry from another ledger all pass. This is
disclosed in the README's "Honest limits" and pinned by strict-``xfail`` tests in
``tests/test_ledger.py``; the fix is a hash chain with the head pinned out-of-band.

Reading needs the concrete receipt type to deserialize into (``SignedReceipt[S]``),
so ``read_all`` / ``verify_integrity`` take it as an argument. The score face passes
``ScoreReceipt``; other faces pass their own parametrization.

Reads fail CLOSED. A ledger that is missing, is not a regular file, cannot be read, or
holds an unparseable line raises a coded error rather than reading as "no entries" —
otherwise a mistyped path would silently report a clean bill of health for a file
nobody ever opened. An *existing but empty* ledger verifies as zero entries: it is a
legitimate initial state, and — per the gap above — one this cannot distinguish from a
ledger truncated to nothing."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

from pydantic import BaseModel, ValidationError

from avow.envelope import SignedReceipt, payload_digest
from avow.errors import (
    LedgerEntryMalformed,
    LedgerIntegrityError,
    LedgerUnreadable,
    SignatureInvalid,
)
from avow.verify import verify_receipt


def append[S: BaseModel](receipt: SignedReceipt[S], *, path: Path) -> None:
    """Append one receipt as a JSON line.

    Opened ``"a"`` (``O_APPEND`` — every write lands at end-of-file) under an exclusive
    advisory lock, so two concurrent appenders can never interleave a half-written line."""
    with path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write(receipt.model_dump_json() + "\n")


def _require_readable_file(path: Path) -> None:
    """Fail closed unless ``path`` is a regular file this process can read.

    ``is_file()`` rejects both the absent path and the directory-in-its-place case;
    the access check rejects a file whose permissions deny reading."""
    if not path.is_file():
        raise LedgerUnreadable(f"ledger is not a readable file: {path}")
    if not os.access(path, os.R_OK):
        raise LedgerUnreadable(f"ledger cannot be read (permission denied): {path}")


def _parse_entry[S: BaseModel](line: str, receipt_type: type[SignedReceipt[S]]) -> SignedReceipt[S]:
    """Parse one ledger line, reporting a coded cause instead of a parse traceback."""
    try:
        return receipt_type.model_validate_json(line)
    except ValidationError as exc:
        raise LedgerEntryMalformed(f"ledger entry is not a valid receipt: {exc}") from exc


def read_all[S: BaseModel](
    path: Path, receipt_type: type[SignedReceipt[S]]
) -> tuple[SignedReceipt[S], ...]:
    """Read every receipt from the ledger, failing closed if it cannot be read."""
    _require_readable_file(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    return tuple(_parse_entry(line, receipt_type) for line in lines if line.strip())


def _verify_entry[S: BaseModel](receipt: SignedReceipt[S], expected_public_key: str) -> None:
    """Fail closed unless the entry's hash matches AND its signature verifies under the
    pinned key. The hash pre-check names the corrupted entry; the signature check is what
    stops an adversary who recomputed the hash from laundering a forged payload through."""
    if payload_digest(receipt.payload) != receipt.payload_hash:
        raise LedgerIntegrityError(f"tampered ledger entry: {receipt.payload_hash}")
    try:
        verify_receipt(receipt, expected_public_key=expected_public_key)
    except SignatureInvalid as exc:
        raise LedgerIntegrityError(f"tampered ledger entry: {receipt.payload_hash}") from exc


def verify_integrity[S: BaseModel](
    path: Path, receipt_type: type[SignedReceipt[S]], *, expected_public_key: str
) -> tuple[SignedReceipt[S], ...]:
    """Return all receipts, raising if any entry fails hash OR signature verification.

    ``expected_public_key`` is the signer's public key, pinned out-of-band (the ``.pub``
    from ``keygen``) — never read from an entry, whose embedded key an attacker could
    swap. Verifying signatures, not just hashes, is what makes tamper-evidence real."""
    receipts = read_all(path, receipt_type)
    for receipt in receipts:
        _verify_entry(receipt, expected_public_key)
    return receipts
