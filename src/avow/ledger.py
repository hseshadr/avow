"""Append-only, content-addressed receipt ledger (JSONL), subject-agnostic.

Each line is one ``SignedReceipt`` of some subject ``S``; its identity is the
``payload_hash``. Appending never rewrites history. ``verify_integrity`` re-derives
each payload's hash and fails closed if a stored hash disagrees — so on-disk tampering
is detectable without the signing key.

Reading needs the concrete receipt type to deserialize into (``SignedReceipt[S]``),
so ``read_all`` / ``verify_integrity`` take it as an argument. The score face passes
``ScoreReceipt``; other faces pass their own parametrization.

Reads fail CLOSED. A ledger that is missing, is not a regular file, cannot be read, or
holds an unparseable line raises a coded error rather than reading as "no entries" —
otherwise a mistyped path would silently report a clean bill of health for a file
nobody ever opened. An *existing but empty* ledger is the one benign case: it is a
legitimate initial state and verifies as zero entries."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, ValidationError

from avow.envelope import SignedReceipt, payload_digest
from avow.errors import LedgerEntryMalformed, LedgerIntegrityError, LedgerUnreadable


def append[S: BaseModel](receipt: SignedReceipt[S], *, path: Path) -> None:
    """Append one receipt as a JSON line."""
    with path.open("a", encoding="utf-8") as handle:
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


def verify_integrity[S: BaseModel](
    path: Path, receipt_type: type[SignedReceipt[S]]
) -> tuple[SignedReceipt[S], ...]:
    """Return all receipts, raising if any stored hash disagrees with its content."""
    receipts = read_all(path, receipt_type)
    for receipt in receipts:
        if payload_digest(receipt.payload) != receipt.payload_hash:
            raise LedgerIntegrityError(f"tampered ledger entry: {receipt.payload_hash}")
    return receipts
