"""Append-only, content-addressed receipt ledger (JSONL), subject-agnostic.

Each line is one ``SignedReceipt`` of some subject ``S``; its identity is the
``payload_hash``. Appending never rewrites history. ``verify_integrity`` re-derives
each payload's hash and fails closed if a stored hash disagrees — so on-disk tampering
is detectable without the signing key.

Reading needs the concrete receipt type to deserialize into (``SignedReceipt[S]``),
so ``read_all`` / ``verify_integrity`` take it as an argument. The score face passes
``ScoreReceipt``; other faces pass their own parametrization."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from avow.envelope import SignedReceipt, payload_digest
from avow.errors import LedgerIntegrityError


def append[S: BaseModel](receipt: SignedReceipt[S], *, path: Path) -> None:
    """Append one receipt as a JSON line."""
    with path.open("a", encoding="utf-8") as handle:
        handle.write(receipt.model_dump_json() + "\n")


def read_all[S: BaseModel](
    path: Path, receipt_type: type[SignedReceipt[S]]
) -> tuple[SignedReceipt[S], ...]:
    """Read every receipt from the ledger (empty if the file is absent)."""
    if not path.exists():
        return ()
    lines = path.read_text(encoding="utf-8").splitlines()
    return tuple(receipt_type.model_validate_json(line) for line in lines if line.strip())


def verify_integrity[S: BaseModel](
    path: Path, receipt_type: type[SignedReceipt[S]]
) -> tuple[SignedReceipt[S], ...]:
    """Return all receipts, raising if any stored hash disagrees with its content."""
    receipts = read_all(path, receipt_type)
    for receipt in receipts:
        if payload_digest(receipt.payload) != receipt.payload_hash:
            raise LedgerIntegrityError(f"tampered ledger entry: {receipt.payload_hash}")
    return receipts
