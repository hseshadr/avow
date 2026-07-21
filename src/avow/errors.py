"""Coded envelope-error catalog. Every envelope failure raises a typed ``AvowError``
with a stable string ``code`` so callers (and any language binding) branch on cause
without string-matching messages. These are the *trust-envelope* codes; the scoring
face keeps its own ``assay.*`` catalog and the effect face its own."""

from __future__ import annotations

from typing import ClassVar


class AvowError(Exception):
    """Base class for every Avow envelope error."""

    code: ClassVar[str] = "avow.error"


class CanonicalizationFailed(AvowError):
    """Payload could not be canonicalized to RFC 8785 JCS bytes."""

    code: ClassVar[str] = "avow.canonicalization_failed"


class SignatureInvalid(AvowError):
    """Ed25519 signature does not match the payload (or the pinned key)."""

    code: ClassVar[str] = "avow.signature_invalid"


class ReplayMismatch(AvowError):
    """Recomputed content-hash does not match the receipt's stored hash."""

    code: ClassVar[str] = "avow.replay_mismatch"


class LedgerIntegrityError(AvowError):
    """A ledger entry's stored hash disagrees with its recomputed hash."""

    code: ClassVar[str] = "avow.ledger_integrity"


class LedgerUnreadable(AvowError):
    """The ledger is missing, is not a regular file, or cannot be read.

    Distinct from an *empty* ledger, which is a legitimate initial state. A ledger
    that could not be read answers nothing, so it must never be reported as intact."""

    code: ClassVar[str] = "avow.ledger_unreadable"


class LedgerEntryMalformed(AvowError):
    """A ledger line is not a parseable receipt of the expected type."""

    code: ClassVar[str] = "avow.ledger_entry_malformed"
