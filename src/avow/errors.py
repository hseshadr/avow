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
    """A receipt failed to verify under the pinned signer.

    The base of two security-distinct causes below. Catch this to mean "did not
    verify, for any reason"; catch a subclass to distinguish *who signed it* from
    *whether the bytes check out*."""

    code: ClassVar[str] = "avow.signature_invalid"


class SignerMismatch(SignatureInvalid):
    """The receipt's embedded key is not the signer the caller pinned.

    A PROVENANCE failure: someone signed this with a key you do not trust. The
    signature is never even checked, because there is no reason to trust it. Coded
    distinctly so a caller can alert on "wrong signer" without parsing a message."""

    code: ClassVar[str] = "avow.signer_mismatch"


class SignatureBytesInvalid(SignatureInvalid):
    """The signer matched, but the Ed25519 check rejected the signature bytes.

    A TAMPER failure: the payload or the signature was altered. This is the case
    ``avow.signature_invalid`` has always named, so it keeps that published code —
    only the provenance case above gets a new one."""


class PayloadHashMismatch(AvowError):
    """Recomputed content-hash does not match the receipt's stored hash.

    A TAMPER failure: the payload was edited behind an untouched hash field.

    Deliberately **not** called "replay". The envelope detects no replay at all — a
    validly-signed receipt presented a second time is byte-identical to its first
    presentation and verifies exactly as it did then. Naming this error after a property
    the envelope does not have would be a claim it cannot keep. Replay of a *recorded*
    entry is caught by the ledger chain (``avow.ledger_integrity``), never here."""

    code: ClassVar[str] = "avow.payload_hash_mismatch"


# Deprecated alias, kept for one minor so `except ReplayMismatch:` written against 0.2.x
# keeps working. The `code` it carries is now `avow.payload_hash_mismatch`; a caller that
# branches on the old string must be updated. Removed in 0.4.0.
ReplayMismatch = PayloadHashMismatch


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


class LedgerHeadUnreadable(AvowError):
    """The pinned chain head is missing or unparseable.

    The head is a verifier *input*, like the pinned public key. Without it there is
    nothing to check the ledger's end against, so this fails closed rather than
    falling back to the head the file computes for itself."""

    code: ClassVar[str] = "avow.ledger_head_unreadable"


class LedgerLockTimeout(AvowError):
    """The ledger could not obtain its process lock before the public deadline."""

    code: ClassVar[str] = "avow.ledger_lock_timeout"


class LedgerConfigurationInvalid(AvowError):
    """Ledger paths or lock bounds cannot satisfy the persistence contract."""

    code: ClassVar[str] = "avow.ledger_configuration_invalid"


class LedgerLimitExceeded(AvowError):
    """A ledger exceeded its supported byte, entry, or line-size boundary."""

    code: ClassVar[str] = "avow.ledger_limit_exceeded"


class LedgerHeadWriteFailed(AvowError):
    """A complete pinned head could not be durably installed."""

    code: ClassVar[str] = "avow.ledger_head_write_failed"
