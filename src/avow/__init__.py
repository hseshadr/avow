"""Avow: sign opaque JSON evidence and verify it offline.

Avow canonicalizes subjects, binds them to Ed25519 signatures, and verifies receipts
against caller-pinned public keys without interpreting the subject's fields."""

from __future__ import annotations

from avow._version import __version__
from avow.canonical import canonical_bytes, content_hash
from avow.envelope import (
    RECEIPT_SCHEMA,
    SignedReceipt,
    payload_digest,
    sign_payload,
    verify_signature,
)
from avow.errors import ReceiptSchemaMismatch
from avow.keys import (
    generate_signing_key,
    load_signing_key,
    public_key_hex,
    read_public_key,
    save_public_key,
    save_signing_key,
)
from avow.ledger import (
    EMPTY_HEAD,
    LedgerEntry,
    LedgerHead,
    append,
    append_and_save_head,
    current_head,
    entry_hash,
    read_all,
    read_entries,
    read_head,
    save_head,
    verify_ledger,
    verify_integrity,
)
from avow.verify import verify_receipt

__all__ = [
    "EMPTY_HEAD",
    "RECEIPT_SCHEMA",
    "LedgerEntry",
    "LedgerHead",
    "ReceiptSchemaMismatch",
    "SignedReceipt",
    "__version__",
    "append",
    "append_and_save_head",
    "canonical_bytes",
    "content_hash",
    "current_head",
    "entry_hash",
    "generate_signing_key",
    "load_signing_key",
    "payload_digest",
    "public_key_hex",
    "read_all",
    "read_entries",
    "read_head",
    "read_public_key",
    "save_head",
    "save_public_key",
    "save_signing_key",
    "sign_payload",
    "verify_integrity",
    "verify_ledger",
    "verify_receipt",
    "verify_signature",
]
