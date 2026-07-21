"""Avow: the shared trust envelope — one signed receipt, many subjects.

Avow signs and verifies the *canonical JSON of a frozen subject model* under a pinned
Ed25519 key, knowing nothing about what the subject means. The scoring face (``assay``)
and the effect face (``writ``) both import this envelope; Avow imports neither. Base
dependencies only: ``pydantic``, ``pydantic-settings``, ``pynacl``, ``rfc8785``."""

from __future__ import annotations

from avow._version import __version__
from avow.canonical import canonical_bytes, content_hash
from avow.envelope import (
    SignedReceipt,
    payload_digest,
    sign_payload,
    verify_signature,
)
from avow.keys import (
    generate_signing_key,
    load_signing_key,
    public_key_hex,
    read_public_key,
    save_public_key,
    save_signing_key,
)
from avow.ledger import append, read_all, verify_integrity
from avow.verify import verify_receipt

__all__ = [
    "SignedReceipt",
    "__version__",
    "append",
    "canonical_bytes",
    "content_hash",
    "generate_signing_key",
    "load_signing_key",
    "payload_digest",
    "public_key_hex",
    "read_all",
    "read_public_key",
    "save_public_key",
    "save_signing_key",
    "sign_payload",
    "verify_integrity",
    "verify_receipt",
    "verify_signature",
]
