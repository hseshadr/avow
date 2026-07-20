"""Deterministic serialization + content hashing.

RFC 8785 (JCS) gives a byte-stable canonical form for any JSON value: keys are
sorted, numbers use shortest round-trip encoding. Two payloads that are equal as
JSON produce identical bytes — and therefore an identical content-hash — which is
what makes a receipt reproducible and tamper-evident."""

from __future__ import annotations

import hashlib

import rfc8785

from avow.errors import CanonicalizationFailed

# A JSON object genuinely has runtime string keys at this I/O boundary; this is
# the one place a str-keyed mapping is a value, not a record.
type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]


def canonical_bytes(payload: JsonValue) -> bytes:
    """Return the RFC 8785 JCS canonical bytes for ``payload``."""
    try:
        encoded: bytes = rfc8785.dumps(payload)
    except (ValueError, TypeError) as exc:
        raise CanonicalizationFailed(str(exc)) from exc
    return encoded


def content_hash(payload: JsonValue) -> str:
    """Return ``"sha256:<hex>"`` over the canonical bytes of ``payload``."""
    digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return f"sha256:{digest}"
