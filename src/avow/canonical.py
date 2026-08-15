"""Deterministic serialization + content hashing.

RFC 8785 (JCS) gives a byte-stable canonical form for any JSON value: keys are
sorted, numbers use shortest round-trip encoding. Two payloads that are equal as
JSON produce identical bytes — and therefore an identical content-hash — which is
what makes a receipt reproducible and tamper-evident."""

from __future__ import annotations

import hashlib
import math

import rfc8785

from avow.errors import CanonicalizationFailed

# A JSON object genuinely has runtime string keys at this I/O boundary; this is
# the one place a str-keyed mapping is a value, not a record.
type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
_MAX_SAFE_INTEGER = (1 << 53) - 1


def _validate_string(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("input contains non-UTF-8 codepoints") from exc


def _validate_number(value: int | float) -> None:
    if isinstance(value, int):
        valid = abs(value) <= _MAX_SAFE_INTEGER
    else:
        valid = math.isfinite(value) and (not value.is_integer() or abs(value) <= _MAX_SAFE_INTEGER)
    if not valid:
        raise ValueError("number is outside the interoperable JSON domain")


def _validate_list(value: list[JsonValue]) -> None:
    for item in value:
        _validate_json_value(item)


def _validate_object(value: dict[str, JsonValue]) -> None:
    for key, item in value.items():
        _validate_string(key)
        _validate_json_value(item)


def _validate_scalar(value: str | int | float | bool) -> None:
    if isinstance(value, str):
        _validate_string(value)
    elif not isinstance(value, bool):
        _validate_number(value)


def _validate_collection(value: list[JsonValue] | dict[str, JsonValue]) -> None:
    if isinstance(value, list):
        _validate_list(value)
    else:
        _validate_object(value)


def _validate_json_value(value: JsonValue) -> None:
    if value is None:
        return
    if isinstance(value, (str, int, float, bool)):
        _validate_scalar(value)
        return
    _validate_collection(value)


def canonical_bytes(payload: JsonValue) -> bytes:
    """Return the RFC 8785 JCS canonical bytes for ``payload``."""
    try:
        _validate_json_value(payload)
        encoded: bytes = rfc8785.dumps(payload)
    except (ValueError, TypeError) as exc:
        raise CanonicalizationFailed(str(exc)) from exc
    return encoded


def content_hash(payload: JsonValue) -> str:
    """Return ``"sha256:<hex>"`` over the canonical bytes of ``payload``."""
    digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return f"sha256:{digest}"
