from __future__ import annotations

import pytest

from avow.canonical import canonical_bytes, content_hash
from avow.errors import CanonicalizationFailed


def test_should_be_key_order_independent_when_hashing() -> None:
    # Given two dicts with the same content but different key order
    a = {"b": 2, "a": 1, "nested": {"y": [1, 2], "x": True}}
    b = {"nested": {"x": True, "y": [1, 2]}, "a": 1, "b": 2}
    # When hashed
    # Then the canonical hashes are identical (JCS sorts keys)
    assert content_hash(a) == content_hash(b)
    assert content_hash(a).startswith("sha256:")


def test_should_change_hash_when_a_single_value_changes() -> None:
    # Given a payload and a one-byte-different payload
    base = {"score": 0.83, "n": 40}
    tampered = {"score": 0.84, "n": 40}
    # When hashed
    # Then the hashes differ
    assert content_hash(base) != content_hash(tampered)


def test_should_raise_canonicalization_failed_when_value_is_non_finite() -> None:
    # Given a payload with a value JCS cannot represent (NaN)
    payload = {"score": float("nan")}
    # When canonicalized
    # Then a typed CanonicalizationFailed is raised (fail-closed)
    with pytest.raises(CanonicalizationFailed):
        canonical_bytes(payload)


@pytest.mark.parametrize("value", [9007199254740992.0, -9007199254740992.0, 1e20])
def test_should_reject_integer_valued_float_outside_safe_domain(value: float) -> None:
    # Given an exactly integer-valued float outside JavaScript's safe domain
    # When canonicalized
    # Then the cross-language contract fails closed regardless of Python type
    with pytest.raises(CanonicalizationFailed):
        canonical_bytes(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (9007199254740991, b"9007199254740991"),
        (-9007199254740991, b"-9007199254740991"),
        (0.5, b"0.5"),
        (1e-7, b"1e-7"),
    ],
)
def test_should_accept_safe_endpoints_fraction_and_exponent(
    value: int | float, expected: bytes
) -> None:
    # Given a safe endpoint or ordinary finite non-integer value
    # When canonicalized
    # Then its RFC 8785 bytes are retained
    assert canonical_bytes(value) == expected
