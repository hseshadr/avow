"""Generate the cross-language golden vectors.

Run:  uv run python tests/gen_vectors.py

Emits three deterministic files replayed byte-for-byte by both the Python kernel tests
(``tests/test_vectors.py``) and P1's TypeScript ``@edgeproc/avow`` conformance suite:

* ``testdata/vectors/canonical.json`` — RFC 8785 canonical bytes + ``sha256:`` hashes
  for a payload set that deliberately stresses the number-serialization hazard
  (0.5, 0.1, 1e21, -0.0, 1e-7), unicode, key-order, nesting, and primitives.
* ``testdata/vectors/receipts.json`` — receipts signed with a FIXED, TEST-ONLY seed
  (``b"\\x01" * 32`` — non-secret, published on purpose) so a TS signer with the same
  seed reproduces byte-identical signatures (Ed25519 is deterministic).
* ``testdata/vectors/invalid.json`` — values both kernels must reject rather than
  silently canonicalize differently.
"""

from __future__ import annotations

import json
from pathlib import Path

from nacl.signing import SigningKey

from avow import canonical_bytes, content_hash, public_key_hex, sign_payload
from avow.canonical import JsonValue

_VECTORS_DIR = Path(__file__).resolve().parent.parent / "testdata" / "vectors"
# NON-SECRET, TEST-ONLY seed. Published deliberately so any language binding can
# reproduce byte-identical signatures. Never used to sign anything real.
_TEST_SEED = b"\x01" * 32


def _float_payload() -> dict[str, JsonValue]:
    return {
        "half": 0.5,
        "tenth": 0.1,
        "big": 1e21,
        "neg_zero": -0.0,
        "tiny": 1e-7,
    }


def _nested_payload() -> dict[str, JsonValue]:
    return {
        "arr": [1, [2, 3], {"k": "v"}],
        "obj": {"x": {"y": [True, False, None]}},
    }


def _canonical_payloads() -> dict[str, JsonValue]:
    objects: dict[str, JsonValue] = {
        "empty_object": {},
        "key_shuffle": {"b": 2, "a": 1, "c": 3},
        "unicode": {"text": "hélloé"},
        "floats": _float_payload(),
        "ints": {"zero": 0, "neg": -42, "big": 1000000},
        "nested": _nested_payload(),
        "primitives": {"t": True, "f": False, "n": None},
    }
    top_level: dict[str, JsonValue] = {
        "array_top": [1, 2, 3, "a", None],
        "string_top": "just a string",
        "unicode_pair_top": "😀",
        "number_top": 42.5,
        "boolean_top": True,
        "null_top": None,
    }
    return objects | top_level


def _canonical_vector(name: str, payload: JsonValue) -> dict[str, JsonValue]:
    return {
        "name": name,
        "payload": payload,
        "canonical_hex": canonical_bytes(payload).hex(),
        "content_hash": content_hash(payload),
    }


def _receipt_subjects() -> tuple[JsonValue, ...]:
    return (
        {"kind": "score", "score": 0.5, "tags": ["a", "b"]},
        {"kind": "effect", "score": 0.1, "tags": []},
        {"kind": "edge", "score": 1e-7, "tags": ["x"]},
        [1, "two", None],
        "sealed evidence",
        42.5,
        True,
        None,
    )


def _receipt_vector(subject: JsonValue) -> dict[str, JsonValue]:
    key = SigningKey(_TEST_SEED)
    receipt = sign_payload(subject, key)
    return {
        "payload": receipt.payload,
        "payload_hash": receipt.payload_hash,
        "signature": receipt.signature,
    }


def _invalid_payloads() -> dict[str, JsonValue]:
    return {
        "unsafe_integer": 9007199254740992,
        "lone_high_surrogate": "\ud800",
        "lone_low_surrogate": "\udc00",
        "nested_lone_surrogate": {"bad": "\ud800"},
    }


def _write(name: str, data: object, *, ensure_ascii: bool = False) -> None:
    path = _VECTORS_DIR / name
    encoded = json.dumps(data, indent=2, ensure_ascii=ensure_ascii) + "\n"
    path.write_text(encoded, encoding="utf-8")


def _receipt_document() -> dict[str, JsonValue]:
    key = SigningKey(_TEST_SEED)
    return {
        "seed_hex": _TEST_SEED.hex(),
        "public_key": public_key_hex(key),
        "receipts": [_receipt_vector(subject) for subject in _receipt_subjects()],
    }


def _invalid_vectors() -> list[dict[str, JsonValue]]:
    return [{"name": name, "payload": payload} for name, payload in _invalid_payloads().items()]


def main() -> int:
    _VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    canonical = [
        _canonical_vector(name, payload) for name, payload in _canonical_payloads().items()
    ]
    _write("canonical.json", canonical)
    _write("receipts.json", _receipt_document())
    _write("invalid.json", _invalid_vectors(), ensure_ascii=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
