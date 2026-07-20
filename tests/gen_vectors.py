"""Generate the cross-language golden vectors.

Run:  uv run python tests/gen_vectors.py

Emits two deterministic files replayed byte-for-byte by both the Python kernel tests
(``tests/test_vectors.py``) and P1's TypeScript ``@edgeproc/avow`` conformance suite:

* ``testdata/vectors/canonical.json`` — RFC 8785 canonical bytes + ``sha256:`` hashes
  for a payload set that deliberately stresses the number-serialization hazard
  (0.5, 0.1, 1e21, -0.0, 1e-7), unicode, key-order, nesting, and primitives.
* ``testdata/vectors/receipts.json`` — receipts signed with a FIXED, TEST-ONLY seed
  (``b"\\x01" * 32`` — non-secret, published on purpose) so a TS signer with the same
  seed reproduces byte-identical signatures (Ed25519 is deterministic).
"""

from __future__ import annotations

import json
from pathlib import Path

from nacl.signing import SigningKey
from pydantic import BaseModel, ConfigDict

from avow import canonical_bytes, content_hash, public_key_hex, sign_payload
from avow.canonical import JsonValue

_VECTORS_DIR = Path(__file__).resolve().parent.parent / "testdata" / "vectors"
# NON-SECRET, TEST-ONLY seed. Published deliberately so any language binding can
# reproduce byte-identical signatures. Never used to sign anything real.
_TEST_SEED = b"\x01" * 32


class _Subject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: str
    score: float
    tags: tuple[str, ...]


def _canonical_payloads() -> dict[str, JsonValue]:
    return {
        "empty_object": {},
        "key_shuffle": {"b": 2, "a": 1, "c": 3},
        "unicode": {"text": "hélloé"},
        "floats": {"half": 0.5, "tenth": 0.1, "big": 1e21, "neg_zero": -0.0, "tiny": 1e-7},
        "ints": {"zero": 0, "neg": -42, "big": 1000000},
        "nested": {"arr": [1, [2, 3], {"k": "v"}], "obj": {"x": {"y": [True, False, None]}}},
        "primitives": {"t": True, "f": False, "n": None},
        "array_top": [1, 2, 3, "a", None],
        "string_top": "just a string",
    }


def _canonical_vector(name: str, payload: JsonValue) -> dict[str, JsonValue]:
    return {
        "name": name,
        "payload": payload,
        "canonical_hex": canonical_bytes(payload).hex(),
        "content_hash": content_hash(payload),
    }


def _receipt_subjects() -> tuple[_Subject, ...]:
    return (
        _Subject(kind="score", score=0.5, tags=("a", "b")),
        _Subject(kind="effect", score=0.1, tags=()),
        _Subject(kind="edge", score=1e-7, tags=("x",)),
    )


def _receipt_vector(subject: _Subject) -> dict[str, object]:
    key = SigningKey(_TEST_SEED)
    receipt = sign_payload(subject, key)
    return {
        "payload": subject.model_dump(mode="json"),
        "payload_hash": receipt.payload_hash,
        "signature": receipt.signature,
    }


def _write(name: str, data: object) -> None:
    path = _VECTORS_DIR / name
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path}")


def main() -> int:
    _VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    canonical = [_canonical_vector(name, p) for name, p in _canonical_payloads().items()]
    _write("canonical.json", canonical)
    key = SigningKey(_TEST_SEED)
    receipts = {
        "seed_hex": _TEST_SEED.hex(),
        "public_key": public_key_hex(key),
        "receipts": [_receipt_vector(s) for s in _receipt_subjects()],
    }
    _write("receipts.json", receipts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
