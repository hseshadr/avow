"""The envelope is importable from ``avow`` with zero scoring-face deps loaded.

These tests pin the P0 packaging invariant: ``avow`` is the shared trust envelope
and imports nothing from the scoring face (``assay``), the effect face (``writ``),
or the heavy scientific stack. Later phases import the exact names asserted here."""

from __future__ import annotations

import importlib
import sys


def test_avow_exports_envelope() -> None:
    # Given the envelope package
    # When its public surface is imported
    from avow import (  # noqa: PLC0415
        SignedReceipt,
        canonical_bytes,
        content_hash,
        generate_signing_key,
        payload_digest,
        public_key_hex,
        sign_payload,
        verify_signature,
    )

    # Then every name every later phase pins is present and callable
    assert SignedReceipt is not None
    assert callable(sign_payload)
    assert callable(verify_signature)
    assert callable(payload_digest)
    assert callable(canonical_bytes)
    assert callable(content_hash)
    assert callable(generate_signing_key)
    assert callable(public_key_hex)


def test_avow_import_pulls_neither_sklearn_nor_the_scoring_faces() -> None:
    # Given a clean module table for the heavy stack and the faces
    for mod in [m for m in sys.modules if m.startswith(("sklearn", "scipy", "assay", "writ"))]:
        del sys.modules[mod]
    # When avow is imported fresh
    import avow  # noqa: PLC0415

    importlib.reload(avow)
    # Then importing the envelope loads no sklearn/scipy and no score/effect face
    assert not any(m.startswith(("sklearn", "scipy")) for m in sys.modules)
    assert not any(m == "assay" or m.startswith("assay.") for m in sys.modules)
    assert not any(m == "writ" or m.startswith("writ.") for m in sys.modules)


def test_score_receipt_roundtrip_unchanged() -> None:
    # Given the envelope primitives and the score face's subject
    from assay.receipt import ReceiptPayload  # noqa: PLC0415
    from avow import (  # noqa: PLC0415
        generate_signing_key,
        public_key_hex,
        sign_payload,
        verify_signature,
    )

    key = generate_signing_key()
    payload = ReceiptPayload(
        assay_version="0",
        metric="f1",
        metric_version="1",
        inputs_hash="sha256:0",
        score=0.5,
    )
    # When a score payload is signed and verified through the shared envelope
    receipt = sign_payload(payload, key)
    # Then it verifies under its pinned signer (behavior unchanged by the split)
    assert verify_signature(receipt, expected_public_key=public_key_hex(key)) is None
    # ...and the round trip preserved the subject rather than merely not raising
    assert receipt.payload == payload
    assert receipt.public_key == public_key_hex(key)
