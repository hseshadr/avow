"""The signed-receipt envelope: schema + Ed25519 sign/verify, subject-agnostic.

The envelope signs the *canonical JSON of a frozen subject model* without ever
inspecting the subject's fields. Because the signed content is a pure function of the
subject — no timestamps — identical subjects yield an identical payload-hash and (Ed25519
being deterministic) an identical signature. Verification recomputes the hash (catching
tampered content) and checks the detached signature under a **pinned** key (catching a
forged or swapped key).

``sign_payload`` and ``verify_signature`` operate on a generic ``SignedReceipt``. The
subject may be a frozen Pydantic model or a JSON-compatible mapping; the envelope never
branches on its keys or meaning."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict

from avow.canonical import JsonValue, canonical_bytes, content_hash
from avow.errors import PayloadHashMismatch, SignatureBytesInvalid, SignerMismatch


type Subject = BaseModel | Mapping[str, JsonValue]


class SignedReceipt[SubjectT: Subject](BaseModel):
    """A signed subject: the subject plus its content-hash, public key and signature.

    The envelope is generic over ``SubjectT`` and never inspects subject fields. It
    signs canonical JSON, so unrelated applications share the same receipt contract."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    payload: SubjectT
    payload_hash: str
    public_key: str
    signature: str


def _subject_json(payload: Subject) -> JsonValue:
    """Convert either supported subject boundary to canonicalizable JSON."""
    if isinstance(payload, BaseModel):
        return cast(JsonValue, payload.model_dump(mode="json"))
    return dict(payload)


def payload_digest(payload: Subject) -> str:
    """Content-hash of a canonical subject (any frozen model)."""
    return content_hash(_subject_json(payload))


def sign_payload[SubjectT: Subject](
    payload: SubjectT, signing_key: SigningKey
) -> SignedReceipt[SubjectT]:
    """Hash and Ed25519-sign any frozen subject into a verifiable receipt."""
    message = canonical_bytes(_subject_json(payload))
    signature = signing_key.sign(message).signature
    return SignedReceipt(
        payload=payload,
        payload_hash=payload_digest(payload),
        public_key=bytes(signing_key.verify_key).hex(),
        signature=signature.hex(),
    )


def _check_hash[SubjectT: Subject](receipt: SignedReceipt[SubjectT]) -> None:
    if payload_digest(receipt.payload) != receipt.payload_hash:
        raise PayloadHashMismatch("payload hash does not match payload content")


def _require_signer[SubjectT: Subject](
    receipt: SignedReceipt[SubjectT], expected_public_key: str
) -> None:
    """Require the caller-pinned signer, comparing hex by value."""
    if receipt.public_key.lower() != expected_public_key.lower():
        raise SignerMismatch("receipt public key is not the expected signer")


def _check_signature_bytes(message: bytes, signature: str, public_key: str) -> None:
    """Translate malformed or invalid signature bytes to one coded failure."""
    try:
        verifier = VerifyKey(bytes.fromhex(public_key))
        verifier.verify(message, bytes.fromhex(signature))
    except (ValueError, BadSignatureError) as exc:
        raise SignatureBytesInvalid("signature does not match payload") from exc


def verify_signature[SubjectT: Subject](
    receipt: SignedReceipt[SubjectT], *, expected_public_key: str
) -> None:
    """Verify content and signer against a caller-pinned key, without freshness.

    The receipt's embedded key is not trusted. Replay defence requires external state;
    see ``docs/OPERATIONS.md`` for the complete boundary."""
    _check_hash(receipt)
    _require_signer(receipt, expected_public_key)
    message = canonical_bytes(_subject_json(receipt.payload))
    _check_signature_bytes(message, receipt.signature, expected_public_key)
