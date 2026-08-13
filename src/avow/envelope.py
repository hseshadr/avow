"""The signed-receipt envelope: schema + Ed25519 sign/verify, subject-agnostic.

The envelope signs the *canonical JSON of a frozen subject model* without ever
inspecting the subject's fields. Because the signed content is a pure function of the
subject — no timestamps — identical subjects yield an identical payload-hash and (Ed25519
being deterministic) an identical signature. Verification recomputes the hash (catching
tampered content) and checks the detached signature under a **pinned** key (catching a
forged or swapped key).

Unification (literal, not aspirational): ``sign_payload`` / ``verify_signature`` /
``payload_digest`` are typed over ``SubjectT`` bound to ``BaseModel`` and produce /
consume a generic ``SignedReceipt[SubjectT]``. The *score* face (``assay``) supplies a
scoring subject; the *effect* face (``writ``) supplies an effect subject; both reuse this
exact hash-sign-verify seam with zero type changes — only the subject differs, never the
envelope. This module is the shared trust boundary and knows nothing of either face."""

from __future__ import annotations

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict

from avow.canonical import canonical_bytes, content_hash
from avow.errors import PayloadHashMismatch, SignatureBytesInvalid, SignerMismatch


class SignedReceipt[SubjectT: BaseModel](BaseModel):
    """A signed subject: the subject plus its content-hash, public key and signature.

    The envelope is generic over ``SubjectT`` (bound to ``BaseModel``) and never
    inspects the subject's fields — it signs the subject's canonical JSON — so it is
    agnostic to what the subject carries. The score face parametrizes it with a scoring
    subject and the effect face with an effect subject; the subject bound is the literal
    "one envelope, many subjects" unification claim."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    payload: SubjectT
    payload_hash: str
    public_key: str
    signature: str


def payload_digest(payload: BaseModel) -> str:
    """Content-hash of a canonical subject (any frozen model)."""
    return content_hash(payload.model_dump(mode="json"))


def sign_payload[SubjectT: BaseModel](
    payload: SubjectT, signing_key: SigningKey
) -> SignedReceipt[SubjectT]:
    """Hash and Ed25519-sign any frozen subject into a verifiable receipt."""
    message = canonical_bytes(payload.model_dump(mode="json"))
    signature = signing_key.sign(message).signature
    return SignedReceipt(
        payload=payload,
        payload_hash=payload_digest(payload),
        public_key=bytes(signing_key.verify_key).hex(),
        signature=signature.hex(),
    )


def _check_hash[SubjectT: BaseModel](receipt: SignedReceipt[SubjectT]) -> None:
    if payload_digest(receipt.payload) != receipt.payload_hash:
        raise PayloadHashMismatch("payload hash does not match payload content")


def _require_signer[SubjectT: BaseModel](
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


def verify_signature[SubjectT: BaseModel](
    receipt: SignedReceipt[SubjectT], *, expected_public_key: str
) -> None:
    """Verify content and signer against a caller-pinned key, without freshness.

    The receipt's embedded key is not trusted. Replay defence requires external state;
    see ``docs/OPERATIONS.md`` for the complete boundary."""
    _check_hash(receipt)
    _require_signer(receipt, expected_public_key)
    message = canonical_bytes(receipt.payload.model_dump(mode="json"))
    _check_signature_bytes(message, receipt.signature, expected_public_key)
