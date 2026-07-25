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
from avow.errors import ReplayMismatch, SignatureBytesInvalid, SignerMismatch


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
        raise ReplayMismatch("payload hash does not match payload content")


def verify_signature[SubjectT: BaseModel](
    receipt: SignedReceipt[SubjectT], *, expected_public_key: str
) -> None:
    """Verify a receipt against a **pinned** signer key.

    Authenticity requires knowing *whose* signature to trust. The receipt's own
    ``public_key`` field lives outside the signed payload, so a re-signed forgery
    can swap in the attacker's key and pass a bare signature check. We therefore
    reject — independent of the signature — any receipt whose embedded key is not
    the ``expected_public_key`` the caller pinned out-of-band, then recompute the
    hash and verify the detached Ed25519 signature under that pinned key."""
    _check_hash(receipt)
    # Hex is case-insensitive, so pin by value, not by spelling: a lowercase embedded key
    # and an uppercase pinned key are the SAME signer and must not read as a mismatch.
    if receipt.public_key.lower() != expected_public_key.lower():
        # Provenance failure, coded apart from a bytes failure: this receipt was signed
        # by a key the caller does not trust, so its signature is never even checked.
        raise SignerMismatch("receipt public key is not the expected signer")
    message = canonical_bytes(receipt.payload.model_dump(mode="json"))
    # Malformed / wrong-length hex (bytes.fromhex, VerifyKey) raises ValueError; a
    # bad signature raises BadSignatureError. Both are tamper failures, so we fail
    # closed with a coded error rather than leaking a raw traceback.
    try:
        verify_key = VerifyKey(bytes.fromhex(expected_public_key))
        verify_key.verify(message, bytes.fromhex(receipt.signature))
    except (ValueError, BadSignatureError) as exc:
        raise SignatureBytesInvalid("signature does not match payload") from exc
