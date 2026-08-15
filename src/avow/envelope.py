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

import copy
from collections.abc import Mapping
from typing import Final, Literal, overload

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from avow.canonical import JsonValue, canonical_bytes, content_hash
from avow.errors import (
    PayloadHashMismatch,
    ReceiptSchemaMismatch,
    SignatureBytesInvalid,
    SignerMismatch,
    SubjectInvalid,
    SubjectNotFrozen,
)


type Subject = BaseModel | JsonValue
type SubjectInput = BaseModel | JsonValue | Mapping[str, JsonValue]
_JSON_ADAPTER: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
RECEIPT_SCHEMA: Final = "avow.receipt/v1"
_SIGNED_FIELDS: Final = frozenset({"payload", "payload_hash", "public_key", "signature"})


class SignedReceipt[SubjectT: Subject](BaseModel):
    """A signed subject: the subject plus its content-hash, public key and signature.

    The envelope is generic over ``SubjectT`` and never inspects subject fields. It
    signs canonical JSON, so unrelated applications share the same receipt contract."""

    model_config = ConfigDict(frozen=True, extra="forbid", serialize_by_alias=True)

    receipt_schema: Literal["avow.receipt/v1"] = Field(alias="schema")
    payload: SubjectT
    payload_hash: str
    public_key: str
    signature: str

    @model_validator(mode="before")
    @classmethod
    def require_supported_schema(cls, value: object) -> object:
        """Reject legacy or unknown envelopes before validating signed fields."""
        if not isinstance(value, Mapping):
            return value
        if value.keys() >= _SIGNED_FIELDS and value.get("schema") != RECEIPT_SCHEMA:
            raise ReceiptSchemaMismatch("receipt schema is missing or unsupported")
        return value


def _require_frozen(payload: BaseModel) -> None:
    """Reject models whose fields may be rebound after sealing."""
    if payload.model_config.get("frozen") is not True:
        raise SubjectNotFrozen("Pydantic subjects must set model_config frozen=True")


def _validated_json(payload: object) -> JsonValue:
    """Validate and detach one value in the closed JSON data model."""
    candidate = dict(payload) if isinstance(payload, Mapping) else payload
    try:
        validated = _JSON_ADAPTER.validate_python(candidate, strict=True)
    except ValidationError as exc:
        raise SubjectInvalid("subject must contain only JSON-compatible values") from exc
    return copy.deepcopy(validated)


def _subject_json(payload: SubjectInput) -> JsonValue:
    """Convert either supported subject boundary to canonicalizable JSON."""
    if isinstance(payload, BaseModel):
        _require_frozen(payload)
        return _validated_json(payload.model_dump(mode="json"))
    return _validated_json(payload)


def _snapshot_subject(payload: SubjectInput) -> tuple[Subject, JsonValue]:
    """Detach validated state, then derive its one canonical JSON snapshot."""
    if isinstance(payload, BaseModel):
        _require_frozen(payload)
        stored_model = payload.model_copy(deep=True)
        snapshot = _validated_json(stored_model.model_dump(mode="json"))
        return stored_model, snapshot
    snapshot = _validated_json(payload)
    return snapshot, snapshot


def payload_digest(payload: SubjectInput) -> str:
    """Content-hash of a canonical subject (any frozen model)."""
    return content_hash(_subject_json(payload))


def _seal_snapshot(
    payload: Subject, snapshot: JsonValue, signing_key: SigningKey
) -> SignedReceipt[Subject]:
    """Derive one receipt entirely from a detached canonical snapshot."""
    message = canonical_bytes(snapshot)
    signature = signing_key.sign(message).signature
    return SignedReceipt(
        schema=RECEIPT_SCHEMA,
        payload=payload,
        payload_hash=content_hash(snapshot),
        public_key=bytes(signing_key.verify_key).hex(),
        signature=signature.hex(),
    )


@overload
def sign_payload[SubjectT: BaseModel](
    payload: SubjectT, signing_key: SigningKey
) -> SignedReceipt[SubjectT]: ...


@overload
def sign_payload(
    payload: JsonValue | Mapping[str, JsonValue], signing_key: SigningKey
) -> SignedReceipt[JsonValue]: ...


def sign_payload(  # type: ignore[misc]  # overloaded generic receipt is invariant
    payload: SubjectInput, signing_key: SigningKey
) -> SignedReceipt[Subject]:
    """Hash and Ed25519-sign any frozen subject into a verifiable receipt."""
    stored, snapshot = _snapshot_subject(payload)
    return _seal_snapshot(stored, snapshot, signing_key)


def _check_hash[SubjectT: Subject](receipt: SignedReceipt[SubjectT]) -> None:
    if payload_digest(receipt.payload) != receipt.payload_hash:
        raise PayloadHashMismatch("payload hash does not match payload content")


def _require_receipt_schema(receipt: object) -> None:
    if getattr(receipt, "receipt_schema", None) != RECEIPT_SCHEMA:
        raise ReceiptSchemaMismatch("receipt schema is missing or unsupported")


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
    _require_receipt_schema(receipt)
    _check_hash(receipt)
    _require_signer(receipt, expected_public_key)
    message = canonical_bytes(_subject_json(receipt.payload))
    _check_signature_bytes(message, receipt.signature, expected_public_key)
