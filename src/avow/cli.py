"""Console adapter for Avow's existing evidence and ledger APIs."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Final

import typer
from click import ClickException
from nacl.signing import VerifyKey
from pydantic import TypeAdapter, ValidationError

from avow._atomic import atomic_write_bytes
from avow.canonical import JsonValue, canonical_bytes
from avow.envelope import SignedReceipt, sign_payload
from avow.errors import AvowError, LedgerHeadWriteFailed, LedgerRecoveryRequired
from avow.keys import _create_key_pair, load_signing_key, read_public_key
from avow.ledger import (
    append_and_save_head,
    read_head,
    require_distinct_paths,
    verify_ledger,
)
from avow.verify import verify_receipt

_ERROR_EXIT: Final[int] = 2
_RECOVERY_EXIT: Final[int] = 3
_PARSE_ERROR: Final[str] = "avow.command.invalid"
_RECOVERY_CODE: Final[str] = "avow.ledger_recovery_required"
_ERROR_STATUS: Final[tuple[tuple[type[BaseException], str, int], ...]] = (
    (LedgerHeadWriteFailed, _RECOVERY_CODE, _RECOVERY_EXIT),
    (LedgerRecoveryRequired, _RECOVERY_CODE, _RECOVERY_EXIT),
    (AvowError, "", _ERROR_EXIT),
    (ValidationError, "avow.input.invalid", _ERROR_EXIT),
    (ValueError, "avow.key.invalid", _ERROR_EXIT),
)
_PAYLOAD_ADAPTER: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


class JsonReceipt(SignedReceipt[JsonValue]):
    """Concrete generic receipt model for opaque CLI JSON objects."""


app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)
ledger_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)
app.add_typer(ledger_app, name="ledger")


def main() -> int:
    """Run Typer without automatic exception rendering at the privacy boundary."""
    try:
        result: object = app(standalone_mode=False)
    except ClickException:
        typer.echo(_PARSE_ERROR, err=True)
        return _ERROR_EXIT
    return result if isinstance(result, int) else 0


def _fail(code: str, exit_code: int = _ERROR_EXIT) -> None:
    """Emit only a stable code at the process boundary."""
    typer.echo(code, err=True)
    raise typer.Exit(exit_code)


def _error_status(error: BaseException) -> tuple[str, int]:
    """Classify one expected boundary error without rendering its details."""
    for error_type, code, exit_code in _ERROR_STATUS:
        if isinstance(error, error_type):
            domain_code = error.code if isinstance(error, AvowError) and not code else code
            return domain_code, exit_code
    return "avow.file.error", _ERROR_EXIT


def _run(operation: Callable[[], None], success_code: str) -> None:
    """Translate expected domain and boundary failures without disclosing inputs."""
    try:
        operation()
    except (AvowError, ValidationError, ValueError, OSError) as exc:
        _fail(*_error_status(exc))
    typer.echo(success_code)


def _public_path(private_path: Path) -> Path:
    """Derive the documented public-key companion path."""
    return Path(f"{private_path}.pub")


def _keygen(private_path: Path) -> None:
    """Create a no-overwrite private/public key pair."""
    public_path = _public_path(private_path)
    require_distinct_paths((private_path, public_path))
    _create_key_pair(private_path=private_path, public_path=public_path)


@app.command()
def keygen(out: Annotated[Path, typer.Option("--out")]) -> None:
    """Generate an Ed25519 private key and its ``.pub`` companion."""
    _run(lambda: _keygen(out), "avow.keygen.ok")


def _read_payload(path: Path) -> JsonValue:
    """Validate one JSON value without exposing rejected bytes."""
    return _PAYLOAD_ADAPTER.validate_json(path.read_bytes())


def _read_receipt(path: Path) -> JsonReceipt:
    """Validate one generic receipt without interpreting its payload."""
    return JsonReceipt.model_validate_json(path.read_bytes())


def _receipt_bytes(receipt: SignedReceipt[JsonValue]) -> bytes:
    """Encode a receipt canonically for stable, atomic output."""
    return canonical_bytes(receipt.model_dump(mode="json")) + b"\n"


def _sign(payload_path: Path, key_path: Path, output_path: Path) -> None:
    """Sign opaque JSON and atomically install the complete receipt."""
    require_distinct_paths((payload_path, key_path, output_path))
    payload = _read_payload(payload_path)
    receipt = sign_payload(payload, load_signing_key(key_path))
    atomic_write_bytes(_receipt_bytes(receipt), path=output_path)


@app.command()
def sign(
    payload: Annotated[Path, typer.Option("--payload")],
    key: Annotated[Path, typer.Option("--key")],
    out: Annotated[Path, typer.Option("--out")],
) -> None:
    """Sign an arbitrary JSON value into a receipt."""
    _run(lambda: _sign(payload, key, out), "avow.sign.ok")


def _validated_public_key(path: Path) -> str:
    """Read and validate a pinned Ed25519 public key."""
    encoded = read_public_key(path)
    VerifyKey(bytes.fromhex(encoded))
    return encoded


def _verify(receipt_path: Path, key_path: Path) -> None:
    """Verify one receipt against a separately pinned signer."""
    require_distinct_paths((receipt_path, key_path))
    receipt = _read_receipt(receipt_path)
    verify_receipt(receipt, expected_public_key=_validated_public_key(key_path))


@app.command()
def verify(
    receipt: Annotated[Path, typer.Option("--receipt")],
    public_key: Annotated[Path, typer.Option("--public-key")],
) -> None:
    """Verify a receipt offline against a pinned public key."""
    _run(lambda: _verify(receipt, public_key), "avow.verify.ok")


def _append(receipt_path: Path, ledger_path: Path, head_path: Path) -> None:
    """Append one receipt through the existing locked ledger transaction."""
    require_distinct_paths((receipt_path, ledger_path, head_path))
    receipt = _read_receipt(receipt_path)
    append_and_save_head(receipt, path=ledger_path, head_path=head_path)


@ledger_app.command("append")
def ledger_append(
    receipt: Annotated[Path, typer.Option("--receipt")],
    ledger: Annotated[Path, typer.Option("--ledger")],
    head: Annotated[Path, typer.Option("--head")],
) -> None:
    """Append a receipt and durably advance its convenience head."""
    _run(lambda: _append(receipt, ledger, head), "avow.ledger.append.ok")


def _verify_ledger(ledger_path: Path, head_path: Path, key_path: Path) -> None:
    """Verify a complete ledger against independently supplied pins."""
    require_distinct_paths((ledger_path, head_path, key_path))
    expected_head = read_head(head_path)
    expected_key = _validated_public_key(key_path)
    verify_ledger(
        ledger_path,
        JsonReceipt,
        expected_public_key=expected_key,
        expected_head=expected_head,
    )


@ledger_app.command("verify")
def ledger_verify(
    ledger: Annotated[Path, typer.Option("--ledger")],
    head: Annotated[Path, typer.Option("--head")],
    public_key: Annotated[Path, typer.Option("--public-key")],
) -> None:
    """Verify every receipt and link against the pinned signer and head."""
    _run(lambda: _verify_ledger(ledger, head, public_key), "avow.ledger.verify.ok")
