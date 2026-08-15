from __future__ import annotations

import fcntl
import json
import os
import subprocess
from importlib.metadata import version
from pathlib import Path

import pytest
from test_cli import _build_and_install
from typer.testing import CliRunner

import avow.ledger as ledger_module
from avow.cli import app
from avow.errors import LedgerHeadWriteFailed
from avow.ledger import EMPTY_HEAD, save_head

_SENTINEL = "harish.private@example.invalid"
_TYPER_FLOOR = "typer==0.16.0"
_RUNNER = CliRunner()


@pytest.fixture(scope="module")
def installed_avow(tmp_path_factory: pytest.TempPathFactory) -> Path:
    requirement = f"typer=={version('typer')}"
    return _build_and_install(tmp_path_factory.mktemp("private-installed-avow"), requirement)


@pytest.fixture(scope="module")
def floor_avow(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("typer-floor-installed-avow")
    return _build_and_install(path, _TYPER_FLOOR)


@pytest.fixture(params=("installed_avow", "floor_avow"))
def supported_avow(request: pytest.FixtureRequest) -> Path:
    return request.getfixturevalue(request.param)


def _run(command: Path, cwd: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(command), *arguments], cwd=cwd, check=False, capture_output=True, text=True
    )


def _assert_success(result: subprocess.CompletedProcess[str], code: str) -> None:
    assert (result.returncode, result.stdout, result.stderr) == (0, f"{code}\n", "")


def _assert_error(result: subprocess.CompletedProcess[str], code: str) -> None:
    assert (result.returncode, result.stdout, result.stderr) == (2, "", f"{code}\n")
    assert _SENTINEL not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def _raise_head_write_failure(*args: object, **kwargs: object) -> None:
    raise LedgerHeadWriteFailed(_SENTINEL)


def _assert_recovery(result: object) -> None:
    assert result.exit_code == 3
    assert result.stdout == ""
    assert result.stderr == "avow.ledger_recovery_required\n"


def _assert_process_recovery(result: subprocess.CompletedProcess[str]) -> None:
    assert (result.returncode, result.stdout, result.stderr) == (
        3,
        "",
        "avow.ledger_recovery_required\n",
    )


def _prepare_old_head(path: Path, exists: bool) -> bytes | None:
    if exists:
        save_head(EMPTY_HEAD, path=path)
    return path.read_bytes() if path.exists() else None


def _invoke_failed_head_install(monkeypatch: pytest.MonkeyPatch) -> tuple[object, bytes]:
    original = ledger_module.save_head
    monkeypatch.setattr(ledger_module, "save_head", _raise_head_write_failure)
    result = _RUNNER.invoke(app, list(_run_append_args("receipt.json")))
    monkeypatch.setattr(ledger_module, "save_head", original)
    return result, Path("evidence.jsonl").read_bytes()


def test_should_import_with_supported_typer_floor(floor_avow: Path, tmp_path: Path) -> None:
    # Given the wheel installed with its declared Typer lower bound
    # When Python imports the console adapter in that clean environment
    result = _run(floor_avow.parent / "python", tmp_path, "-c", "import avow.cli")
    # Then the supported dependency floor imports without private-module failures
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


@pytest.mark.parametrize(
    "arguments",
    [
        ("keygen", f"--{_SENTINEL}"),
        (_SENTINEL,),
        ("sign", "--payload", _SENTINEL, "--key"),
    ],
)
def test_should_redact_parser_failures_from_supported_installed_command(
    supported_avow: Path, tmp_path: Path, arguments: tuple[str, ...]
) -> None:
    # Given a malformed command line carrying a private sentinel
    # When each supported clean-installed console script parses it
    result = _run(supported_avow, tmp_path, *arguments)
    # Then only one stable code is rendered, without usage or private arguments
    _assert_error(result, "avow.command.invalid")
    assert "Usage" not in result.stderr


def _keygen(command: Path, directory: Path) -> None:
    result = _run(command, directory, "keygen", "--out", "signing.key")
    _assert_success(result, "avow.keygen.ok")


def _sign(command: Path, directory: Path, payload: str, receipt: str) -> None:
    result = _run(
        command, directory, "sign", "--payload", payload, "--key", "signing.key", "--out", receipt
    )
    _assert_success(result, "avow.sign.ok")


def _append(command: Path, directory: Path, receipt: str = "receipt.json") -> None:
    result = _run_append(command, directory, receipt)
    _assert_success(result, "avow.ledger.append.ok")


def _signed_evidence(command: Path, directory: Path) -> None:
    (directory / "payload.json").write_text('{"evidence":"safe"}\n', encoding="utf-8")
    _keygen(command, directory)
    _sign(command, directory, "payload.json", "receipt.json")


def _ledger_verify(command: Path, directory: Path) -> subprocess.CompletedProcess[str]:
    return _run(
        command,
        directory,
        "ledger",
        "verify",
        "--ledger",
        "evidence.jsonl",
        "--head",
        "evidence.head",
        "--public-key",
        "signing.key.pub",
    )


def _run_sign(
    command: Path,
    directory: Path,
    *,
    key: str,
    out: str,
    payload: str = "payload.json",
) -> subprocess.CompletedProcess[str]:
    return _run(command, directory, "sign", "--payload", payload, "--key", key, "--out", out)


def _run_verify(command: Path, directory: Path) -> subprocess.CompletedProcess[str]:
    return _run(
        command,
        directory,
        "verify",
        "--receipt",
        "receipt.json",
        "--public-key",
        "signing.key.pub",
    )


def _run_append(command: Path, directory: Path, receipt: str) -> subprocess.CompletedProcess[str]:
    return _run(
        command,
        directory,
        "ledger",
        "append",
        "--receipt",
        receipt,
        "--ledger",
        "evidence.jsonl",
        "--head",
        "evidence.head",
    )


def test_should_redact_hostile_json_from_command_failure(
    installed_avow: Path, tmp_path: Path
) -> None:
    # Given malformed evidence containing a private sentinel
    payload, output = tmp_path / "hostile.json", tmp_path / "receipt.json"
    payload.write_text(f'{{"email":"{_SENTINEL}"', encoding="utf-8")
    # When signing parses the payload before touching its output
    result = _run_sign(
        installed_avow, tmp_path, payload=payload.name, key="missing.key", out=output.name
    )
    # Then only a stable code leaves the boundary and no partial receipt exists
    _assert_error(result, "avow.input.invalid")
    assert not output.exists()


@pytest.mark.parametrize("aliased_role", ["key", "out"])
def test_should_reject_exact_input_alias_before_writing(
    installed_avow: Path, tmp_path: Path, aliased_role: str
) -> None:
    # Given a signing role is exactly the payload path
    _signed_evidence(installed_avow, tmp_path)
    output = tmp_path / "second.json"
    key = "payload.json" if aliased_role == "key" else "signing.key"
    out = "payload.json" if aliased_role == "out" else output.name
    before = (tmp_path / "payload.json").read_bytes()
    # When the aliased command is attempted
    result = _run_sign(installed_avow, tmp_path, key=key, out=out)
    # Then configuration fails before any input or output is changed
    _assert_error(result, "avow.ledger_configuration_invalid")
    assert (tmp_path / "payload.json").read_bytes() == before
    assert not output.exists()


@pytest.mark.parametrize("alias_kind", ["symlink", "link"])
def test_should_reject_filesystem_output_alias_before_writing(
    installed_avow: Path, tmp_path: Path, alias_kind: str
) -> None:
    # Given the output resolves to the input through a filesystem alias
    _signed_evidence(installed_avow, tmp_path)
    payload, alias = tmp_path / "payload.json", tmp_path / "alias.json"
    getattr(os, alias_kind)(payload, alias)
    before = payload.read_bytes()
    # When signing is attempted through the aliased output path
    result = _run_sign(installed_avow, tmp_path, key="signing.key", out=alias.name)
    # Then neither inode is changed and no private content leaves the process
    _assert_error(result, "avow.ledger_configuration_invalid")
    assert payload.read_bytes() == alias.read_bytes() == before


def test_should_leave_no_partial_receipt_when_output_is_unwritable(
    installed_avow: Path, tmp_path: Path
) -> None:
    # Given valid evidence and an unwritable destination directory
    _signed_evidence(installed_avow, tmp_path)
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    # When atomic receipt staging cannot create its temporary file
    result = _run_sign(installed_avow, tmp_path, key="signing.key", out="locked/out.json")
    # Then only the file code is returned and no stage or output survives
    _assert_error(result, "avow.file.error")
    assert tuple(locked.iterdir()) == ()


def test_should_reject_invalid_private_key_without_partial_output(
    installed_avow: Path, tmp_path: Path
) -> None:
    # Given a malformed private-key file containing a private sentinel
    (tmp_path / "payload.json").write_text('{"safe":true}\n', encoding="utf-8")
    (tmp_path / "bad.key").write_text(_SENTINEL, encoding="utf-8")
    # When signing attempts to load it
    result = _run_sign(installed_avow, tmp_path, key="bad.key", out="receipt.json")
    # Then the key fails closed without a receipt or disclosed bytes
    _assert_error(result, "avow.key.invalid")
    assert not (tmp_path / "receipt.json").exists()


def test_should_reject_invalid_public_key_without_disclosure(
    installed_avow: Path, tmp_path: Path
) -> None:
    # Given a valid receipt and a malformed pinned-key file
    _signed_evidence(installed_avow, tmp_path)
    (tmp_path / "bad.pub").write_text(_SENTINEL, encoding="utf-8")
    # When verification loads the malformed trust anchor
    result = _run(
        installed_avow, tmp_path, "verify", "--receipt", "receipt.json", "--public-key", "bad.pub"
    )
    # Then it reports only the stable key code
    _assert_error(result, "avow.key.invalid")


def test_should_fail_closed_when_pinned_head_is_missing(
    installed_avow: Path, tmp_path: Path
) -> None:
    # Given a valid ledger whose external head is missing
    _signed_evidence(installed_avow, tmp_path)
    _append(installed_avow, tmp_path)
    (tmp_path / "evidence.head").unlink()
    # When ledger verification has no truncation anchor
    result = _ledger_verify(installed_avow, tmp_path)
    # Then it returns the precise coded failure without a traceback
    _assert_error(result, "avow.ledger_head_unreadable")


def test_should_report_tampered_receipt_without_payload_disclosure(
    installed_avow: Path, tmp_path: Path
) -> None:
    # Given a receipt whose payload was changed after signing
    _signed_evidence(installed_avow, tmp_path)
    receipt_path = tmp_path / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["payload"] = {"email": _SENTINEL}
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    # When the modified receipt is verified
    result = _run_verify(installed_avow, tmp_path)
    # Then tampering has its domain code and the payload stays private
    _assert_error(result, "avow.payload_hash_mismatch")


def _stale_head_ledger(command: Path, directory: Path) -> bytes:
    _signed_evidence(command, directory)
    _append(command, directory)
    stale = (directory / "evidence.head").read_bytes()
    (directory / "payload-2.json").write_text('{"evidence":"second"}\n', encoding="utf-8")
    _sign(command, directory, "payload-2.json", "receipt-2.json")
    _append(command, directory, "receipt-2.json")
    (directory / "evidence.head").write_bytes(stale)
    return (directory / "evidence.jsonl").read_bytes()


def test_should_reject_stale_head_during_verification(installed_avow: Path, tmp_path: Path) -> None:
    # Given a ledger whose pin was rolled back to an earlier valid head
    _stale_head_ledger(installed_avow, tmp_path)
    # When its complete chain is checked against the stale pin
    result = _ledger_verify(installed_avow, tmp_path)
    # Then truncation ambiguity fails closed under the integrity code
    _assert_error(result, "avow.ledger_integrity")


def test_should_not_append_when_saved_head_is_stale(installed_avow: Path, tmp_path: Path) -> None:
    # Given a valid ledger whose convenience pin is stale
    before = _stale_head_ledger(installed_avow, tmp_path)
    # When another CLI append attempts to absorb the unacknowledged tail
    result = _run_append(installed_avow, tmp_path, "receipt.json")
    # Then recovery is required and the legacy ledger bytes are untouched
    _assert_process_recovery(result)
    assert (tmp_path / "evidence.jsonl").read_bytes() == before


def test_should_honour_legacy_ledger_file_lock(installed_avow: Path, tmp_path: Path) -> None:
    # Given the data file is locked by a legacy-compatible writer
    _signed_evidence(installed_avow, tmp_path)
    _append(installed_avow, tmp_path)
    ledger = tmp_path / "evidence.jsonl"
    before = ledger.read_bytes()
    with ledger.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        # When the CLI appends through the same data-file lock protocol
        result = _run_append(installed_avow, tmp_path, "receipt.json")
    # Then it times out with a stable code and changes no history
    _assert_error(result, "avow.ledger_lock_timeout")
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("existing_head", [False, True])
def test_should_surface_recovery_after_durable_append_when_head_write_fails(
    installed_avow: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing_head: bool,
) -> None:
    # Given valid evidence and a missing or empty old pin
    _signed_evidence(installed_avow, tmp_path)
    head = tmp_path / "evidence.head"
    old_head = _prepare_old_head(head, existing_head)
    monkeypatch.chdir(tmp_path)
    # When the real append commits but head installation fails
    first, advanced = _invoke_failed_head_install(monkeypatch)
    ledger = Path("evidence.jsonl")
    second = _RUNNER.invoke(app, list(_run_append_args("receipt.json")))
    # Then both calls require recovery and the second preserves the durable history
    _assert_recovery(first)
    _assert_recovery(second)
    assert advanced and ledger.read_bytes() == advanced
    assert (head.read_bytes() if head.exists() else None) == old_head


def _run_append_args(receipt: str) -> tuple[str, ...]:
    return (
        "ledger",
        "append",
        "--receipt",
        receipt,
        "--ledger",
        "evidence.jsonl",
        "--head",
        "evidence.head",
    )
