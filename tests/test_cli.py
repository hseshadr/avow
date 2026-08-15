from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from avow.cli import app

type Command = tuple[tuple[str, ...], str]

_WORKFLOW: tuple[Command, ...] = (
    (("keygen", "--out", "signing.key"), "avow.keygen.ok"),
    (
        (
            "sign",
            "--payload",
            "evidence.json",
            "--key",
            "signing.key",
            "--out",
            "receipt.json",
        ),
        "avow.sign.ok",
    ),
    (
        ("verify", "--receipt", "receipt.json", "--public-key", "signing.key.pub"),
        "avow.verify.ok",
    ),
    (
        (
            "ledger",
            "append",
            "--receipt",
            "receipt.json",
            "--ledger",
            "evidence.jsonl",
            "--head",
            "evidence.head",
        ),
        "avow.ledger.append.ok",
    ),
    (
        (
            "ledger",
            "verify",
            "--ledger",
            "evidence.jsonl",
            "--head",
            "evidence.head",
            "--public-key",
            "signing.key.pub",
        ),
        "avow.ledger.verify.ok",
    ),
)
_ARTIFACTS = {
    "evidence.head",
    "evidence.json",
    "evidence.jsonl",
    "receipt.json",
    "signing.key",
    "signing.key.pub",
}
_RUNNER = CliRunner()


def _run_checked(arguments: list[str]) -> None:
    subprocess.run(arguments, check=True, capture_output=True, text=True)


def _build_wheel(output_dir: Path) -> Path:
    _run_checked(["uv", "build", "--wheel", "--out-dir", str(output_dir)])
    wheels = tuple(output_dir.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _create_environment(path: Path) -> Path:
    _run_checked(["uv", "venv", "--python", sys.executable, str(path)])
    return path / "bin/python"


def _install_wheel(python: Path, wheel: Path) -> None:
    _run_checked(["uv", "pip", "install", "--python", str(python), str(wheel)])


def _build_and_install(tmp_path: Path) -> Path:
    wheel = _build_wheel(tmp_path / "wheel")
    python = _create_environment(tmp_path / "environment")
    _install_wheel(python, wheel)
    return python.parent / "avow"


@pytest.fixture(scope="module")
def installed_avow(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _build_and_install(tmp_path_factory.mktemp("installed-avow"))


def _run(command: Path, cwd: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(command), *arguments], cwd=cwd, check=False, capture_output=True, text=True
    )


def _assert_success(result: subprocess.CompletedProcess[str], code: str) -> None:
    assert (result.returncode, result.stdout, result.stderr) == (0, f"{code}\n", "")


def _run_workflow(command: Path, directory: Path) -> None:
    for arguments, code in _WORKFLOW:
        _assert_success(_run(command, directory, *arguments), code)


def _invoke_workflow() -> None:
    for arguments, code in _WORKFLOW:
        result = _RUNNER.invoke(app, list(arguments))
        assert (result.exit_code, result.stdout, result.stderr) == (0, f"{code}\n", "")


def _assert_invocation_error(arguments: list[str], code: str) -> None:
    result = _RUNNER.invoke(app, arguments)
    assert (result.exit_code, result.stdout, result.stderr) == (2, "", f"{code}\n")


def _exercise_boundary_errors() -> None:
    sign = ["sign", "--payload", "payload.json", "--key", "key", "--out", "out"]
    _assert_invocation_error(sign, "avow.input.invalid")
    Path("payload.json").write_text("{}", encoding="utf-8")
    _assert_invocation_error(sign, "avow.file.error")
    Path("key").write_bytes(b"bad")
    _assert_invocation_error(sign, "avow.key.invalid")
    sign[-1] = "payload.json"
    _assert_invocation_error(sign, "avow.ledger_configuration_invalid")


def _entry_points(wheel: Path) -> str:
    with zipfile.ZipFile(wheel) as archive:
        path = next(name for name in archive.namelist() if name.endswith("entry_points.txt"))
        return archive.read(path).decode()


def test_should_run_complete_evidence_workflow_through_installed_command(
    installed_avow: Path, tmp_path: Path
) -> None:
    # Given arbitrary JSON evidence in a clean directory
    (tmp_path / "evidence.json").write_text('{"kind":"deployment","sequence":7}\n')
    # When each documented command is invoked through the installed console script
    _run_workflow(installed_avow, tmp_path)
    # Then every complete requested artifact exists and no hidden artifact remains
    assert {path.name for path in tmp_path.iterdir()} == _ARTIFACTS


def test_should_ship_only_avow_console_entry_point(tmp_path: Path) -> None:
    # Given the built standalone wheel
    wheel = _build_wheel(tmp_path / "wheel")
    # When its console entry-point metadata is inspected
    metadata = _entry_points(wheel)
    # Then Avow owns its command and does not install Assay's command
    assert metadata == "[console_scripts]\navow = avow.cli:app\n"


def test_should_route_workflow_through_thin_typer_adapter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Given arbitrary JSON evidence at the in-process command boundary
    monkeypatch.chdir(tmp_path)
    Path("evidence.json").write_text('{"kind":"policy"}\n', encoding="utf-8")
    # When every public route delegates to the existing domain operations
    _invoke_workflow()
    # Then the same complete artifact contract is preserved
    assert {path.name for path in tmp_path.iterdir()} == _ARTIFACTS


def test_should_translate_expected_boundary_failures_without_details(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Given malformed input, a missing file, a bad key, and aliased roles
    monkeypatch.chdir(tmp_path)
    Path("payload.json").write_text('{"private":', encoding="utf-8")
    # When each expected failure crosses the Typer boundary
    _exercise_boundary_errors()
    # Then domain failures also remain stable codes without exception text
    assert not Path("out").exists()
