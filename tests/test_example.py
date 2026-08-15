from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

_EXPECTED_SCHEMA = "avow.receipt/v1"
_EXPECTED_OUTPUT = (
    "Receipt schema: avow.receipt/v1\n"
    "Original receipt: avow.verify.ok\n"
    "Altered receipt: avow.payload_hash_mismatch (expected)\n"
)


def _run_checked(arguments: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(arguments, cwd=cwd, check=True, capture_output=True, text=True)


def _installed_wheel(tmp_path: Path) -> Path:
    wheel_dir = tmp_path / "wheel"
    _run_checked(["uv", "build", "--wheel", "--out-dir", str(wheel_dir)])
    wheel = next(wheel_dir.glob("*.whl"))
    environment = tmp_path / "environment"
    _run_checked(["uv", "venv", "--python", "3.13", str(environment)])
    _run_checked(["uv", "pip", "install", "--python", str(environment / "bin/python"), str(wheel)])
    return environment


def _run(command: Path, directory: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(command), *arguments],
        cwd=directory,
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_verification(
    command: Path, directory: Path, receipt: str, expected: tuple[int, str, str]
) -> None:
    result = _run(
        command,
        directory,
        "verify",
        "--receipt",
        receipt,
        "--public-key",
        "signing.key.pub",
    )
    assert (result.returncode, result.stdout, result.stderr) == expected


def _example_environment(environment: Path, artifacts: Path) -> dict[str, str]:
    return dict(os.environ) | {
        "AVOW_DEMO_DIR": str(artifacts),
        "PATH": f"{environment / 'bin'}:{os.environ['PATH']}",
    }


def _run_example(example: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "run_evidence_loop.sh"],
        cwd=example,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_should_run_evidence_loop_from_only_examples_and_installed_wheel(tmp_path: Path) -> None:
    # Given a clean Python 3.13 wheel install outside the repository
    environment = _installed_wheel(tmp_path)
    example, artifacts = tmp_path / "outside-repository", tmp_path / "artifacts"
    shutil.copytree("examples", example)
    # When the copied example runs against only that installed wheel
    result = _run_example(example, _example_environment(environment, artifacts))
    # Then output and independent verification prove both branches
    assert (result.returncode, result.stdout, result.stderr) == (0, _EXPECTED_OUTPUT, "")
    _assert_example_artifacts(environment / "bin/avow", artifacts)


def test_should_prefer_checkout_over_unrelated_avow_on_path(tmp_path: Path) -> None:
    # Given a hostile avow command earlier on PATH beside the source checkout
    fake_bin, artifacts = tmp_path / "bin", tmp_path / "artifacts"
    fake_bin.mkdir()
    _write_fake_avow(fake_bin / "avow", tmp_path / "fake-used")
    environment = _example_environment(Path(".venv"), artifacts)
    environment["PATH"] = f"{fake_bin}:{os.environ['PATH']}"
    # When the source-checkout example runs
    result = _run_example(Path("examples"), environment)
    # Then uv runs this checkout and never invokes the unrelated command
    assert (result.returncode, result.stdout, result.stderr) == (0, _EXPECTED_OUTPUT, "")
    assert not (tmp_path / "fake-used").exists()


def _write_fake_avow(command: Path, marker: Path) -> None:
    command.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n", encoding="utf-8")
    command.chmod(0o755)


def _assert_example_artifacts(command: Path, artifacts: Path) -> None:
    original = json.loads((artifacts / "receipt.json").read_text(encoding="utf-8"))
    altered = json.loads((artifacts / "altered-receipt.json").read_text(encoding="utf-8"))
    assert original["schema"] == altered["schema"] == _EXPECTED_SCHEMA
    _assert_verification(command, artifacts, "receipt.json", (0, "avow.verify.ok\n", ""))
    _assert_verification(
        command,
        artifacts,
        "altered-receipt.json",
        (2, "", "avow.payload_hash_mismatch\n"),
    )
