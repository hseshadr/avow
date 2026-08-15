"""Inspect and clean-install the three Avow release artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

_PYTHON_PRERELEASE = re.compile(r"^(\d+\.\d+\.\d+)\.dev(\d+)$")
_ARGUMENT_COUNT = 2
_NODE_PROBE = """
import { generateSeedHex, publicKeyHex, signPayload, verifySignature } from '@edgeproc/avow';
const key = generateSeedHex();
const pinned = await publicKeyHex(key);
const receipt = await signPayload({ artifact: 'sha256:clean-install' }, key);
await verifySignature(receipt, pinned);
"""
_PYTHON_PROBE = """
from avow import generate_signing_key, public_key_hex, sign_payload, verify_signature
key = generate_signing_key()
receipt = sign_payload({"artifact": "sha256:clean-install"}, key)
verify_signature(receipt, expected_public_key=public_key_hex(key))
"""


@dataclass(frozen=True)
class Artifacts:
    wheel: Path
    sdist: Path
    npm: Path


@dataclass(frozen=True)
class Identity:
    name: str
    version: str


def _only(paths: tuple[Path, ...], kind: str) -> Path:
    if len(paths) != 1:
        raise ValueError(f"expected one {kind}, found {len(paths)}")
    return paths[0]


def _artifacts(root: Path) -> Artifacts:
    python = root / "python"
    return Artifacts(
        wheel=_only(tuple(python.glob("*.whl")), "wheel"),
        sdist=_only(tuple(python.glob("*.tar.gz")), "sdist"),
        npm=_only(tuple((root / "npm").glob("*.tgz")), "npm tarball"),
    )


def _wheel_metadata(path: Path) -> bytes:
    with zipfile.ZipFile(path) as archive:
        members = tuple(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = _only(tuple(Path(name) for name in members), "wheel METADATA")
        return archive.read(metadata.as_posix())


def _sdist_metadata(path: Path) -> bytes:
    with tarfile.open(path, "r:gz") as archive:
        members = tuple(item for item in archive.getmembers() if item.name.endswith("/PKG-INFO"))
        member = _only(tuple(Path(item.name) for item in members), "sdist PKG-INFO")
        extracted = archive.extractfile(member.as_posix())
        if extracted is None:
            raise ValueError("sdist PKG-INFO is unreadable")
        return extracted.read()


def _python_identity(payload: bytes) -> Identity:
    metadata = BytesParser().parsebytes(payload)
    return Identity(name=str(metadata["Name"]), version=str(metadata["Version"]))


def _npm_identity(path: Path) -> Identity:
    with tarfile.open(path, "r:gz") as archive:
        extracted = archive.extractfile("package/package.json")
        if extracted is None:
            raise ValueError("npm package metadata is unreadable")
        package = cast(object, json.loads(extracted.read()))
    return _npm_identity_from(package)


def _npm_identity_from(package: object) -> Identity:
    if not isinstance(package, dict):
        raise ValueError("npm package metadata is not an object")
    name, version = package.get("name"), package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ValueError("npm package identity is missing")
    return Identity(name=name, version=version)


def _npm_spelling(python_version: str) -> str:
    match = _PYTHON_PRERELEASE.fullmatch(python_version)
    if match is None:
        return python_version
    return f"{match.group(1)}-dev.{match.group(2)}"


def _validate_metadata(artifacts: Artifacts) -> tuple[Identity, Identity]:
    wheel = _python_identity(_wheel_metadata(artifacts.wheel))
    sdist = _python_identity(_sdist_metadata(artifacts.sdist))
    npm = _npm_identity(artifacts.npm)
    if wheel != sdist or wheel.name != "avow":
        raise ValueError("Python artifact metadata does not match")
    if npm.name != "@edgeproc/avow" or npm.version != _npm_spelling(wheel.version):
        raise ValueError("Python and npm artifact metadata does not match")
    return wheel, npm


def _artifact_paths(artifacts: Artifacts) -> tuple[Path, ...]:
    return tuple(sorted((artifacts.wheel, artifacts.sdist, artifacts.npm)))


def _digest_lines(root: Path, artifacts: Artifacts) -> tuple[str, ...]:
    return tuple(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}"
        for path in _artifact_paths(artifacts)
    )


def _write_digest_manifest(root: Path, artifacts: Artifacts) -> None:
    content = "\n".join(_digest_lines(root, artifacts)) + "\n"
    (root / "SHA256SUMS").write_text(content, encoding="utf-8")


def _run(arguments: list[str | Path], *, cwd: Path | None = None) -> None:
    # Arguments are fixed commands plus path values and never enter a shell.
    subprocess.run(arguments, cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603


def _clean_python_install(artifact: Path, root: Path) -> None:
    environment = root / artifact.name
    _run(["uv", "venv", "--python", "3.13", environment])
    python = environment / "bin/python"
    _run(["uv", "pip", "install", "--python", python, artifact])
    _run([python, "-c", _PYTHON_PROBE])


def _clean_npm_install(artifact: Path, root: Path) -> None:
    project = root / "npm"
    project.mkdir()
    (project / "package.json").write_text('{"private":true,"type":"module"}', encoding="utf-8")
    _run(["npm", "install", "--ignore-scripts", "--no-package-lock", artifact], cwd=project)
    _run(["node", "--input-type=module", "--eval", _NODE_PROBE], cwd=project)


def main() -> int:
    if len(sys.argv) != _ARGUMENT_COUNT:
        sys.stderr.write("usage: verify_release_artifacts.py ARTIFACT_ROOT\n")
        return 1
    root = Path(sys.argv[1]).resolve()
    artifacts = _artifacts(root)
    python, npm = _validate_metadata(artifacts)
    with TemporaryDirectory(prefix="avow-release-") as temporary:
        _clean_python_install(artifacts.wheel, Path(temporary))
        _clean_python_install(artifacts.sdist, Path(temporary))
        _clean_npm_install(artifacts.npm, Path(temporary))
    _write_digest_manifest(root, artifacts)
    sys.stdout.write(
        f"verified release artifacts: {python.name} {python.version} and {npm.name} {npm.version}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
