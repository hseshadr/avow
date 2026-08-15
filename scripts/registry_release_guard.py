"""Fail-closed registry preflight for retry-safe trusted publication."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import cast

from scripts.verify_release_artifacts import verify_release_bundle

_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
_NPM_ATTESTATION_ROOT = "https://registry.npmjs.org/-/npm/v1/attestations/"
_PYTHON_FILE_COUNT = 2
_NOT_FOUND = 404
_NPM_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("registry metadata is malformed")
    return cast(dict[str, object], value)


def _sequence(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("registry metadata is malformed")
    return value


def _digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _integrity(path: Path) -> str:
    digest = hashlib.sha512(path.read_bytes()).digest()
    return f"sha512-{base64.b64encode(digest).decode()}"


def _local_python_digests(root: Path) -> dict[str, str]:
    files = tuple(sorted(path for path in root.iterdir() if path.is_file()))
    if len(files) != _PYTHON_FILE_COUNT:
        raise ValueError("Python release artifact count mismatch")
    return {path.name: _digest(path, "sha256") for path in files}


def _pypi_digests(payload: object) -> dict[str, str]:
    urls = _sequence(_mapping(payload).get("urls"))
    records = (_mapping(item) for item in urls)
    return {
        str(record.get("filename")): str(_mapping(record.get("digests")).get("sha256"))
        for record in records
    }


def pypi_release_state(root: Path, payload: object | None, provenance: set[str]) -> bool:
    """Return whether PyPI needs publishing; reject any existing drift."""
    if payload is None:
        return True
    expected = _local_python_digests(root)
    if _pypi_digests(payload) != expected or provenance != set(expected):
        raise ValueError("PyPI artifact or provenance mismatch")
    return False


def _npm_attestation_url(payload: object) -> str:
    dist = _mapping(_mapping(payload).get("dist"))
    attestations = _mapping(dist.get("attestations"))
    provenance = _mapping(attestations.get("provenance"))
    if provenance.get("predicateType") != _PROVENANCE_TYPE:
        raise ValueError("npm artifact or provenance mismatch")
    url = attestations.get("url")
    if not isinstance(url, str) or not url.startswith(_NPM_ATTESTATION_ROOT):
        raise ValueError("npm artifact or provenance mismatch")
    return url


def provenance_payload_valid(payload: object | None) -> bool:
    """Recognize nonempty PyPI or npm provenance endpoint payloads."""
    if payload is None:
        return False
    metadata = _mapping(payload)
    collections = (metadata.get("attestations"), metadata.get("attestation_bundles"))
    return any(isinstance(items, list) and bool(items) for items in collections)


def npm_dist_tag(version: str) -> str:
    """Map exact stable and prerelease SemVer versions to safe npm channels."""
    if _NPM_VERSION.fullmatch(version) is None:
        raise ValueError("npm release version is not valid SemVer")
    return "next" if "-" in version else "latest"


def npm_release_state(path: Path, payload: object | None, attestation: object | None) -> bool:
    """Return whether npm needs publishing; reject any existing drift."""
    if payload is None:
        return True
    dist = _mapping(_mapping(payload).get("dist"))
    expected = (_digest(path, "sha1"), _integrity(path))
    actual = (dist.get("shasum"), dist.get("integrity"))
    if actual != expected:
        raise ValueError("npm artifact or provenance mismatch")
    provenance_url = _npm_attestation_url(payload)
    if not provenance_url or not provenance_payload_valid(attestation):
        raise ValueError("npm artifact or provenance mismatch")
    return False


def _fetch_json(url: str) -> object | None:
    if not url.startswith("https://"):
        raise ValueError("registry URL must use HTTPS")
    try:
        with urllib.request.urlopen(url, timeout=15) as response:  # noqa: S310
            return cast(object, json.load(response))
    except urllib.error.HTTPError as error:
        if error.code == _NOT_FOUND:
            return None
        raise


def _pypi_provenance(version: str, filenames: set[str]) -> set[str]:
    root = f"https://pypi.org/integrity/avow/{version}"
    proven = set()
    for filename in filenames:
        encoded = urllib.parse.quote(filename, safe="")
        if provenance_payload_valid(_fetch_json(f"{root}/{encoded}/provenance")):
            proven.add(filename)
    return proven


def _pypi_state(root: Path, version: str) -> bool:
    python, _npm = verify_release_bundle(root.parent)
    if python.version != version:
        raise ValueError("PyPI artifact version mismatch")
    url = f"https://pypi.org/pypi/avow/{version}/json"
    payload = _fetch_json(url)
    filenames = set(_local_python_digests(root)) if payload is not None else set()
    return pypi_release_state(root, payload, _pypi_provenance(version, filenames))


def _npm_state(root: Path, version: str) -> bool:
    _python, npm = verify_release_bundle(root.parent)
    if npm.version != version:
        raise ValueError("npm artifact version mismatch")
    tarballs = tuple(root.glob("*.tgz"))
    if len(tarballs) != 1:
        raise ValueError("npm release artifact count mismatch")
    encoded = urllib.parse.quote("@edgeproc/avow", safe="")
    payload = _fetch_json(f"https://registry.npmjs.org/{encoded}/{version}")
    attestation = _fetch_json(_npm_attestation_url(payload)) if payload is not None else None
    return npm_release_state(tarballs[0], payload, attestation)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("registry", choices=("pypi", "npm"))
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("version")
    parser.add_argument("github_output", type=Path)
    return parser


def _write_decision(path: Path, publish: bool, registry: str, version: str) -> None:
    lines = [f"publish={'true' if publish else 'false'}"]
    if registry == "npm":
        lines.append(f"dist-tag={npm_dist_tag(version)}")
    with path.open("a", encoding="utf-8") as output:
        output.write("\n".join(lines) + "\n")


def _run(arguments: argparse.Namespace) -> bool:
    root = cast(Path, arguments.artifact_root)
    version = cast(str, arguments.version)
    if arguments.registry == "pypi":
        return _pypi_state(root, version)
    return _npm_state(root, version)


def main() -> int:
    """Run one registry preflight and emit a GitHub Actions decision."""
    arguments = _parser().parse_args()
    try:
        publish = _run(arguments)
    except (OSError, ValueError, urllib.error.URLError) as error:
        print(str(error), file=sys.stderr)
        return 1
    _write_decision(
        cast(Path, arguments.github_output),
        publish,
        cast(str, arguments.registry),
        cast(str, arguments.version),
    )
    message = (
        "registry artifact is missing"
        if publish
        else "verified existing registry bytes and provenance"
    )
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
