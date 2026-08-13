"""Fail closed unless one release tag identifies both immutable artifacts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_ARGUMENT_COUNT = 2


def _python_version() -> str:
    source = (ROOT / "src/avow/_version.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', source, re.MULTILINE)
    if match is None:
        raise ValueError("Python artifact version is missing")
    return match.group(1)


def _typescript_version() -> str:
    package = json.loads((ROOT / "ts/package.json").read_text(encoding="utf-8"))
    version = package.get("version") if isinstance(package, dict) else None
    if not isinstance(version, str):
        raise ValueError("TypeScript artifact version is missing")
    return version


def main() -> int:
    if len(sys.argv) != _ARGUMENT_COUNT:
        print("usage: verify_release_identity.py vX.Y.Z", file=sys.stderr)
        return 1
    python_version, typescript_version = _python_version(), _typescript_version()
    expected = f"v{python_version}"
    if python_version != typescript_version or sys.argv[1] != expected:
        print("release tag and artifact versions do not match", file=sys.stderr)
        return 1
    print(f"verified release identity: {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
