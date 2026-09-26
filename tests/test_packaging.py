"""Claim: installing avow never breaks another package.

Every avow release up to 0.4.1 shipped top-level ``assay/`` and ``writ/`` packages
beside ``avow/``. Installed next to ``assay-engine`` they overwrote each other's
files, so ``from assay import ScoreResult`` broke depending on install order.
These tests pin the exact set of top-level names avow may put on ``sys.path``.
"""

from __future__ import annotations

import importlib
import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

_NEIGHBOUR = "assay-engine==0.5.0.dev3"


def _release_module() -> ModuleType:
    sys.path.insert(0, str(Path.cwd()))
    try:
        return importlib.import_module("scripts.verify_release_artifacts")
    finally:
        sys.path.pop(0)


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    out = tmp_path_factory.mktemp("dist")
    subprocess.run(
        ["uv", "build", "--wheel", "--sdist", "--out-dir", out],
        check=True,
        capture_output=True,
    )
    return next(out.glob("*.whl")), next(out.glob("*.tar.gz"))


def _wheel_with(tmp_path: Path, members: tuple[str, ...]) -> Path:
    path = tmp_path / "avow-9.9.9-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for member in members:
            archive.writestr(member, "")
    return path


def _sdist_with(tmp_path: Path, members: tuple[str, ...]) -> Path:
    path = tmp_path / "avow-9.9.9.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for member in members:
            archive.addfile(tarfile.TarInfo(f"avow-9.9.9/{member}"), io.BytesIO(b""))
    return path


def test_should_ship_only_the_avow_package_in_the_built_wheel(built: tuple[Path, Path]) -> None:
    # Given the wheel built from this checkout
    release = _release_module()
    # Then it installs exactly one top-level name
    assert release.wheel_top_levels(built[0]) == frozenset({"avow"})


def test_should_ship_only_the_avow_package_in_the_built_sdist(built: tuple[Path, Path]) -> None:
    # Given the sdist built from this checkout
    release = _release_module()
    # Then its src/ layout carries exactly one package
    assert release.sdist_top_levels(built[1]) == frozenset({"avow"})


def test_should_count_top_level_modules_and_ignore_dist_info(tmp_path: Path) -> None:
    # Given a wheel with a package, a bare module, a .pth hook, and metadata
    release = _release_module()
    wheel = _wheel_with(
        tmp_path,
        ("avow/__init__.py", "stray.py", "hook.pth", "avow-9.9.9.dist-info/METADATA"),
    )
    # Then everything that lands in site-packages counts, metadata does not
    assert release.wheel_top_levels(wheel) == frozenset({"avow", "stray", "hook.pth"})


def test_should_refuse_a_wheel_that_ships_a_foreign_top_level_package(tmp_path: Path) -> None:
    release = _release_module()
    # Given the 0.4.1 defect: a wheel that also ships assay/
    wheel = _wheel_with(tmp_path, ("avow/__init__.py", "assay/__init__.py"))
    sdist = _sdist_with(tmp_path, ("src/avow/__init__.py",))
    # Then the release verifier refuses it by name
    with pytest.raises(ValueError, match=r"wheel ships foreign top-level names: \['assay'\]"):
        release.validate_top_levels(wheel, sdist)


def test_should_refuse_an_sdist_that_ships_a_foreign_top_level_package(tmp_path: Path) -> None:
    release = _release_module()
    wheel = _wheel_with(tmp_path, ("avow/__init__.py",))
    # Given an sdist that also ships src/writ
    sdist = _sdist_with(tmp_path, ("src/avow/__init__.py", "src/writ/__init__.py"))
    # Then the release verifier refuses it by name
    with pytest.raises(ValueError, match=r"sdist ships foreign top-level names: \['writ'\]"):
        release.validate_top_levels(wheel, sdist)


def test_should_install_beside_assay_engine_without_breaking_it(
    built: tuple[Path, Path], tmp_path: Path
) -> None:
    # Given the built wheel and the real assay-engine distribution
    release = _release_module()
    # When both are installed in each order (raises if either import breaks)
    release.coinstall_with_neighbour(built[0], tmp_path)
    # Then the check ran against the pinned neighbour
    assert release.NEIGHBOUR == _NEIGHBOUR
