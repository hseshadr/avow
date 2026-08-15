from __future__ import annotations

import subprocess
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path


def _build_wheel(output_dir: Path) -> Path:
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(output_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(output_dir.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _read_wheel(wheel_path: Path) -> tuple[list[str], bytes]:
    with zipfile.ZipFile(wheel_path) as wheel:
        members = wheel.namelist()
        metadata_path = next(name for name in members if name.endswith(".dist-info/METADATA"))
        return members, wheel.read(metadata_path)


def _shipped_packages(members: list[str]) -> set[str]:
    return {
        name.split("/", maxsplit=1)[0]
        for name in members
        if ".dist-info/" not in name and name.endswith((".py", "py.typed"))
    }


def _inspect_wheel(wheel_path: Path) -> tuple[str | None, str | None, set[str]]:
    members, metadata_bytes = _read_wheel(wheel_path)
    metadata = BytesParser().parsebytes(metadata_bytes)
    return metadata["Name"], metadata["Version"], _shipped_packages(members)


def test_should_build_only_avow_distribution_and_package(tmp_path: Path) -> None:
    # Given the standalone project configuration
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    # When its wheel is built and inspected
    name, version, packages = _inspect_wheel(_build_wheel(tmp_path))
    # Then both declared and built identities contain only Avow
    assert project["project"]["name"] == "avow"
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/avow"]
    assert (name, version, packages) == ("avow", "0.5.0.dev0", {"avow"})


def test_should_ship_no_scoring_source() -> None:
    # Given the forbidden product-owned source locations
    forbidden = (Path("src/assay"), Path("src/writ"), Path("ts/src/metrics.ts"))
    # When the extracted repository paths are inspected
    existing = tuple(path for path in forbidden if path.exists())
    # Then no scoring or action-policy implementation remains
    assert existing == ()
