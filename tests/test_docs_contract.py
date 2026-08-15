from __future__ import annotations

import os
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

_README = Path("README.md")
_TYPESCRIPT_README = Path("ts/README.md")
_FORBIDDEN_OPENING = ("Assay", "score", "ranking", "recommendation", "AML", "astrology")
_TREE_LINE = re.compile(
    r"^(src/avow|ts/src)/\s+→\s+(Python wheel|npm tarball):\s+(\S+)/$",
    re.MULTILINE,
)


def _readme() -> str:
    return _README.read_text(encoding="utf-8")


def _source_version() -> str:
    source = Path("src/avow/_version.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', source, re.MULTILINE)
    assert match is not None
    return match.group(1)


def _first_paragraph(markdown: str) -> str:
    blocks = re.split(r"\n\s*\n", markdown)
    return next(block.replace("\n", " ") for block in blocks if not block.startswith("#"))


def _first_runnable_block(markdown: str) -> tuple[str, ...]:
    block = re.search(r"```(?:bash|sh)\n(.*?)```", markdown, re.DOTALL)
    assert block is not None
    return tuple(line for line in block.group(1).splitlines() if line and not line.startswith("#"))


def _typescript_usage() -> str:
    markdown = _TYPESCRIPT_README.read_text(encoding="utf-8")
    block = re.search(r"```ts\n(.*?)```", markdown, re.DOTALL)
    assert block is not None
    return block.group(1)


def _local_links(markdown: str) -> tuple[Path, ...]:
    destinations = re.findall(r"\[[^]]+\]\(([^)]+)\)", markdown)
    return tuple(Path(link.partition("#")[0]) for link in destinations if "://" not in link)


def _build_wheel(output_dir: Path) -> Path:
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(output_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    return next(output_dir.glob("*.whl"))


def _wheel_roots(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as archive:
        return {
            name.partition("/")[0]
            for name in archive.namelist()
            if ".dist-info/" not in name and name.endswith((".py", "py.typed"))
        }


def _build_npm_tarball(output_dir: Path) -> Path:
    environment = _node_environment()
    _run_npm(["pnpm", "build"], environment)
    _run_npm(["pnpm", "pack", "--pack-destination", str(output_dir)], environment)
    return next(output_dir.glob("*.tgz"))


def _run_npm(arguments: list[str], environment: dict[str, str]) -> None:
    subprocess.run(arguments, cwd="ts", check=True, capture_output=True, text=True, env=environment)


def _node_environment() -> dict[str, str]:
    environments = tuple((Path.home() / ".nvm/versions/node").glob("v22.*/bin"))
    if not environments:
        return dict(os.environ)
    selected = max(environments, key=lambda path: tuple(map(int, path.parent.name[1:].split("."))))
    return dict(os.environ) | {"PATH": f"{selected}:{os.environ['PATH']}"}


def _npm_roots(tarball: Path) -> set[str]:
    with tarfile.open(tarball) as archive:
        return {
            parts[1]
            for member in archive.getmembers()
            if len(parts := Path(member.name).parts) > 2
            and parts[1] not in {"node_modules"}
            and parts[-1].endswith((".js", ".d.ts"))
        }


def test_should_open_readme_with_one_clear_product_identity() -> None:
    # Given the root product interface
    markdown = _readme()
    # When its identity and first explanation are read
    assert re.findall(r"^# .+$", markdown, re.MULTILINE) == ["# Avow"]
    paragraph = _first_paragraph(markdown).lower()
    # Then it explains the complete plain-language purpose
    assert all(term in paragraph for term in ("signed", "tamper-evident", "json", "receipt"))
    assert "verify offline" in paragraph


def test_should_put_short_cold_start_after_tldr_and_before_installation() -> None:
    # Given the root product interface
    markdown = _readme()
    # When its first runnable path is extracted
    assert markdown.index("## TL;DR") < markdown.index("## Installation")
    commands = _first_runnable_block(markdown)
    # Then a cold reader starts the bounded evidence loop directly
    assert len(commands) <= 15
    assert commands[0] == "bash examples/run_evidence_loop.sh"


def test_should_explain_prerequisites_and_checkout_command_selection() -> None:
    # Given the cold-reader path before architecture details
    opening = " ".join(_readme().partition("## Architecture")[0].lower().split())
    # When prerequisites and command resolution are read
    assert all(term in opening for term in ("bash", "python 3.12", "`uv`"))
    # Then it says this checkout wins over an unrelated installed command
    assert "before any installed `avow`" in opening
    assert "exercises this source checkout" in opening


def test_should_pin_typescript_signer_independently_of_receipt() -> None:
    # Given the TypeScript README usage example
    usage = _typescript_usage()
    # When its trust anchor is inspected
    assert "publicKeyHex" in usage
    assert "receipt.public_key" not in usage
    # Then verification uses an independently named pin
    assert re.search(r"verifySignature\(receipt,\s*pinnedPublicKey\)", usage)


def test_should_keep_opening_free_of_other_domain_language() -> None:
    # Given everything before the architecture boundary
    opening = _readme().partition("## Architecture")[0]
    # When cross-product vocabulary is checked
    violations = tuple(
        word for word in _FORBIDDEN_OPENING if re.search(rf"\b{word}\b", opening, re.I)
    )
    # Then the opening stays focused on Avow's evidence purpose
    assert violations == ()


def test_should_state_proof_limits_and_unpublished_split_status() -> None:
    # Given the root product interface
    markdown = _readme()
    # When proof and release claims are inspected
    assert "## What this proves" in markdown
    assert "## What this does not prove" in markdown
    # Then source and published identities stay explicitly separate
    assert _source_version() == "0.5.0.dev0"
    assert f"`{_source_version()}`" in markdown
    assert re.search(r"local split candidate", markdown, re.I)
    assert re.search(r"not\s+published", markdown, re.I)
    assert re.search(r"published `avow` `0\.4\.1`[^.]*untouched", markdown, re.I)


def test_should_resolve_every_readme_local_link() -> None:
    # Given every local destination exposed by the README
    links = _local_links(_readme())
    # When the checkout resolves those destinations
    assert links
    # Then no cold-reader path is broken
    assert tuple(path for path in links if not path.exists()) == ()


def test_should_map_source_tree_one_to_one_to_real_built_packages(tmp_path: Path) -> None:
    # Given machine-readable source-to-artifact claims
    claims = {
        (source, artifact): target for source, artifact, target in _TREE_LINE.findall(_readme())
    }
    # When both package artifacts are built and inspected
    actual = {
        ("src/avow", "Python wheel"): _wheel_roots(_build_wheel(tmp_path / "wheel")),
        ("ts/src", "npm tarball"): _npm_roots(_build_npm_tarball(tmp_path / "npm")),
    }
    # Then every source node maps to exactly one real production root
    assert set(claims) == set(actual)
    assert all({claims[key].rstrip("/")} == roots for key, roots in actual.items())
