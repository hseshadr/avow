"""README contract: plain first screen, fixed section order, and examples backed by a real run."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_README = _ROOT / "README.md"
_TRY = "## Try it"
_HOW = "## How it works"
_SECTIONS = (
    _TRY,
    _HOW,
    "## What it does not do",
    "## When to use something else",
    "## Install",
    "## Develop",
    "## More detail",
    "## License",
)
_TECH_DOCS = "**Technical docs:**"
_REQUIRED_DOCS = ("docs/ARCHITECTURE.md", "docs/GETTING_STARTED.md")
_MAP_TEXT = "Explore the interactive architecture map"
_MAP_PAGE = "docs/architecture/index.html"
_MAP_SOURCE = _ROOT / "docs" / "architecture" / "runtime.architecture.json"
_MAX_TAGLINE = 160
_MAX_BADGES = 3
_BANNED = (
    "northstar",
    "seam",
    "lego",
    "trust envelope",
    "receipt-speak",
    "gate",
    "fleet",
    "portfolio",
    "production-ready",
    "robust",
    "blazing",
    "enterprise-grade",
    "seamless",
    "at a glance",
    "try it in 60 seconds",
    "below the fold",
)
_LINK_TARGET = re.compile(r"\]\(([^)\s]+)\)")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_RUN_AND_OUTPUT = re.compile(
    r"^```bash\n([^`]*?)^```\n+[^`\n]*\n+^```text\n([^`]*?)^```$", re.MULTILINE | re.DOTALL
)


def _readme() -> str:
    return _README.read_text(encoding="utf-8")


def _section(heading: str) -> str:
    return _readme().split(f"\n{heading}\n", maxsplit=1)[1].split("\n## ", maxsplit=1)[0]


def _intro() -> str:
    return _readme().split(f"\n{_TRY}\n", maxsplit=1)[0]


def _tagline() -> str:
    lines = _readme().splitlines()
    return next(line for line in lines[1:] if line.strip() and not line.startswith("[!["))


def _prose(markdown: str) -> str:
    without_blocks = re.sub(r"^```.*?^```$", "", markdown, flags=re.MULTILINE | re.DOTALL)
    without_code = re.sub(r"`[^`\n]+`", "", without_blocks)
    return re.sub(r"\]\([^)]*\)", "]", without_code)


def _fenced(text: str, language: str) -> str:
    block = re.search(rf"^```{language}\n(.*?)^```$", text, re.MULTILINE | re.DOTALL)
    assert block is not None, language
    return block.group(1)


def test_should_open_with_name_and_tagline_equal_to_both_package_descriptions() -> None:
    # Given the README and both package manifests
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package = json.loads((_ROOT / "ts" / "package.json").read_text(encoding="utf-8"))
    # When the title and tagline are read
    tagline = _tagline()
    # Then one plain sentence that explains a receipt is the description everywhere
    assert _readme().splitlines()[0] == "# Avow"
    assert len(tagline) <= _MAX_TAGLINE
    assert all(term in tagline for term in ("JSON", "receipt", "a file anyone can check offline"))
    assert tagline == project["project"]["description"] == package["description"]


def test_should_put_the_fastest_try_in_bold_right_under_the_tagline() -> None:
    # Given the first paragraph after the tagline
    after = _readme().split(_tagline(), maxsplit=1)[1].lstrip("\n")
    first = after.split("\n\n", maxsplit=1)[0]
    # Then it is a bold line naming the one-line install
    assert first.startswith("**") and first.endswith("**")
    assert "pip install" in first


def test_should_keep_badges_to_ci_license_and_version() -> None:
    # Given the lines above the first section
    # Then at most CI, license, and version badges compete with the tagline
    assert _intro().count("[![") <= _MAX_BADGES


def test_should_link_technical_docs_from_the_intro() -> None:
    # Given the intro above Try it
    line = next(line for line in _intro().splitlines() if line.startswith(_TECH_DOCS))
    # Then it links the architecture and developer guides, which exist
    assert all(f"]({doc})" in line for doc in _REQUIRED_DOCS)
    assert all((_ROOT / doc).is_file() for doc in _REQUIRED_DOCS)


def test_should_keep_sections_in_the_standard_order() -> None:
    # Given the README's second-level headings
    headings = tuple(re.findall(r"^## .+$", _readme(), re.MULTILINE))
    # Then every required section appears once, in order
    assert all(headings.count(section) == 1 for section in _SECTIONS)
    positions = tuple(headings.index(section) for section in _SECTIONS)
    assert positions == tuple(sorted(positions))


def test_should_keep_internal_jargon_out_of_readme_prose() -> None:
    # Given the README prose, with commands and link targets removed
    prose = _prose(_readme()).lower()
    # Then none of the banned internal or hype words appear
    found = tuple(word for word in _BANNED if re.search(rf"\b{re.escape(word)}\b", prose))
    assert found == ()


def test_should_link_every_technical_doc_from_more_detail() -> None:
    # Given every doc a reader could need
    docs = sorted(path.relative_to(_ROOT).as_posix() for path in (_ROOT / "docs").glob("*.md"))
    expected = (*docs, "QUICKSTART.md", "CHANGELOG.md", "SECURITY.md", "PROVENANCE.md")
    # Then More detail links each one
    more = _section("## More detail")
    assert tuple(doc for doc in expected if f"]({doc}" not in more) == ()


def test_should_link_develop_to_the_getting_started_guide() -> None:
    # Given the Develop section
    # Then it sends new developers to the step-by-step guide
    assert "](docs/GETTING_STARTED.md)" in _section("## Develop")


def test_should_link_the_interactive_architecture_map_and_its_source() -> None:
    # Given every link labelled as the architecture map
    targets = re.findall(rf"\[{re.escape(_MAP_TEXT)}[^\]]*\]\(([^)\s]+)\)", _readme())
    # Then it points at the generated page, whose source exists on disk
    assert targets
    assert all(target.endswith(_MAP_PAGE) for target in targets)
    assert (_ROOT / _MAP_PAGE).is_file()
    assert _MAP_SOURCE.is_file()


def test_should_resolve_every_relative_link() -> None:
    # Given every link destination without a URL scheme or pure anchor
    targets = (target.split("#", maxsplit=1)[0] for target in _LINK_TARGET.findall(_readme()))
    relative = tuple(target for target in targets if target and not _SCHEME.match(target))
    # Then each one names a file or directory in this checkout
    assert tuple(target for target in relative if not (_ROOT / target).exists()) == ()


def _run_in(directory: Path, commands: str) -> str:
    path = f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}"
    result = subprocess.run(
        ["bash", "-c", f"exec 2>&1\n{commands}"],
        cwd=directory,
        env=dict(os.environ) | {"PATH": path},
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def test_should_print_exactly_the_documented_cli_output(tmp_path: Path) -> None:
    # Given each Try it command block and the output printed under it
    pairs = _RUN_AND_OUTPUT.findall(_section(_TRY))
    # When the blocks run in order, in one empty directory, against this checkout
    printed = tuple(_run_in(tmp_path, commands) for commands, _documented in pairs)
    # Then the README shows the real output, including the refused tampered copy
    assert len(pairs) >= 2
    assert printed == tuple(documented for _commands, documented in pairs)
    assert "avow.payload_hash_mismatch" in printed[-1]


def test_should_print_exactly_the_documented_python_output_with_network_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given the Python example, its documented output, and no network
    section = _section(_TRY).split("### From Python", maxsplit=1)[1]
    source, documented = _fenced(section, "python"), _fenced(section, "text")

    def refuse_socket(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", refuse_socket)
    # When the example runs against this checkout
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        exec(compile(source, "README.md", "exec"), {})  # noqa: S102 - README example is the subject
    # Then the README shows the real output
    assert printed.getvalue() == documented
