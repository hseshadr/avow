"""Portfolio README contract: keep the first screen plain, honest, and backed by a real run."""

from __future__ import annotations

import contextlib
import io
import json
import re
import socket
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_README = _ROOT / "README.md"
_AT_A_GLANCE = "## At a glance"
_TRY = "## Try it in 60 seconds"
_HOW = "## How it works"
_CAPTION = "Real output of the example below"
_MAP_TEXT = "Explore the interactive architecture map"
_MAP_PAGE = "docs/architecture/index.html"
_MAP_SOURCE = _ROOT / "docs" / "architecture" / "runtime.architecture.json"
_MAX_TAGLINE = 120
_MAX_BADGES = 4
_LABELS = (
    "**What it does**",
    "**Who it's for**",
    "**What stays on your device / what leaves it**",
    "**Runs on**",
    "**Not for**",
    "**Status**",
)
_LINK_TARGET = re.compile(r"\]\(([^)\s]+)\)")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def _readme() -> str:
    return _README.read_text(encoding="utf-8")


def _first_screen() -> str:
    return _readme().split(_HOW, maxsplit=1)[0]


def _tagline() -> str:
    lines = _readme().splitlines()
    return next(line for line in lines[1:] if line.strip() and not line.startswith("[!["))


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
    # Then one short tagline is the single description everywhere
    assert _readme().splitlines()[0] == "# Avow"
    assert len(tagline) <= _MAX_TAGLINE
    assert tagline == project["project"]["description"] == package["description"]


def test_should_keep_first_screen_badges_bounded() -> None:
    # Given the lines above the at-a-glance summary
    opening = _readme().split(_AT_A_GLANCE, maxsplit=1)[0]
    # Then at most four badges compete with the tagline
    assert opening.count("[![") <= _MAX_BADGES


def test_should_answer_every_at_a_glance_question_on_the_first_screen() -> None:
    # Given the first screen
    first_screen = _first_screen()
    # Then each plain-language question is present with its exact bold label
    assert all(label in first_screen for label in _LABELS)


def test_should_show_real_output_before_the_example_and_example_before_internals() -> None:
    # Given the README section order
    readme = _readme()
    # Then the hero caption precedes the runnable example, which precedes internals
    assert readme.count(_TRY) == 1
    assert readme.index(_CAPTION) < readme.index(_TRY) < readme.index(_HOW)


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


def test_should_print_exactly_the_documented_output_with_network_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given the runnable example, its documented output, the hero, and no network
    section = _readme().split(_TRY, maxsplit=1)[1].split(_HOW, maxsplit=1)[0]
    source, documented = _fenced(section, "python"), _fenced(section, "text")
    hero = _fenced(_readme().split(_TRY, maxsplit=1)[0], "text")

    def refuse_socket(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", refuse_socket)
    # When the example runs against this checkout
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        exec(compile(source, "README.md", "exec"), {})  # noqa: S102 - README example is the subject
    # Then the README shows the real output, in the example and in the hero
    assert printed.getvalue() == documented
    hero_output = hero.split("output:", maxsplit=1)[1].splitlines()
    assert tuple(line.strip() for line in hero_output) == tuple(
        line.strip() for line in documented.splitlines()
    )
