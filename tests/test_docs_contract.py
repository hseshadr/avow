from __future__ import annotations

import json
import os
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

_README = Path("README.md")
_TYPESCRIPT_README = Path("ts/README.md")
_ARCHITECTURE = Path("docs/ARCHITECTURE.md")
_GETTING_STARTED = Path("docs/GETTING_STARTED.md")
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


def _npm_source_version() -> str:
    package = json.loads(Path("ts/package.json").read_text(encoding="utf-8"))
    version = package.get("version") if isinstance(package, dict) else None
    assert isinstance(version, str)
    return version


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


def _architecture() -> str:
    return _ARCHITECTURE.read_text(encoding="utf-8")


def _getting_started() -> str:
    return _GETTING_STARTED.read_text(encoding="utf-8")


def _problem_paragraphs(markdown: str) -> str:
    intro = markdown.partition("\n## ")[0]
    return " ".join(
        block for block in re.split(r"\n\s*\n", intro) if not block.startswith(("#", "*", "["))
    )


def test_should_open_readme_with_one_clear_product_identity() -> None:
    # Given the root product interface
    markdown = _readme()
    # When its identity and plain-language explanation are read
    assert re.findall(r"^# .+$", markdown, re.MULTILINE) == ["# Avow"]
    tagline = _first_paragraph(markdown).lower()
    problem = " ".join(_problem_paragraphs(markdown).lower().split())
    # Then it explains the complete plain-language purpose without leading jargon
    assert all(term in tagline for term in ("json", "receipt", "check offline"))
    assert all(term in problem for term in ("public key", "no server", "no internet"))


def test_should_put_one_line_install_before_internals_and_keep_the_evidence_loop() -> None:
    # Given the root product interface
    markdown = _readme()
    # When its runnable paths are extracted
    assert markdown.index("## Try it") < markdown.index("## How it works")
    assert markdown.index("## How it works") < markdown.index("## Install")
    commands = _first_runnable_block(markdown)
    loop = re.findall(r"```bash\n(bash examples/run_evidence_loop\.sh)\n```", markdown)
    # Then a cold reader starts from one install line and the evidence loop stays one line
    assert commands == ('pip install "avow>=0.5.0"',)
    assert loop == ["bash examples/run_evidence_loop.sh"]


def test_should_explain_prerequisites_and_checkout_command_selection() -> None:
    # Given the install section and the developer guide
    install = " ".join(_readme().partition("## Install")[2].partition("\n## ")[0].lower().split())
    guide = " ".join(_getting_started().lower().split())
    # When prerequisites and command resolution are read
    assert all(term in install for term in ("python 3.12", "node.js 22.13"))
    assert all(term in guide for term in ("bash", "python 3.12", "`uv`"))
    # Then the guide says this checkout wins over an unrelated installed command
    assert "before any installed `avow`" in guide
    assert "exercises this source checkout" in guide


def test_should_pin_typescript_signer_independently_of_receipt() -> None:
    # Given the TypeScript README usage example
    usage = _typescript_usage()
    # When its trust anchor is inspected
    assert "publicKeyHex" in usage
    assert "receipt.public_key" not in usage
    # Then verification uses an independently named pin
    assert re.search(r"verifySignature\(receipt,\s*pinnedPublicKey\)", usage)


def test_should_keep_opening_free_of_other_domain_language() -> None:
    # Given the first screen, everything before the architecture explanation
    opening = _readme().partition("## How it works")[0]
    # When cross-product vocabulary is checked
    violations = tuple(
        word for word in _FORBIDDEN_OPENING if re.search(rf"\b{word}\b", opening, re.I)
    )
    # Then the opening stays focused on Avow's evidence purpose
    assert violations == ()


def test_should_state_proof_limits_and_first_clean_release_status() -> None:
    # Given the root product interface
    markdown = _readme()
    # When proof and release claims are inspected
    assert "## What this proves" in _architecture()
    assert "## What this does not prove" in _architecture()
    # Then 0.5.0 is named as the first clean release and 0.1.0-0.4.1 as the broken ones
    assert _source_version() == "0.5.0"
    assert f"`{_source_version()}`" in markdown
    assert re.search(r"first release (built )?from this repository", markdown, re.I)
    assert re.search(r"`0\.1\.0`[\s\S]{0,40}`0\.4\.1`[^.]*`assay/`[^.]*`writ/`", markdown)
    assert re.search(r"yank", markdown, re.I)


def test_should_state_both_release_versions_without_registry_drift() -> None:
    # Given the Python and npm sources plus their reader-facing status
    root = _readme()
    quickstart = Path("QUICKSTART.md").read_text(encoding="utf-8")
    typescript = _TYPESCRIPT_README.read_text(encoding="utf-8")
    security = Path("SECURITY.md").read_text(encoding="utf-8")
    # Then both ecosystems ship the same 0.5.0 and no doc still names the dev candidate
    assert (_source_version(), _npm_source_version()) == ("0.5.0", "0.5.0")
    assert all("`0.5.0`" in text for text in (root, quickstart, typescript, security))
    assert not any(
        re.search(r"0\.5\.0[.-]dev", text) for text in (root, quickstart, typescript, security)
    )
    assert "dist/avow-0.5.0-py3-none-any.whl" in quickstart


def test_should_record_the_packaging_fix_and_upgrade_path_in_the_changelog() -> None:
    # Given the 0.5.0 changelog entry
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    entry = changelog.partition("## [0.5.0]")[2].partition("\n## [")[0]
    # Then it explains the clobbering fix, the assay-engine repair, and the yank plan
    assert entry
    assert "`assay/`" in entry and "`writ/`" in entry
    assert re.search(r"reinstall[^.]*assay-engine", entry, re.I)
    assert re.search(r"yank[^.]*`0\.1\.0`[^.]*`0\.4\.1`", entry, re.I)


def test_should_keep_release_tooling_out_of_end_user_first_run() -> None:
    # Given the end-user cold start and the maintainer-only release section of the guide
    markdown = _readme()
    first_run = "\n".join(_first_runnable_block(markdown))
    release = _getting_started().partition("## Maintainer release check")[2]
    # Then users still get one simple start while maintainers get exact tool prerequisites
    assert first_run == 'pip install "avow>=0.5.0"'
    assert "release-candidate" not in markdown.partition("## How it works")[0]
    assert all(item in release for item in ("Node 22", "Corepack", "pnpm 11.5.0"))
    assert "uv run poe release-candidate" in release


def test_should_probe_the_direct_pinned_pnpm_used_by_release_scripts() -> None:
    # Given the maintainer prerequisites and the release scripts
    release = _getting_started().partition("## Maintainer release check")[2]
    scripts = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in ("scripts/build_release_artifacts.sh", "scripts/verify_release_candidate.sh")
    )
    # Then the documented probe exercises the same direct pnpm command as automation
    assert "pnpm --version" in release
    assert "corepack pnpm --version" not in release
    assert "corepack pnpm" not in scripts


def test_should_resolve_every_readme_local_link() -> None:
    # Given every local destination exposed by the README
    links = _local_links(_readme())
    # When the checkout resolves those destinations
    assert links
    # Then no cold-reader path is broken
    assert tuple(path for path in links if not path.exists()) == ()


def test_should_resolve_every_local_link_in_the_moved_docs() -> None:
    # Given every local destination in the docs that took over README material
    links = tuple(
        doc.parent / link
        for doc in (_ARCHITECTURE, _GETTING_STARTED)
        for link in _local_links(doc.read_text(encoding="utf-8"))
    )
    # Then each resolves relative to its own document
    assert links
    assert tuple(path for path in links if not path.exists()) == ()


def test_should_map_source_tree_one_to_one_to_real_built_packages(tmp_path: Path) -> None:
    # Given machine-readable source-to-artifact claims
    claims = {
        (source, artifact): target
        for source, artifact, target in _TREE_LINE.findall(_architecture())
    }
    # When both package artifacts are built and inspected
    actual = {
        ("src/avow", "Python wheel"): _wheel_roots(_build_wheel(tmp_path / "wheel")),
        ("ts/src", "npm tarball"): _npm_roots(_build_npm_tarball(tmp_path / "npm")),
    }
    # Then every source node maps to exactly one real production root
    assert set(claims) == set(actual)
    assert all({claims[key].rstrip("/")} == roots for key, roots in actual.items())


def test_should_state_replay_and_key_custody_limits_at_the_boundary() -> None:
    # Given the architecture guide's proof boundary
    boundary = _architecture().partition("## What this does not prove")[2].partition("\n## ")[0]
    flat = " ".join(boundary.split())
    # Then replay is explicitly out of scope and points at the caller recipe
    assert "Not a replay defence" in flat
    assert "OPERATIONS.md#replay-protection-is-caller-owned" in flat
    # And key custody is stated plainly: an unencrypted seed guarded by file permissions
    assert all(term in flat for term in ("unencrypted", "filesystem permissions", "KMS", "HSM"))


def test_should_state_replay_and_key_custody_limits_in_the_readme() -> None:
    # Given the README's plain list of limits
    limits = _readme().partition("## What it does not do")[2].partition("\n## ")[0]
    flat = " ".join(limits.split())
    # Then replay and key custody are named, with the caller recipe linked
    assert "replay" in flat.lower()
    assert "docs/OPERATIONS.md#replay-protection-is-caller-owned" in flat
    assert all(term in flat for term in ("not encrypted", "file permissions", "KMS", "HSM"))


def test_should_give_operators_replay_and_rotation_recipes() -> None:
    # Given the operations guide
    operations = Path("docs/OPERATIONS.md").read_text(encoding="utf-8")
    flat = " ".join(operations.split())
    # Then callers get concrete replay and rotation recipes plus the key-mode code
    assert "## Replay protection is caller-owned" in operations
    assert all(term in flat for term in ("nonce", "`aud`", "`exp`", "verify_signature"))
    assert "## Key rotation" in operations
    assert "avow.key_permissions_insecure" in flat


def test_should_keep_typescript_key_custody_and_replay_limits_in_parity() -> None:
    # Given the TypeScript README, whose seed never touches a file inside Avow
    flat = " ".join(_TYPESCRIPT_README.read_text(encoding="utf-8").split())
    # Then it states the same replay and custody boundary as the Python docs
    assert "Not a replay defence" in flat
    assert "unencrypted" in flat
    assert "avow.key_permissions_insecure" in flat
