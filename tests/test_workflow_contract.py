from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import cast

import yaml

_WORKFLOW_DIR = Path(".github/workflows")
_WORKFLOW_NAMES = ("ci.yml", "security-audit.yml", "publish.yml")
_ACTION_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast(dict[str, object], value)


def _workflow(name: str) -> dict[str, object]:
    path = _WORKFLOW_DIR / name
    assert path.is_file(), f"missing standalone workflow: {path}"
    loader = yaml.BaseLoader(path.read_text(encoding="utf-8"))
    try:
        document = loader.get_single_data()
    finally:
        loader.dispose()
    return _mapping(document)


def _jobs(workflow: dict[str, object]) -> dict[str, object]:
    return _mapping(workflow["jobs"])


def _job(workflow: dict[str, object], name: str) -> dict[str, object]:
    return _mapping(_jobs(workflow)[name])


def _steps(job: dict[str, object]) -> list[dict[str, object]]:
    steps = job["steps"]
    assert isinstance(steps, list)
    return [_mapping(step) for step in steps]


def _commands(job: dict[str, object]) -> str:
    return "\n".join(str(step["run"]) for step in _steps(job) if "run" in step)


def _action_uses(workflow: dict[str, object]) -> tuple[str, ...]:
    jobs = (_mapping(value) for value in _jobs(workflow).values())
    return tuple(str(step["uses"]) for job in jobs for step in _steps(job) if "uses" in step)


def _permissions(value: object) -> dict[str, object]:
    return {} if value in (None, "") else _mapping(value)


def _release_fixture(tmp_path: Path, *, npm_version: str) -> Path:
    shutil.copytree("scripts", tmp_path / "scripts")
    shutil.copytree("src/avow", tmp_path / "src/avow")
    (tmp_path / "ts").mkdir()
    package = json.loads(Path("ts/package.json").read_text(encoding="utf-8"))
    package["version"] = npm_version
    (tmp_path / "ts/package.json").write_text(json.dumps(package), encoding="utf-8")
    return tmp_path / "scripts/verify_release_identity.py"


def _run_identity(script: Path, tag: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python", str(script), tag],
        check=False,
        capture_output=True,
        text=True,
    )


def _node_environment() -> dict[str, str]:
    environments = tuple((Path.home() / ".nvm/versions/node").glob("v22.*/bin"))
    if not environments:
        return dict(os.environ)
    selected = max(environments, key=lambda path: tuple(map(int, path.parent.name[1:].split("."))))
    return dict(os.environ) | {"PATH": f"{selected}:{os.environ['PATH']}"}


def _wrong_node_environment(tmp_path: Path) -> dict[str, str]:
    binary = tmp_path / "node"
    binary.write_text('#!/bin/sh\necho "v26.5.0"\n', encoding="utf-8")
    binary.chmod(0o755)
    return dict(os.environ) | {"PATH": f"{tmp_path}:/usr/bin:/bin"}


def _build_release_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "release"
    result = subprocess.run(
        ["bash", "scripts/build_release_artifacts.sh", root],
        check=False,
        capture_output=True,
        text=True,
        env=_node_environment(),
    )
    assert result.returncode == 0, result.stderr
    return root


def test_should_define_all_standalone_workflows_as_valid_mappings() -> None:
    # Given the standalone workflow contract
    # When each required workflow is parsed as YAML
    workflows = tuple(_workflow(name) for name in _WORKFLOW_NAMES)
    # Then every workflow has independently executable jobs
    assert all(_jobs(workflow) for workflow in workflows)


def test_should_pin_every_third_party_action_to_an_immutable_commit() -> None:
    # Given every third-party action used by the release system
    uses = tuple(use for name in _WORKFLOW_NAMES for use in _action_uses(_workflow(name)))
    # When action references are checked
    unpinned = tuple(use for use in uses if _ACTION_PIN.fullmatch(use) is None)
    # Then no mutable tag or branch can change the reviewed workflow
    assert uses
    assert unpinned == ()


def test_should_isolate_oidc_write_in_the_minimal_publish_job() -> None:
    # Given all workflow and job permissions
    workflows = {name: _workflow(name) for name in _WORKFLOW_NAMES}
    writers: list[tuple[str, str, str]] = []
    for name, workflow in workflows.items():
        for job_name, value in _jobs(workflow).items():
            for scope, access in _permissions(_mapping(value).get("permissions")).items():
                if access == "write":
                    writers.append((name, job_name, scope))
    # Then only the publish job can mint an OIDC identity
    assert writers == [("publish.yml", "publish", "id-token")]


def test_should_keep_default_and_build_permissions_least_privileged() -> None:
    # Given each workflow default and the unprivileged release build
    workflows = tuple(_workflow(name) for name in _WORKFLOW_NAMES)
    publish_build = _job(workflows[-1], "build")
    # Then defaults are read-only or empty and build cannot mint credentials
    assert tuple(_permissions(item.get("permissions")) for item in workflows) == (
        {"contents": "read"},
        {"contents": "read"},
        {},
    )
    assert _permissions(publish_build.get("permissions")) == {"contents": "read"}


def test_should_generate_exact_commit_language_parity_and_example_evidence() -> None:
    # Given the standalone CI workflow
    workflow = _workflow("ci.yml")
    jobs = _jobs(workflow)
    commands = "\n".join(_commands(_mapping(job)) for job in jobs.values())
    # Then it covers both runtimes, the shared vectors, mutations, and the real example
    assert {"python", "typescript", "vector-parity", "mutation", "example"} <= jobs.keys()
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in commands
    assert "tests/test_vectors.py" in commands and "src/receipt.test.ts" in commands
    assert "tests/test_example.py" in commands and "tests/test_envelope.py" in commands
    assert _mapping(_steps(_job(workflow, "typescript"))[1]["with"])["node-version"] == "22"


def test_should_build_and_clean_install_every_release_artifact() -> None:
    # Given the CI artifact job and unprivileged release build
    ci_artifacts = _commands(_job(_workflow("ci.yml"), "artifacts"))
    release_build = _commands(_job(_workflow("publish.yml"), "build"))
    # Then CI calls the real builder and tagged releases run the complete local gate
    assert "bash scripts/build_release_artifacts.sh release" in ci_artifacts
    assert "AVOW_ARTIFACT_ROOT=release uv run poe release-candidate" in release_build


def test_should_verify_real_release_artifacts_through_clean_installs(tmp_path: Path) -> None:
    # Given real wheel, sdist, and npm tarball candidates
    artifacts = _build_release_fixture(tmp_path)
    # When the local artifact verifier inspects and clean-installs them
    result = subprocess.run(
        [
            sys.executable,
            Path("scripts/verify_release_artifacts.py").resolve(),
            artifacts.relative_to(tmp_path),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=_node_environment(),
    )
    # Then all three consumer surfaces pass with aligned metadata
    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        "verified release artifacts: avow 0.5.0.dev0 and @edgeproc/avow 0.5.0-dev.0\n"
    )


def test_should_explain_node_22_requirement_before_running_release_gate(tmp_path: Path) -> None:
    # Given a maintainer shell whose active Node is not the release runtime
    environment = _wrong_node_environment(tmp_path)
    # When the local release candidate starts
    result = subprocess.run(
        ["bash", "scripts/verify_release_candidate.sh"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    # Then it stops before installation with one stable actionable message
    assert (result.returncode, result.stdout, result.stderr) == (
        1,
        "",
        "release candidate requires Node 22; detected v26.5.0\n",
    )


def test_should_scan_full_history_and_audit_locked_dependencies() -> None:
    # Given the scheduled security workflow
    workflow = _workflow("security-audit.yml")
    commands = "\n".join(_commands(_mapping(job)) for job in _jobs(workflow).values())
    checkout = _steps(_job(workflow, "secrets"))[0]
    # Then history, Python lock, npm lock, actionlint, and zizmor are all enforced
    assert _mapping(checkout["with"])["fetch-depth"] == "0"
    assert "gitleaks git --log-opts=--all" in commands
    assert "uv export --frozen --all-groups" in commands
    assert "pnpm --dir ts install --frozen-lockfile --ignore-scripts" in commands
    assert "pnpm --dir ts audit --audit-level high" in commands
    assert "actionlint" in commands and "zizmor" in commands


def test_should_trigger_publication_only_for_version_tags_without_tokens() -> None:
    # Given the publish workflow event and source
    workflow = _workflow("publish.yml")
    triggers = _mapping(workflow["on"])
    source = (_WORKFLOW_DIR / "publish.yml").read_text(encoding="utf-8")
    # Then only version tags enter eligibility and no token secret is accepted
    push = _mapping(triggers["push"])
    assert push == {"tags": ["v*.*.*"]}
    assert set(triggers) == {"push"}
    assert "verify_release_identity.py" in _commands(_job(workflow, "build"))
    assert re.search(r"secrets\.[A-Za-z0-9_]*TOKEN", source) is None


def test_should_recheck_digest_metadata_and_registries_after_publish() -> None:
    # Given the minimal publish job and unprivileged post-publish verifier
    workflow = _workflow("publish.yml")
    publish = _commands(_job(workflow, "publish"))
    registry = _commands(_job(workflow, "verify-published"))
    # Then downloaded bytes and metadata are rechecked before both registries
    assert "sha256sum --check SHA256SUMS" in publish
    names = {step.get("name") for step in _steps(_job(workflow, "publish"))}
    assert "Verify downloaded artifact metadata" in names
    assert "pypi.org/pypi/avow" in registry
    assert 'npm view @edgeproc/avow@"$VERSION" version' in registry


def test_should_fail_closed_until_python_and_npm_versions_align(tmp_path: Path) -> None:
    # Given the current intentionally divergent unpublished package versions
    script = _release_fixture(tmp_path / "divergent", npm_version="0.4.1")
    # When a tag matches only the Python candidate
    result = _run_identity(script, "v0.5.0-dev.0")
    # Then release eligibility fails without disclosing artifact metadata
    assert (result.returncode, result.stdout) == (1, "")
    assert result.stderr == "release tag and artifact versions do not match\n"


def test_should_accept_only_one_tag_matching_both_artifact_versions(tmp_path: Path) -> None:
    # Given aligned Python and npm artifact metadata
    script = _release_fixture(tmp_path / "aligned", npm_version="0.5.0-dev.0")
    # When the exact shared version tag is checked
    exact = _run_identity(script, "v0.5.0-dev.0")
    wrong = _run_identity(script, "v0.5.0")
    # Then only the exact tag is release-eligible
    assert (exact.returncode, exact.stdout, exact.stderr) == (
        0,
        "verified release identity: v0.5.0-dev.0\n",
        "",
    )
    assert wrong.returncode == 1


def test_should_expose_runnable_local_security_and_release_equivalents() -> None:
    # Given the project task runner configuration
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    tasks = project["tool"]["poe"]["tasks"]
    # Then local commands cover every hosted security and release gate
    assert {
        "audit",
        "artifacts",
        "secrets",
        "workflow-contract",
        "workflow-lint",
        "workflow-security",
        "release-candidate",
    } <= tasks.keys()
