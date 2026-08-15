#!/usr/bin/env bash
set -euo pipefail

detected_node="$(node --version 2>/dev/null || true)"
node_major="${detected_node#v}"
node_major="${node_major%%.*}"
if [[ "${node_major}" != "22" ]]; then
  printf 'release candidate requires Node 22; detected %s\n' "${detected_node:-unavailable}" >&2
  exit 1
fi
uv sync --frozen --all-groups
corepack pnpm --dir ts install --frozen-lockfile --ignore-scripts

uv run poe gate
uv run python -m benchmarks.release
corepack pnpm --dir ts gate
uv run pytest tests/test_vectors.py -q
corepack pnpm --dir ts exec vitest run src/canonical.test.ts src/receipt.test.ts
bash examples/run_evidence_loop.sh

uv run poe workflow-lint
uv run poe workflow-security
uv run poe secrets
uv run poe audit
bash scripts/build_release_artifacts.sh "${AVOW_ARTIFACT_ROOT:-dist/release}"
shellcheck examples/*.sh scripts/*.sh
git diff --check
if [[ "${CI:-false}" == "true" ]]; then
  git diff --exit-code
fi
