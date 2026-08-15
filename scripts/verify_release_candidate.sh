#!/usr/bin/env bash
set -euo pipefail

test "$(node -p 'process.versions.node.split(".")[0]')" = "22"
uv sync --frozen --all-groups
corepack pnpm --dir ts install --frozen-lockfile --ignore-scripts

uv run poe gate
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
