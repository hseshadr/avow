#!/usr/bin/env bash
set -euo pipefail

artifact_root="${1:-dist/release}"
mkdir -p "${artifact_root}/python" "${artifact_root}/npm"

uv build --wheel --sdist --out-dir "${artifact_root}/python"
corepack pnpm --dir ts build
corepack pnpm --dir ts pack --pack-destination "$(cd "${artifact_root}/npm" && pwd -P)"
uv run python scripts/verify_release_artifacts.py "${artifact_root}"

(
  cd "${artifact_root}"
  sha256sum python/* npm/* > SHA256SUMS
  sha256sum --check SHA256SUMS
)
