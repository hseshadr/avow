"""Run every frozen workload in a clean process and emit one JSON report."""

from __future__ import annotations

import json
import subprocess
import sys

from avow.benchmarks._contracts import Stats

_WORKLOADS = ("envelope", "classification", "ledger")


def _isolated(workload: str) -> Stats:
    command = [sys.executable, "-m", f"avow.benchmarks.{workload}"]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)  # noqa: S603
    if completed.returncode:
        output = completed.stderr + completed.stdout
        raise RuntimeError(f"{workload} benchmark failed:\n{output}")
    return Stats.model_validate_json(completed.stdout)


def main() -> None:
    """Run and print the complete deterministic release report."""
    results = {name: _isolated(name).model_dump() for name in _WORKLOADS}
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main()
