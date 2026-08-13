"""Isolated deterministic Python classification workload."""

from __future__ import annotations

from functools import partial

from assay.metrics import binary_scores
from avow.benchmarks._contracts import Stats, require, sample, stats


def _operation(labels: list[int], scores: list[float]) -> None:
    binary_scores(labels, scores)


def benchmark() -> Stats:
    labels = [index % 2 for index in range(10_000)]
    scores = [0.8 if label else 0.2 for label in labels]
    operation = partial(_operation, labels, scores)
    return require(stats(sample(operation, 5, 100)), (75, 150, 300), 512)


if __name__ == "__main__":
    print(benchmark().model_dump_json())
