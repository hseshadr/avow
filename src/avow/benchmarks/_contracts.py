"""Shared typed measurement and acceptance contracts."""

from __future__ import annotations

import math
import resource
import sys
import time
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict


class Stats(BaseModel):
    """Machine-readable result for one predeclared workload."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    count: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    peak_rss_mib: float
    completion_seconds: float | None = None


class SampleBatch(BaseModel):
    """Raw per-operation timings and per-process memory for aggregation."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    samples_ms: tuple[float, ...]
    peak_rss_mib: float


def peak_rss_mib() -> float:
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    byte_count = value if sys.platform == "darwin" else value * 1024
    return byte_count / (1024 * 1024)


def percentile(samples: list[float], quantile: float) -> float:
    index = max(0, math.ceil(quantile * len(samples)) - 1)
    return sorted(samples)[index]


def stats(samples: list[float], completion: float | None = None) -> Stats:
    return Stats(
        count=len(samples),
        p50_ms=percentile(samples, 0.50),
        p95_ms=percentile(samples, 0.95),
        p99_ms=percentile(samples, 0.99),
        peak_rss_mib=peak_rss_mib(),
        completion_seconds=completion,
    )


def sample(operation: Callable[[], object], warmup: int, count: int) -> list[float]:
    for _ in range(warmup):
        operation()
    samples: list[float] = []
    for _ in range(count):
        started = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return samples


def require(result: Stats, latency: tuple[float, float, float], rss: float) -> Stats:
    observed = (result.p50_ms, result.p95_ms, result.p99_ms)
    if any(value > limit for value, limit in zip(observed, latency, strict=True)):
        raise RuntimeError(f"latency budget missed: observed={observed}, limits={latency}")
    if result.peak_rss_mib > rss:
        raise RuntimeError(f"RSS budget missed: {result.peak_rss_mib:.2f} > {rss:.2f} MiB")
    return result
