"""Isolated deterministic real-process ledger workload."""

from __future__ import annotations

import multiprocessing
import tempfile
import time
from functools import partial
from multiprocessing.process import BaseProcess
from pathlib import Path

from nacl.signing import SigningKey

from avow.benchmarks._contracts import SampleBatch, Stats, peak_rss_mib, require, sample, stats
from avow.benchmarks.envelope import BenchmarkSubject
from avow.envelope import SignedReceipt, sign_payload
from avow.ledger import append_and_save_head, read_head, verify_integrity

_SEED = bytes(range(32))
_ENTRY_COUNT = 200
_COMPLETION_LIMIT_SECONDS = 15


def _worker(ledger: Path, head: Path, result: Path) -> None:
    receipt = sign_payload(BenchmarkSubject(evidence="ledger"), SigningKey(_SEED))
    operation = partial(append_and_save_head, receipt, path=ledger, head_path=head)
    batch = SampleBatch(samples_ms=tuple(sample(operation, 0, 50)), peak_rss_mib=peak_rss_mib())
    result.write_text(batch.model_dump_json(), encoding="utf-8")


def _start(ledger: Path, head: Path, results: list[Path]) -> list[BaseProcess]:
    context = multiprocessing.get_context("spawn")
    workers: list[BaseProcess] = [
        context.Process(target=_worker, args=(ledger, head, result)) for result in results
    ]
    for worker in workers:
        worker.start()
    return workers


def _join(workers: list[BaseProcess]) -> None:
    for worker in workers:
        worker.join(timeout=_COMPLETION_LIMIT_SECONDS)
    exit_codes = [worker.exitcode for worker in workers]
    if exit_codes != [0, 0, 0, 0]:
        raise RuntimeError(f"ledger workers failed or deadlocked: {exit_codes}")


def _aggregate(results: list[Path], completion: float) -> Stats:
    batches = [SampleBatch.model_validate_json(path.read_text()) for path in results]
    samples = [value for batch in batches for value in batch.samples_ms]
    peak = max(batch.peak_rss_mib for batch in batches)
    return stats(samples, completion).model_copy(update={"peak_rss_mib": peak})


def _verify(ledger: Path, head: Path) -> None:
    receipts = verify_integrity(
        ledger,
        SignedReceipt[BenchmarkSubject],
        expected_public_key=bytes(SigningKey(_SEED).verify_key).hex(),
        expected_head=read_head(head),
    )
    if len(receipts) != _ENTRY_COUNT:
        raise RuntimeError(f"ledger lost entries: expected {_ENTRY_COUNT}, found {len(receipts)}")


def _run(root: Path) -> Stats:
    ledger, head = root / "ledger.jsonl", root / "ledger.head"
    results = [root / f"worker-{index}.json" for index in range(4)]
    started = time.perf_counter()
    _join(_start(ledger, head, results))
    _verify(ledger, head)
    return _aggregate(results, time.perf_counter() - started)


def benchmark() -> Stats:
    with tempfile.TemporaryDirectory() as directory:
        result = _run(Path(directory))
    if result.completion_seconds is None or result.completion_seconds > _COMPLETION_LIMIT_SECONDS:
        raise RuntimeError(f"ledger completion budget missed: {result.completion_seconds}")
    return require(result, (10, 50, 250), 128)


if __name__ == "__main__":
    print(benchmark().model_dump_json())
