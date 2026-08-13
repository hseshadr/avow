"""Isolated deterministic Python envelope workload."""

from __future__ import annotations

from functools import partial

from nacl.signing import SigningKey
from pydantic import BaseModel, ConfigDict

from avow.benchmarks._contracts import Stats, require, sample, stats
from avow.envelope import sign_payload, verify_signature

_SEED = bytes(range(32))


class BenchmarkSubject(BaseModel):
    """Fixed 4 KiB envelope subject."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    evidence: str


def _operation(subject: BenchmarkSubject, key: SigningKey, public_key: str) -> None:
    receipt = sign_payload(subject, key)
    verify_signature(receipt, expected_public_key=public_key)


def benchmark() -> Stats:
    key = SigningKey(_SEED)
    subject = BenchmarkSubject(evidence="e" * 4096)
    operation = partial(_operation, subject, key, bytes(key.verify_key).hex())
    return require(stats(sample(operation, 25, 500)), (2, 4, 10), 128)


if __name__ == "__main__":
    print(benchmark().model_dump_json())
