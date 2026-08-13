"""Small same-directory durability primitives for caller-requested artifacts."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

OWNER_ONLY = 0o600


def sync_directory(path: Path) -> None:
    """Persist directory-entry changes on the supported local filesystems."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_descriptor(descriptor: int, data: bytes, mode: int) -> None:
    """Write, permission, flush, and sync one already-created temporary file."""
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), mode)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def stage_bytes(data: bytes, *, path: Path, mode: int = OWNER_ONLY) -> Path:
    """Stage complete synced bytes beside their eventual destination."""
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    staged = Path(name)
    try:
        _write_descriptor(descriptor, data, mode)
    except OSError:
        staged.unlink(missing_ok=True)
        raise
    return staged


def discard_staged(path: Path) -> None:
    """Remove a stage that was not consumed by installation."""
    path.unlink(missing_ok=True)


def install_staged(staged: Path, *, path: Path) -> None:
    """Atomically replace a destination with a complete staged file."""
    try:
        os.replace(staged, path)
        sync_directory(path.parent)
    except OSError:
        discard_staged(staged)
        raise


def atomic_write_bytes(data: bytes, *, path: Path, mode: int = OWNER_ONLY) -> None:
    """Durably replace one file without exposing partial or truncated contents."""
    staged = stage_bytes(data, path=path, mode=mode)
    install_staged(staged, path=path)
