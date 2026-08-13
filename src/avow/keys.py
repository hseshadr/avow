"""Ed25519 signing-key custody. The private key is a 32-byte seed written to a
0600 file; it is never logged and never committed (``*.key`` is gitignored). The
public verify key is recovered from the seed and travels inside each receipt."""

from __future__ import annotations

import os
from pathlib import Path

from nacl.signing import SigningKey

from avow._atomic import atomic_write_bytes, discard_staged, stage_bytes, sync_directory

_SEED_BYTES = 32


def generate_signing_key() -> SigningKey:
    """Generate a fresh random Ed25519 signing key."""
    return SigningKey.generate()


def save_signing_key(key: SigningKey, *, path: Path) -> None:
    """Atomically and durably replace ``path`` with an owner-only 32-byte seed."""
    atomic_write_bytes(bytes(key), path=path)


def load_signing_key(path: Path) -> SigningKey:
    """Load a signing key from its 32-byte seed file."""
    seed = path.read_bytes()
    if len(seed) != _SEED_BYTES:
        raise ValueError(f"signing key must be {_SEED_BYTES} bytes, got {len(seed)}")
    return SigningKey(seed)


def public_key_hex(key: SigningKey) -> str:
    """Return the hex-encoded Ed25519 public verify key for ``key``."""
    return bytes(key.verify_key).hex()


def save_public_key(key: SigningKey, *, path: Path) -> None:
    """Write the hex public verify key to ``path`` for out-of-band distribution.

    The public key is not secret; it is what a verifier pins to authenticate
    receipts, so it is meant to travel separately from the private seed."""
    atomic_write_bytes(public_key_hex(key).encode(), path=path)


def _claim(staged: Path, path: Path) -> None:
    """Publish one staged file without replacing any existing filesystem entry."""
    os.link(staged, path, follow_symlinks=False)


def _rollback_claim(staged: Path, path: Path) -> None:
    """Remove only the destination inode created from this stage."""
    try:
        if path.samefile(staged):
            path.unlink()
    except FileNotFoundError:
        pass


def _rollback_pair(private_stage: Path, public_stage: Path, private: Path, public: Path) -> None:
    """Remove this operation's claims and persist their directory removals."""
    _rollback_claim(private_stage, private)
    _rollback_claim(public_stage, public)
    _sync_pair(private, public)


def _sync_pair(private: Path, public: Path) -> None:
    """Persist both pair destination directories after their claims."""
    for parent in {private.parent, public.parent}:
        sync_directory(parent)


def _commit_pair(private_stage: Path, public_stage: Path, private: Path, public: Path) -> None:
    """Claim public then private, rolling back either on every reported failure."""
    _claim(public_stage, public)
    try:
        _claim(private_stage, private)
        _sync_pair(private, public)
    except OSError:
        _rollback_pair(private_stage, public_stage, private, public)
        raise


def _stage_pair(key: SigningKey, private: Path, public: Path) -> tuple[Path, Path]:
    """Prepare both complete pair members before either becomes visible."""
    private_stage = stage_bytes(bytes(key), path=private)
    try:
        public_stage = stage_bytes(public_key_hex(key).encode(), path=public)
    except OSError:
        discard_staged(private_stage)
        raise
    return private_stage, public_stage


def _create_pair(private: Path, public: Path) -> SigningKey:
    """Create one new pair while refusing to rotate an existing identity."""
    if private.exists() or private.is_symlink() or public.exists() or public.is_symlink():
        raise FileExistsError("keygen refuses to overwrite an existing key artifact")
    key = generate_signing_key()
    private_stage, public_stage = _stage_pair(key, private, public)
    try:
        _commit_pair(private_stage, public_stage, private, public)
    finally:
        discard_staged(private_stage)
        discard_staged(public_stage)
    return key


def _create_key_pair(*, private_path: Path, public_path: Path) -> SigningKey:
    """Internal CLI helper for race-safe, no-overwrite pair creation."""
    return _create_pair(private_path, public_path)


def read_public_key(path: Path) -> str:
    """Read a hex public verify key written by :func:`save_public_key`."""
    return path.read_text(encoding="utf-8").strip()
