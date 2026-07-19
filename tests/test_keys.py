from __future__ import annotations

import stat
from pathlib import Path

from avow.keys import generate_signing_key, load_signing_key, save_signing_key


def test_should_round_trip_a_signing_key_through_disk(tmp_path: Path) -> None:
    # Given a generated signing key saved to disk
    key = generate_signing_key()
    path = tmp_path / "signing.key"
    save_signing_key(key, path=path)
    # When reloaded
    reloaded = load_signing_key(path)
    # Then the reloaded key is byte-identical
    assert bytes(reloaded) == bytes(key)


def test_should_write_key_file_with_owner_only_permissions(tmp_path: Path) -> None:
    # Given a saved key
    path = tmp_path / "signing.key"
    save_signing_key(generate_signing_key(), path=path)
    # When inspecting file permissions
    mode = stat.S_IMODE(path.stat().st_mode)
    # Then only the owner can read/write it
    assert mode == 0o600


def test_should_reset_permissions_when_rekeying_over_a_loose_file(tmp_path: Path) -> None:
    # Given an existing key file with loose (world-readable) permissions
    path = tmp_path / "signing.key"
    path.write_bytes(b"x" * 32)
    path.chmod(0o644)
    # When a new key is written over it
    save_signing_key(generate_signing_key(), path=path)
    # Then the mode is forced back to owner-only (O_CREAT|O_TRUNC never resets it)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
