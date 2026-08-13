from __future__ import annotations

import stat
from pathlib import Path

import pytest

import avow._atomic as atomic_module
import avow.keys as keys_module
from avow.keys import (
    _create_key_pair,
    generate_signing_key,
    load_signing_key,
    public_key_hex,
    save_public_key,
    save_signing_key,
)


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


def _raise_replace() -> None:
    raise OSError("replace failed")


def _raise_sync(*args: object) -> None:
    raise OSError("sync failed")


def test_staging_failure_removes_the_temporary_key_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "key"
    monkeypatch.setattr(atomic_module.os, "fchmod", _raise_sync)
    with pytest.raises(OSError, match="sync failed"):
        save_signing_key(generate_signing_key(), path=path)
    assert tuple(tmp_path.iterdir()) == ()


def test_pair_staging_removes_the_private_stage_when_public_staging_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_stage = keys_module.stage_bytes
    calls = 0

    def fail_second(data: bytes, *, path: Path) -> Path:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("public stage failed")
        return original_stage(data, path=path)

    monkeypatch.setattr(keys_module, "stage_bytes", fail_second)
    with pytest.raises(OSError, match="public stage failed"):
        keys_module._stage_pair(generate_signing_key(), tmp_path / "key", tmp_path / "key.pub")
    assert tuple(tmp_path.iterdir()) == ()


def test_rollback_ignores_a_claim_that_is_already_absent(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    stage.touch()
    keys_module._rollback_claim(stage, tmp_path / "absent")
    assert stage.exists()


@pytest.mark.parametrize("public", [False, True])
def test_atomic_key_helper_preserves_existing_bytes_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, public: bool
) -> None:
    # Given an existing key artifact and a filesystem refusing its atomic replacement
    path = tmp_path / "key"
    path.write_bytes(b"existing-key-bytes")
    monkeypatch.setattr(atomic_module.os, "replace", lambda *_: _raise_replace())
    # When either public helper attempts a replacement
    saver = save_public_key if public else save_signing_key
    with pytest.raises(OSError, match="replace failed"):
        saver(generate_signing_key(), path=path)
    # Then the prior artifact is complete and no staged file remains
    assert path.read_bytes() == b"existing-key-bytes"
    assert tuple(tmp_path.iterdir()) == (path,)


def test_atomic_key_helper_reports_sync_failure_with_complete_new_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "key"
    key = generate_signing_key()
    path.write_bytes(b"existing-key-bytes")
    monkeypatch.setattr(atomic_module, "sync_directory", _raise_sync)
    with pytest.raises(OSError, match="sync failed"):
        save_signing_key(key, path=path)
    assert path.read_bytes() == bytes(key)
    assert tuple(tmp_path.iterdir()) == (path,)


def test_pair_creation_rolls_back_when_the_second_install_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given the second no-overwrite claim fails after the private claim succeeded
    private, public = tmp_path / "signing.key", tmp_path / "signing.key.pub"
    original_claim = keys_module._claim
    calls = 0

    def fail_second(staged: Path, path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("second install failed")
        original_claim(staged, path)

    monkeypatch.setattr(keys_module, "_claim", fail_second)
    # When pair creation reaches that second install
    with pytest.raises(OSError, match="second install failed"):
        _create_key_pair(private_path=private, public_path=public)
    # Then neither half nor any staged bytes remain visible
    assert tuple(tmp_path.iterdir()) == ()


def test_pair_creation_rolls_back_both_claims_when_directory_sync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private, public = tmp_path / "signing.key", tmp_path / "signing.key.pub"
    calls = 0

    def fail_first_sync(private: Path, public: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("sync failed")
        for parent in {private.parent, public.parent}:
            atomic_module.sync_directory(parent)

    monkeypatch.setattr(keys_module, "_sync_pair", fail_first_sync)
    with pytest.raises(OSError, match="sync failed"):
        _create_key_pair(private_path=private, public_path=public)
    assert tuple(tmp_path.iterdir()) == ()


def test_keygen_refuses_an_existing_artifact_before_staging(tmp_path: Path) -> None:
    private, public = tmp_path / "signing.key", tmp_path / "signing.key.pub"
    private.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        _create_key_pair(private_path=private, public_path=public)
    assert private.read_bytes() == b"existing"
    assert not public.exists()


def test_pair_creation_publishes_matching_owner_only_artifacts(tmp_path: Path) -> None:
    private, public = tmp_path / "signing.key", tmp_path / "signing.key.pub"
    key = _create_key_pair(private_path=private, public_path=public)
    assert load_signing_key(private) == key
    assert public.read_text(encoding="utf-8") == public_key_hex(key)
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(public.stat().st_mode) == 0o600
