"""Hash-chained receipt ledger (JSONL) of signed entries, subject-agnostic.

Each line is one ``LedgerEntry``: a ``SignedReceipt`` of some subject ``S``, plus the
two fields that make the log a *log* — its sequence number and the hash of the entry
before it. Writes are ``O_APPEND`` under a lock, so appending never rewrites history.

Two independent checks, because they answer two different questions:

* **Per entry** — ``verify_integrity`` re-derives each payload's hash AND verifies its
  Ed25519 signature against a pinned public key. This answers "is this line genuine?"
  with the signer's *public* key alone, never the secret seed. A hash-only check would
  be fooled by an adversary who edits a payload and recomputes its (public) content
  hash; the detached signature is the thing they cannot forge.
* **Across entries** — the chain walk. Every entry's ``prev_hash`` must equal the hash
  of the entry before it and its ``seq`` must equal its position, so deleting,
  reordering, replaying or splicing in a foreign entry breaks a link. This answers
  "are these the lines, in this order?", which no per-line signature ever can: a
  signature binds an entry to a signer, never to a ledger or to a position in one.

A chain alone still cannot stop **truncation** — drop the last N lines and what remains
is a perfectly self-consistent chain, as is an empty file. So the chain ends at a head
(``LedgerHead``: how many entries, and the hash of the last) that the caller pins
**out-of-band**, exactly as ``expected_public_key`` is pinned. ``append`` returns the
new head; ``verify_integrity`` requires the pinned one and rejects any ledger that does
not end exactly there. The honest limit: this moves the trust requirement from N lines
to 32 bytes, it does not remove it. Those 32 bytes must live somewhere the ledger's
writer cannot reach — another host, a git commit, a printout. A head file sitting
beside the ledger buys nothing against an attacker who can write both.

Reading needs the concrete receipt type to deserialize into (``SignedReceipt[S]``),
so ``read_all`` / ``verify_integrity`` take it as an argument. The score face passes
``ScoreReceipt``; other faces pass their own parametrization. Chain-walking needs no
such type: an entry's receipt is carried as JSON, so integrity of the *sequence* is
checkable by a party that cannot parse the subjects at all.

Reads fail CLOSED. A ledger that is missing, is not a regular file, cannot be read, or
holds an unparseable line raises a coded error rather than reading as "no entries" —
otherwise a mistyped path would silently report a clean bill of health for a file
nobody ever opened. An existing but empty ledger is a legitimate initial state and
verifies only against the empty head; a ledger truncated to nothing now fails against
the head its operator pinned, which is the case the old zero-entry pass could not see."""

from __future__ import annotations

import fcntl
import os
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from pydantic import BaseModel, ConfigDict, ValidationError

from avow.canonical import JsonValue, content_hash
from avow.envelope import SignedReceipt, payload_digest
from avow.errors import (
    LedgerEntryMalformed,
    LedgerHeadUnreadable,
    LedgerHeadWriteFailed,
    LedgerIntegrityError,
    LedgerLockTimeout,
    LedgerUnreadable,
    SignatureInvalid,
)
from avow.verify import verify_receipt

# The predecessor of the first entry. No real digest can collide with it, so an entry
# claiming genesis provenance can only ever be at position 0.
GENESIS_HASH = "sha256:" + "0" * 64
DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_POLL_SECONDS = 0.01


class LedgerHead(BaseModel):
    """Where the chain ends: how many entries the ledger holds, and the last one's hash.

    This is the whole out-of-band pin — 32 bytes plus a count, regardless of how long
    the ledger grows. Both fields matter: the hash alone cannot describe an empty
    ledger, and a count alone would be trivial to fake."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    count: int
    head_hash: str


EMPTY_HEAD = LedgerHead(count=0, head_hash=GENESIS_HASH)
"""The head of a ledger nobody has written to yet — a legitimate state to pin."""


class LedgerEntry(BaseModel):
    """One ledger line: its position, its predecessor's hash, and the receipt itself.

    The receipt is held as JSON rather than a parsed subject so the chain can be walked
    without knowing what any face's subject looks like; ``verify_integrity`` parses it
    into the caller's concrete receipt type when it comes time to check signatures."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int
    prev_hash: str
    receipt: JsonValue


def entry_hash(entry: LedgerEntry) -> str:
    """The chain link: a hash binding this entry's position, its predecessor AND its
    whole receipt — signature included. Changing any of the three breaks the next link."""
    return content_hash(entry.model_dump(mode="json"))


def _head_after(entry: LedgerEntry) -> LedgerHead:
    """The head a ledger has once ``entry`` is its last line."""
    return LedgerHead(count=entry.seq + 1, head_hash=entry_hash(entry))


def _link_onto[S: BaseModel](head: LedgerHead, receipt: SignedReceipt[S]) -> LedgerEntry:
    """Build the entry that extends a chain ending at ``head``."""
    return LedgerEntry(
        seq=head.count,
        prev_hash=head.head_hash,
        receipt=receipt.model_dump(mode="json"),
    )


def _parse_entry(line: str) -> LedgerEntry:
    """Parse one ledger line, reporting a coded cause instead of a parse traceback."""
    try:
        return LedgerEntry.model_validate_json(line)
    except ValidationError as exc:
        raise LedgerEntryMalformed(f"ledger entry is not a valid chained entry: {exc}") from exc


def _open_lines(handle: TextIO) -> list[str]:
    """Every non-blank line currently in an open ledger, read from the top."""
    handle.seek(0)
    return [line for line in handle.read().splitlines() if line.strip()]


def _head_of_lines(lines: list[str]) -> LedgerHead:
    """The head these lines claim. Untrusted by construction — an appender chains onto
    whatever it finds; only the pinned head decides whether that was the real history."""
    if not lines:
        return EMPTY_HEAD
    return _head_after(_parse_entry(lines[-1]))


def _acquire_lock(handle: TextIO, timeout_seconds: float) -> None:
    """Take the ledger lock or fail with a stable code at the bounded deadline."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                message = f"ledger lock not acquired within {timeout_seconds:.3f} seconds"
                raise LedgerLockTimeout(message) from exc
            time.sleep(min(_LOCK_POLL_SECONDS, remaining))


@contextmanager
def _locked_ledger(path: Path, timeout_seconds: float) -> Iterator[TextIO]:
    """Open the append-only ledger and hold its process lock for the caller."""
    with path.open("a+", encoding="utf-8") as handle:
        _acquire_lock(handle, timeout_seconds)
        try:
            yield handle
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _sync_directory(path: Path) -> None:
    """Persist a directory entry or replacement on an in-scope local filesystem."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _append_locked[S: BaseModel](
    receipt: SignedReceipt[S], *, handle: TextIO, path: Path
) -> LedgerHead:
    """Append and durably flush while the caller holds the ledger lock."""
    entry = _link_onto(_head_of_lines(_open_lines(handle)), receipt)
    handle.write(entry.model_dump_json() + "\n")
    handle.flush()
    os.fsync(handle.fileno())
    _sync_directory(path.parent)
    return _head_after(entry)


def append[S: BaseModel](
    receipt: SignedReceipt[S],
    *,
    path: Path,
    lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> LedgerHead:
    """Durably append under a bounded process lock and return the new head.

    Export the returned head beyond the ledger writer; otherwise truncation is not
    detectable. See ``docs/OPERATIONS.md`` for failure and recovery bounds."""
    with _locked_ledger(path, lock_timeout_seconds) as handle:
        return _append_locked(receipt, handle=handle, path=path)


def _require_readable_file(path: Path) -> None:
    """Fail closed unless ``path`` is a regular file this process can read.

    ``is_file()`` rejects both the absent path and the directory-in-its-place case;
    the access check rejects a file whose permissions deny reading."""
    if not path.is_file():
        raise LedgerUnreadable(f"ledger is not a readable file: {path}")
    if not os.access(path, os.R_OK):
        raise LedgerUnreadable(f"ledger cannot be read (permission denied): {path}")


def read_entries(path: Path) -> tuple[LedgerEntry, ...]:
    """Read every chained entry, failing closed if the ledger cannot be read.

    Subject-agnostic: this is enough to walk the chain, never enough to check a
    signature."""
    _require_readable_file(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    return tuple(_parse_entry(line) for line in lines if line.strip())


def _entry_receipt[S: BaseModel](
    entry: LedgerEntry, receipt_type: type[SignedReceipt[S]]
) -> SignedReceipt[S]:
    """Parse an entry's receipt into the caller's concrete type."""
    try:
        return receipt_type.model_validate(entry.receipt)
    except ValidationError as exc:
        raise LedgerEntryMalformed(f"ledger entry is not a valid receipt: {exc}") from exc


def read_all[S: BaseModel](
    path: Path, receipt_type: type[SignedReceipt[S]]
) -> tuple[SignedReceipt[S], ...]:
    """Read every receipt from the ledger, failing closed if it cannot be read."""
    return tuple(_entry_receipt(entry, receipt_type) for entry in read_entries(path))


def current_head(path: Path) -> LedgerHead:
    """The head this FILE claims — derived from its own bytes, therefore not evidence.

    Useful for recording the head after a batch of appends, and for modelling the
    strongest attacker: one who rewrites the ledger *and* recomputes a self-consistent
    chain over it. Verification must still reject that, because it is checked against
    the head the operator pinned earlier, not against the file's own arithmetic."""
    entries = read_entries(path)
    return _head_after(entries[-1]) if entries else EMPTY_HEAD


def _require_link(entry: LedgerEntry, position: int, prev_hash: str) -> None:
    """Fail closed unless ``entry`` is the entry that belongs at ``position``."""
    if entry.seq != position:
        raise LedgerIntegrityError(
            f"ledger entry at position {position} claims sequence {entry.seq}"
        )
    if entry.prev_hash != prev_hash:
        raise LedgerIntegrityError(f"ledger entry {position} does not chain to the entry before it")


def _verify_chain(entries: tuple[LedgerEntry, ...], expected_head: LedgerHead) -> None:
    """Walk the chain from genesis and require it to end exactly at the pinned head.

    The walk catches deletion, reordering, replay and splicing; the head comparison is
    what catches truncation, which leaves a chain that is self-consistent but short."""
    prev_hash = GENESIS_HASH
    for position, entry in enumerate(entries):
        _require_link(entry, position, prev_hash)
        prev_hash = entry_hash(entry)
    head = LedgerHead(count=len(entries), head_hash=prev_hash)
    if head != expected_head:
        raise LedgerIntegrityError(
            f"ledger ends at {head.count} entries / {head.head_hash}, "
            f"but the pinned head is {expected_head.count} entries / {expected_head.head_hash}"
        )


def _verify_entry[S: BaseModel](receipt: SignedReceipt[S], expected_public_key: str) -> None:
    """Fail closed unless the entry's hash matches AND its signature verifies under the
    pinned key. The hash pre-check names the corrupted entry; the signature check is what
    stops an adversary who recomputed the hash from laundering a forged payload through."""
    if payload_digest(receipt.payload) != receipt.payload_hash:
        raise LedgerIntegrityError(f"tampered ledger entry: {receipt.payload_hash}")
    try:
        verify_receipt(receipt, expected_public_key=expected_public_key)
    except SignatureInvalid as exc:
        raise LedgerIntegrityError(f"tampered ledger entry: {receipt.payload_hash}") from exc


def verify_integrity[S: BaseModel](
    path: Path,
    receipt_type: type[SignedReceipt[S]],
    *,
    expected_public_key: str,
    expected_head: LedgerHead,
) -> tuple[SignedReceipt[S], ...]:
    """Require every signature and link plus both caller-supplied pins."""
    entries = read_entries(path)
    receipts = tuple(_entry_receipt(entry, receipt_type) for entry in entries)
    for receipt in receipts:
        _verify_entry(receipt, expected_public_key)
    _verify_chain(entries, expected_head)
    return receipts


def _stage_head(head: LedgerHead, path: Path) -> Path:
    """Write and sync a complete head in the destination directory."""
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(head.model_dump_json() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


def _install_head(head: LedgerHead, path: Path) -> None:
    """Atomically install a staged head, cleaning up on every failure."""
    staged = _stage_head(head, path)
    try:
        os.replace(staged, path)
        _sync_directory(path.parent)
    except OSError as exc:
        staged.unlink(missing_ok=True)
        raise LedgerHeadWriteFailed(f"could not durably write ledger head: {path}") from exc


def save_head(head: LedgerHead, *, path: Path) -> None:
    """Write a head for the operator to carry out-of-band.

    Writing it *next to the ledger* is a convenience for copying it elsewhere, never a
    control: anyone who can rewrite the ledger can rewrite a file beside it."""
    try:
        _install_head(head, path)
    except OSError as exc:
        raise LedgerHeadWriteFailed(f"could not durably write ledger head: {path}") from exc


def append_and_save_head[S: BaseModel](
    receipt: SignedReceipt[S],
    *,
    path: Path,
    head_path: Path,
    lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> LedgerHead:
    """Append and atomically save its convenience pin under one process lock.

    Export the head beyond the ledger writer for an actual truncation boundary."""
    with _locked_ledger(path, lock_timeout_seconds) as handle:
        head = _append_locked(receipt, handle=handle, path=path)
        save_head(head, path=head_path)
        return head


def read_head(path: Path) -> LedgerHead:
    """Read a pinned head written by :func:`save_head`, failing closed if unusable.

    A missing or malformed pin means the verifier has nothing to check against, which
    is a failure — never a licence to verify the ledger against itself."""
    try:
        return LedgerHead.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise LedgerHeadUnreadable(f"pinned ledger head is unusable: {path}") from exc
