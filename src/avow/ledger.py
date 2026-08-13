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
import math
import os
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, TextIO

from pydantic import BaseModel, ConfigDict, ValidationError

from avow.canonical import JsonValue, content_hash
from avow.envelope import SignedReceipt, payload_digest
from avow.errors import (
    LedgerConfigurationInvalid,
    LedgerEntryMalformed,
    LedgerHeadUnreadable,
    LedgerHeadWriteFailed,
    LedgerIntegrityError,
    LedgerLimitExceeded,
    LedgerLockTimeout,
    LedgerUnreadable,
    SignatureInvalid,
)
from avow.verify import verify_receipt

# The predecessor of the first entry. No real digest can collide with it, so an entry
# claiming genesis provenance can only ever be at position 0.
GENESIS_HASH = "sha256:" + "0" * 64
DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_LEDGER_ENTRIES = 100_000
MAX_LEDGER_LINE_BYTES = 64 * 1024
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


def _require_ledger_size(size: int) -> None:
    """Fail before reading or appending beyond the supported memory boundary."""
    if size > MAX_LEDGER_BYTES:
        raise LedgerLimitExceeded(f"ledger exceeds {MAX_LEDGER_BYTES} bytes")


def _last_content(tail: bytes) -> bytes:
    """Return bytes before one canonical LF, rejecting a partial final line."""
    if not tail.endswith(b"\n"):
        raise LedgerEntryMalformed("ledger final line is incomplete")
    return tail[:-1]


def _require_complete_tail(tail: bytes, *, truncated: bool) -> None:
    """Reject a tail whose final line began before the bounded read."""
    content = tail[:-1] if tail.endswith(b"\n") else tail
    if truncated and b"\n" not in content:
        raise LedgerLimitExceeded(f"ledger line exceeds {MAX_LEDGER_LINE_BYTES} bytes")


def _decode_entry_line(line: bytes) -> str:
    """Decode one canonical, size-bounded JSONL content segment."""
    if len(line) + 1 > MAX_LEDGER_LINE_BYTES:
        raise LedgerLimitExceeded(f"ledger line exceeds {MAX_LEDGER_LINE_BYTES} bytes")
    if not line.strip():
        raise LedgerEntryMalformed("ledger contains a blank line")
    if line.endswith(b"\r"):
        raise LedgerEntryMalformed("ledger lines must use LF endings")
    try:
        return line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LedgerEntryMalformed("ledger entry is not valid UTF-8") from exc


def _decode_last_line(tail: bytes, *, truncated: bool) -> str:
    """Decode one bounded tail, refusing an incomplete oversized final line."""
    _require_complete_tail(tail, truncated=truncated)
    content = _last_content(tail)
    return _decode_entry_line(content.rsplit(b"\n", maxsplit=1)[-1])


def _last_line(handle: TextIO) -> str | None:
    """Read only the bounded tail needed to recover the current entry."""
    size = os.fstat(handle.fileno()).st_size
    _require_ledger_size(size)
    if size == 0:
        return None
    length = min(size, MAX_LEDGER_LINE_BYTES + 2)
    tail = os.pread(handle.fileno(), length, size - length)
    return _decode_last_line(tail, truncated=size > length)


def _current_locked_head(handle: TextIO) -> LedgerHead:
    """Recover the untrusted current head in O(one bounded line)."""
    line = _last_line(handle)
    return EMPTY_HEAD if line is None else _head_after(_parse_entry(line))


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


def _require_bounded_timeout(timeout_seconds: float) -> None:
    """Reject a deadline that could wait forever or predate the call."""
    if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        message = "ledger lock timeout must be one finite, non-negative number"
        raise LedgerConfigurationInvalid(message)


@contextmanager
def _locked_ledger(path: Path, timeout_seconds: float) -> Iterator[TextIO]:
    """Open the append-only ledger and hold its process lock for the caller."""
    _require_bounded_timeout(timeout_seconds)
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
    current = _current_locked_head(handle)
    entry = _link_onto(current, receipt)
    encoded = (entry.model_dump_json() + "\n").encode()
    _require_append_limits(handle, current, encoded)
    handle.buffer.write(encoded)
    handle.flush()
    os.fsync(handle.fileno())
    _sync_directory(path.parent)
    return _head_after(entry)


def _require_append_limits(handle: TextIO, head: LedgerHead, encoded: bytes) -> None:
    """Reject any append that would cross a declared support ceiling."""
    if head.count >= MAX_LEDGER_ENTRIES:
        raise LedgerLimitExceeded(f"ledger exceeds {MAX_LEDGER_ENTRIES} entries")
    if len(encoded) > MAX_LEDGER_LINE_BYTES:
        raise LedgerLimitExceeded(f"ledger line exceeds {MAX_LEDGER_LINE_BYTES} bytes")
    if os.fstat(handle.fileno()).st_size + len(encoded) > MAX_LEDGER_BYTES:
        raise LedgerLimitExceeded(f"ledger exceeds {MAX_LEDGER_BYTES} bytes")


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


def _decode_complete_line(line: bytes) -> str:
    """Decode one complete encoded line with exact terminator accounting."""
    if len(line) > MAX_LEDGER_LINE_BYTES:
        raise LedgerLimitExceeded(f"ledger line exceeds {MAX_LEDGER_LINE_BYTES} bytes")
    if not line.endswith(b"\n"):
        raise LedgerEntryMalformed("ledger final line is incomplete")
    return _decode_entry_line(line[:-1])


def _read_bounded_entries(handle: BinaryIO) -> list[LedgerEntry]:
    """Stream a ledger into its explicitly bounded public tuple."""
    entries: list[LedgerEntry] = []
    while line := handle.readline(MAX_LEDGER_LINE_BYTES + 1):
        entries.append(_parse_entry(_decode_complete_line(line)))
        if len(entries) > MAX_LEDGER_ENTRIES:
            raise LedgerLimitExceeded(f"ledger exceeds {MAX_LEDGER_ENTRIES} entries")
    return entries


def read_entries(path: Path) -> tuple[LedgerEntry, ...]:
    """Read every entry within the documented byte, line, and count ceilings."""
    _require_readable_file(path)
    _require_ledger_size(path.stat().st_size)
    with path.open("rb") as handle:
        entries = _read_bounded_entries(handle)
    return tuple(entries)


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


def _same_parent(left: Path, right: Path) -> bool:
    """Ask the filesystem whether two destination directories are one directory."""
    try:
        return left.parent.samefile(right.parent)
    except FileNotFoundError:
        return left.parent.resolve() == right.parent.resolve()


def _probe_absent_names(left: Path, right: Path) -> bool:
    """Ask the destination volume whether its directory rules collapse two names."""
    with tempfile.TemporaryDirectory(prefix=".avow-path-probe-", dir=left.parent) as directory:
        first, second = Path(directory) / left.name, Path(directory) / right.name
        first.touch(exist_ok=False)
        try:
            second.touch(exist_ok=False)
        except FileExistsError:
            return True
    return False


def _unchecked_absent_alias(left: Path, right: Path) -> bool:
    """Resolve absent destinations and ask their actual volume about name equality."""
    if left.exists() or right.exists():
        return False
    if left.resolve() == right.resolve():
        return True
    return _same_parent(left, right) and _probe_absent_names(left, right)


def _absent_paths_alias(left: Path, right: Path) -> bool:
    """Translate an unknowable filesystem identity into one coded failure."""
    try:
        return _unchecked_absent_alias(left, right)
    except OSError as exc:
        raise LedgerConfigurationInvalid("ledger persistence paths could not be resolved") from exc


def _paths_alias(left: Path, right: Path) -> bool:
    """Whether two path spellings name, or would name, the same filesystem entry."""
    try:
        return left.samefile(right)
    except FileNotFoundError:
        return _absent_paths_alias(left, right)
    except OSError as exc:
        raise LedgerConfigurationInvalid("ledger persistence paths could not be resolved") from exc


def _require_distinct_paths(ledger: Path, head: Path) -> None:
    """Protect the append log from replacement by its convenience head."""
    if _paths_alias(ledger, head):
        raise LedgerConfigurationInvalid("ledger and head must use distinct paths")


def append_and_save_head[S: BaseModel](
    receipt: SignedReceipt[S],
    *,
    path: Path,
    head_path: Path,
    lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> LedgerHead:
    """Append and save its convenience pin under one bounded process lock."""
    _require_distinct_paths(path, head_path)
    with _locked_ledger(path, lock_timeout_seconds) as handle:
        _require_distinct_paths(path, head_path)
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
