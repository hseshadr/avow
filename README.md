# Avow

Avow creates signed, tamper-evident records. Give it any JSON evidence; it returns a
receipt that another machine can verify offline.

## TL;DR

Use Avow when a decision or release record must remain portable and independently
checkable. It keeps the evidence inside the receipt, binds that evidence to an Ed25519
key, and needs no service or database to verify it later.

Prerequisites: Bash, Python 3.12 or newer, and [`uv`](https://docs.astral.sh/uv/).

From this checkout, run the complete evidence loop:

```bash
bash examples/run_evidence_loop.sh
```

Expected output:

```text
Receipt schema: avow.receipt/v1
Original receipt: avow.verify.ok
Altered receipt: avow.payload_hash_mismatch (expected)
```

The schema line names the exact receipt envelope Avow emitted and verified. The next
line means the payload hash, pinned signer, and signature all matched. The final line
is an expected rejection: the demo changed the deployment outcome inside a copy of the
receipt, so its stored hash no longer matched its payload.

## Installation

This checkout contains the source; it is not a published or installed artifact.
Prepare its local environment with:

```bash
uv sync
```

Beside this repository's `pyproject.toml`, the demo deliberately selects the checkout's
`uv run ... avow` path before any installed `avow` on `PATH`, so it exercises this
source checkout. When only `examples/` is copied away, it uses the installed command
instead. To prove that packaged path, build and install the wheel as shown in the
[quickstart](QUICKSTART.md).

## Architecture

Avow has two production package surfaces and no hidden third core:

```text
src/avow/  → Python wheel: avow/
ts/src/    → npm tarball: dist/
```

The Python wheel owns canonical JSON, hashes, Ed25519 key handling, receipts, the
`avow` command, and the append-only ledger. The npm package `@edgeproc/avow` owns the
portable TypeScript canonicalization and receipt surface; it does not ship the Python
ledger. Contract tests build both artifacts and check this mapping against their real
contents.

The cores do not interpret the evidence they seal. Domain calculations and
action-policy logic belong to their applications, not to Avow.

## A realistic evidence loop

[`examples/evidence.json`](examples/evidence.json) records a deployment decision with
an artifact digest, policy identity, environment, and completed checks. The script:

1. generates a local Ed25519 key pair;
2. signs that JSON into a self-contained receipt;
3. verifies the receipt against the separately pinned public key;
4. changes only the copied receipt's deployment outcome; and
5. requires the altered copy to fail with `avow.payload_hash_mismatch`.

The script creates a temporary directory and removes it on exit. Set `AVOW_DEMO_DIR`
to an empty directory if you want to inspect `receipt.json`,
`altered-receipt.json`, and the generated keys afterward.

## What this proves

`avow.verify.ok` proves that the evidence is unchanged from the bytes Avow sealed,
that the embedded signer matches the public key the verifier supplied independently,
and that the Ed25519 signature is valid for that evidence. Verification runs locally;
the runtime makes no network request.

A Python ledger can additionally prove that every retained receipt is valid, ordered,
linked, and ends at an externally pinned head. See [operations](docs/OPERATIONS.md).

## What this does not prove

A valid receipt does not prove that the evidence is correct, complete, fair, current,
or honest. It does not prove wall-clock time or prevent a valid receipt from being
presented again. A neighboring ledger-head file is only a convenience copy, not an
independent trust anchor. Receipts contain their JSON payload in cleartext; signing is
not encryption or redaction.

## Version and publication status

The Python source version is `0.5.0.dev0`; the npm source version is its SemVer spelling,
`0.5.0-dev.0`. Both are local split candidates and are not published. The published
`avow` `0.4.1` remains untouched. The published `@edgeproc/avow` `0.4.1` also remains
untouched. No command in this README publishes, tags, or changes either registry release.

## Next steps

- [Quickstart](QUICKSTART.md): build a real wheel, run the demo, and use the CLI.
- [Operations](docs/OPERATIONS.md): trust anchors, ledger recovery, error codes,
  local-only behavior, limits, and key handling.
- [TypeScript package](ts/README.md): browser/runtime receipt API.
- [Provenance](PROVENANCE.md): repository and release identity.

## Maintainer release gate

The end-user demo above needs only Bash, Python 3.12 or newer, and `uv`. Contributors
running the complete release gate additionally need Node 22, Corepack, pnpm 11.5.0,
actionlint, gitleaks, and ShellCheck. Corepack selects the pinned pnpm version from
`ts/package.json`.

```bash
node --version
pnpm --version
uv run poe release-candidate
```

The gate rejects any active Node major other than 22 before installing dependencies.
