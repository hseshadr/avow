# Avow quickstart

## TL;DR

Avow signs arbitrary JSON into a portable receipt and verifies it locally against a
public key you pin. This walkthrough uses a real deployment decision, not a toy string.

## Run from the source checkout

```bash
bash examples/run_evidence_loop.sh
```

The script needs Bash, Python 3.12 or newer, and either `uv` in this checkout or an
installed `avow` command. It creates no database and contacts no service.

Expected output:

```text
Original receipt: avow.verify.ok
Altered receipt: avow.payload_hash_mismatch (expected)
```

- `Original receipt: avow.verify.ok` means the payload hash, caller-pinned signer,
  and Ed25519 signature matched.
- `Altered receipt: avow.payload_hash_mismatch (expected)` means changing the copied
  receipt's deployment outcome was detected before signature verification.

Set `AVOW_DEMO_DIR` to an empty directory to keep the generated artifacts:

```bash
AVOW_DEMO_DIR="$PWD/demo-output" bash examples/run_evidence_loop.sh
```

## Prove the wheel, outside the repository

The project is not published at version `0.5.0.dev0`, so install the wheel you build:

```bash
uv build --wheel
tmp="$(mktemp -d)"
uv venv --python 3.13 "$tmp/venv"
uv pip install --python "$tmp/venv/bin/python" dist/avow-0.5.0.dev0-py3-none-any.whl
cp -R examples "$tmp/examples"
PATH="$tmp/venv/bin:$PATH" bash "$tmp/examples/run_evidence_loop.sh"
```

That copy contains only `examples/`; it does not rely on imports from `src/`.

## Use the CLI directly

```bash
uv run avow keygen --out signing.key
uv run avow sign --payload examples/evidence.json --key signing.key --out receipt.json
uv run avow verify --receipt receipt.json --public-key signing.key.pub
uv run avow ledger append --receipt receipt.json --ledger evidence.jsonl --head evidence.head
uv run avow ledger verify --ledger evidence.jsonl --head evidence.head --public-key signing.key.pub
```

Successful commands print, in order, `avow.keygen.ok`, `avow.sign.ok`,
`avow.verify.ok`, `avow.ledger.append.ok`, and `avow.ledger.verify.ok`. The private key
is `signing.key`; the separately shareable verifier key is `signing.key.pub`.

## Supported JSON values

The CLI accepts the complete Avow `JsonValue` domain at the top level: objects,
arrays, Unicode-scalar strings, finite numbers, booleans, and `null`. Object keys must
also be Unicode-scalar strings. For Python/TypeScript parity, every integer-valued
number must be within `-(2^53 - 1)` through `2^53 - 1`, even when Python parsed it as
an `int`. Encode larger exact quantities as strings. `NaN`, infinities, lone UTF-16
surrogates, non-string object keys, and values outside this closed I-JSON-compatible
domain fail before signing.

Library callers may also sign a frozen Pydantic model. Mutable models are rejected;
accepted subjects are deep-copied into one detached snapshot before hashing, signing,
or storing.

## Read failures safely

The command emits stable codes, not rejected JSON, key material, paths, tracebacks, or
usage text. Ordinary validation and I/O failures exit `2`. A durable ledger append
whose head was not installed, or any later append against a mismatched head, emits
only `avow.ledger_recovery_required` and exits `3`. Do not retry that state blindly;
follow [ledger recovery](docs/OPERATIONS.md#ledger-recovery).

## What this proves

Receipt verification proves unmodified evidence under the public key you supplied.
Ledger verification additionally proves entry signatures, order, links, and the final
head you supplied.

## What this does not prove

Avow does not validate the evidence's meaning, author honesty, correctness, freshness,
or wall-clock time. It does not encrypt payloads or stop semantic replay. Keep sensitive
data out of receipts and ledgers unless cleartext retention is intended.
