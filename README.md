# Avow

Avow signs a JSON record into a receipt, a file anyone can check offline to confirm the record is unchanged and who signed it.

**Try it: `pip install "avow>=0.5.0"`, then run the four commands under [Try it](#try-it).**

[![CI](https://github.com/hseshadr/avow/actions/workflows/ci.yml/badge.svg)](https://github.com/hseshadr/avow/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/hseshadr/avow)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/avow)](https://pypi.org/project/avow/)

Teams often have to show later what they decided: that a release was approved, that its
tests passed, that a setting was what they say it was. Usually that record sits in a
database or a log that only they control, so an auditor or customer has to take their
word that nobody edited it. A plain checksum doesn't help much, because anyone who can
change the record can recompute the checksum too.

Avow gives the record a signature. You keep a private key and hand out the matching
public key once, ahead of time. Avow turns your JSON record into a receipt: the record,
its fingerprint, and a signature, in one small file. Anyone with your public key can
check the receipt on their own machine, with no server and no internet. If one word of
the record changed, the check refuses it. There's a Python library and command, and a
TypeScript package that reads and writes the same receipts.

**Technical docs:** [Architecture](docs/ARCHITECTURE.md) · [Getting started for developers](docs/GETTING_STARTED.md) · [Operations](docs/OPERATIONS.md) · [Quickstart](QUICKSTART.md)

## Try it

You need Python 3.12 or newer.

1. Install Avow:

```bash
pip install "avow>=0.5.0"
```

2. Make a key pair, write a record, sign it, and check it. Run these in an empty folder:

```bash
avow keygen --out signing.key
echo '{"release": "checkout-api 2.4.1", "approved_by": "dana", "tests_passed": true}' > decision.json
avow sign --payload decision.json --key signing.key --out receipt.json
avow verify --receipt receipt.json --public-key signing.key.pub
```

It prints:

```text
avow.keygen.ok
avow.sign.ok
avow.verify.ok
```

`signing.key` is your private key. Keep it to yourself. `signing.key.pub` is the public
key you give to whoever will check your receipts. `receipt.json` is the receipt. It
holds the record in plain text, plus the fingerprint, the signer's public key, and the
signature:

```json
{
    "payload": {"approved_by": "dana", "release": "checkout-api 2.4.1", "tests_passed": true},
    "payload_hash": "sha256:64a2594744910b829fe6f712750b05f87e08313a5f98af6ce2d170116d2a3fc5",
    "public_key": "47c7e14708f5e1acf35e998cc289997a19299ffef8fa86953fe99278c4ec6dd5",
    "schema": "avow.receipt/v1",
    "signature": "20e8b0a7310cbc640046ace3fedda22592fdb525d7bbf254036d61a184f6c9d7e6224187def7618791b9d5b0f39659ec8e8fe87e807307626b561d21150b4200"
}
```

Your keys and signature will differ; the fingerprint will match, because it depends only
on the record.

3. Now change who approved it, and check again:

```bash
sed 's/dana/mallory/' receipt.json > tampered.json
avow verify --receipt tampered.json --public-key signing.key.pub
echo "exit code: $?"
```

It prints:

```text
avow.payload_hash_mismatch
exit code: 2
```

The record no longer matches the fingerprint that was signed, so Avow refuses it. Every
refusal is a short, stable code like this one, so scripts can act on it. Checking a
receipt against someone else's public key fails the same way, with
`avow.signer_mismatch`.

### From Python

The same thing from Python:

```python
from avow import generate_signing_key, public_key_hex, sign_payload, verify_receipt
from avow.errors import AvowError

private_key = generate_signing_key()      # stays with whoever signs
public_key = public_key_hex(private_key)  # handed to whoever checks, ahead of time
receipt = sign_payload({"service": "checkout-api", "decision": "approved"}, private_key)
verify_receipt(receipt, expected_public_key=public_key)
print("original:", receipt.payload, "-> verified")

altered = receipt.model_copy(update={"payload": {"service": "checkout-api", "decision": "rejected"}})
try:
    verify_receipt(altered, expected_public_key=public_key)
except AvowError as error:
    print("altered: ", altered.payload, "-> refused:", error.code)
```

Its real output:

```text
original: {'service': 'checkout-api', 'decision': 'approved'} -> verified
altered:  {'service': 'checkout-api', 'decision': 'rejected'} -> refused: avow.payload_hash_mismatch
```

## How it works

Avow first writes your JSON in one fixed form (sorted keys, no extra spaces, numbers
spelled one way), so the same data always gives the same bytes. It takes a SHA-256
fingerprint of those bytes and signs them with your Ed25519 private key. To check a
receipt, Avow recomputes the fingerprint, confirms the signer is the public key you
supplied (it never trusts the key written inside the receipt), and checks the
signature. All of this is local math on local files; Avow's code opens no network
connection. If you need a history, the ledger (`avow ledger append` and
`avow ledger verify`) chains receipts so a deleted, inserted, or reordered entry is
caught. The details are in [Architecture](docs/ARCHITECTURE.md).

## What it does not do

- **It does not prove the record is true.** A receipt proves the record is unchanged and
  who signed it. It says nothing about whether the record is correct, complete, or
  current, and it carries no trusted timestamp.
- **It does not hide anything.** A receipt is not encrypted. The record sits in it as
  plain text, so keep secrets out.
- **It does not stop replay.** A valid receipt checks out every time someone shows it.
  If that matters, put a nonce, audience, or expiry inside your record and check them
  yourself; see [replay protection](docs/OPERATIONS.md#replay-protection-is-caller-owned).
- **It does not guard your key for you.** The private key is an unencrypted file,
  protected only by file permissions. Avow refuses to sign with a key file other users
  can read, but there is no KMS or HSM support yet. Anyone who copies the file can sign
  as you. See [key rotation](docs/OPERATIONS.md#key-rotation).

## When to use something else

| If you need | Use |
| --- | --- |
| To catch accidental corruption only | A plain checksum such as `sha256sum` |
| To sign files for people who already use those tools | GPG, minisign, or `ssh-keygen -Y sign` |
| Public, time-stamped signing of software releases | Sigstore or a transparency log |
| Login or API tokens | A JWT / JWS library |
| Signed JSON records that anyone can check offline, from Python or TypeScript, with no account or service | Avow |

A longer comparison is in [Architecture](docs/ARCHITECTURE.md#compared-with-other-tools).

## Install

Python 3.12 or newer:

```bash
pip install "avow>=0.5.0"
```

TypeScript, on Node.js 22.13 or newer:

```bash
npm install @edgeproc/avow@0.5.0
```

`0.5.0` is the first release built from this repository. Python releases `0.1.0` through
`0.4.1` came from an older repository and also installed stray `assay/` and `writ/`
packages that overwrote another project's files; they are being yanked, so do not
install them. If one of them broke `assay-engine`, run
`pip uninstall assay-engine && pip install assay-engine`. See the
[CHANGELOG](CHANGELOG.md).

## Develop

You need Python 3.12 or newer and [`uv`](https://docs.astral.sh/uv/); Node 22 and pnpm
only for the TypeScript package.

```bash
git clone https://github.com/hseshadr/avow.git && cd avow
uv sync --frozen --all-groups
```

Then run the demo:

```bash
bash examples/run_evidence_loop.sh
```

It signs a sample deployment decision, checks it, and shows a changed copy
being refused. To run the same checks as CI:

```bash
uv run poe gate && pnpm --dir ts gate
```

[Getting started for developers](docs/GETTING_STARTED.md) walks through setup, the
local traps we hit, a map of the code, a first change, and how to open a pull request.

## More detail

- [Architecture](docs/ARCHITECTURE.md): how receipts are built and checked, the package
  layout, the security model, and what a receipt does and does not prove.
- [Explore the interactive architecture map](docs/architecture/index.html), generated from
  [`runtime.architecture.json`](docs/architecture/runtime.architecture.json).
- [Getting started for developers](docs/GETTING_STARTED.md): from a fresh clone to your
  first pull request.
- [Operations](docs/OPERATIONS.md): distributing public keys, ledger recovery, error
  codes, replay protection, and key rotation.
- [Quickstart](QUICKSTART.md): every CLI command, the JSON values Avow accepts, and how
  to test the built wheel.
- [TypeScript package](ts/README.md): using `@edgeproc/avow`.
- [CHANGELOG](CHANGELOG.md): what changed in each release.
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately.
- [PROVENANCE.md](PROVENANCE.md): where this repository's history came from.
- Questions and bugs: [GitHub Issues](https://github.com/hseshadr/avow/issues).

## License

MIT. See [LICENSE](LICENSE).
