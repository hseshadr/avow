# Operating Avow

## TL;DR

Keep private keys private, distribute verifier keys through an independent trusted
channel, and pin ledger heads somewhere the ledger writer cannot rewrite. If Avow
reports `avow.ledger_recovery_required`, stop appending and reconcile the durable tail
before installing a new head.

## Runtime and network boundary

Signing, receipt verification, ledger append, and ledger verification are local file
and cryptographic operations. Avow runtime code opens no socket and calls no remote
service. Installing dependencies may use your package manager's configured network;
that is outside Avow's runtime boundary.

Receipts include the payload in cleartext. The ledger is local JSONL and Avow has no
automatic upload, telemetry, timestamp server, certificate authority, key server, or
background process. Applications remain responsible for access controls, backups,
retention, deletion, and any deliberate export.

## Trust anchors

Receipt verification needs a public key obtained independently of the receipt. Never
treat the receipt's embedded `public_key` as trusted merely because it is present.
Distribute `signing.key.pub` through a channel whose identity your verifier already
trusts.

Ledger verification needs two caller-supplied pins:

- the expected public key, which identifies the permitted signer; and
- the expected `LedgerHead`, which identifies the permitted final count and hash.

The `--head` file written beside a ledger is convenient for copying, but an attacker
who can rewrite both files can truncate both consistently. Store the authoritative
head out of band—for example in a protected release record or a separately controlled
host—and supply that pin during verification.

## Append transaction

`avow ledger append` takes a bounded exclusive lock, checks that the current ledger
matches the current convenience head, appends and durably flushes one complete JSONL
entry, then atomically installs the new head. The defaults support at most 100,000
entries, 64 MiB per ledger, and 64 KiB per encoded line; the lock deadline is five
seconds in the Python API. Reads fail closed for missing files, non-regular files,
malformed/partial lines, invalid signatures, broken links, or a final-head mismatch.

## Ledger recovery

The ledger append is durable before its convenience head is installed. A crash or
head-write failure in between therefore leaves a real new ledger entry and the prior
head. Avow reports `avow.ledger_recovery_required` with exit `3`. Every later combined
append also fails closed while those two files disagree; Avow never absorbs the tail
into a later append automatically.

Recovery is an operator decision, not a retry loop:

1. stop every writer and preserve the ledger, old head, receipt, and operational logs;
2. compare the old out-of-band head with the preserved ledger prefix;
3. independently establish whether the durable tail is the intended receipt;
4. verify the tail's signer, payload, sequence, predecessor, and resulting head; and
5. only then install that resulting head with the Python `save_head` API and replace
   the out-of-band pin.

There is intentionally no CLI command that blesses an unpinned tail. `current_head()`
reports what the file claims, not trusted evidence; never feed it directly to
`save_head()` without the investigation above. If intent cannot be established, keep
the system stopped and restore through your separately audited recovery process.

## Stable command boundary

Successful commands write one code to standard output:

| Operation | Code |
| --- | --- |
| key generation | `avow.keygen.ok` |
| sign | `avow.sign.ok` |
| receipt verify | `avow.verify.ok` |
| ledger append | `avow.ledger.append.ok` |
| ledger verify | `avow.ledger.verify.ok` |

Expected failures write one stable code to standard error. They do not echo arguments,
payloads, key bytes, exception messages, tracebacks, or usage text. Parser, validation,
key, file, receipt-schema, canonicalization, signer, signature, payload-hash, ledger
configuration, lock, size, read, parse, integrity, and head-read failures exit `2`.
Recovery-required state exits `3`; a failed head installation is deliberately
translated to that same recovery code because the ledger entry may already be durable.

Applications should branch on typed `AvowError.code` values in Python/TypeScript and
on the stable command code plus exit status at the process boundary. Do not match
human-readable exception messages.

## The shared JSON boundary

Python and TypeScript share one portable `JsonValue`/I-JSON-compatible domain:

- object values with Unicode-scalar string keys;
- arrays;
- Unicode-scalar string values;
- finite numbers whose integer-valued members stay within ±(2^53−1);
- booleans; and
- `null`.

Every receipt uses the exact envelope schema `avow.receipt/v1`. A missing or unsupported
schema fails first with `avow.receipt_schema_mismatch`, before payload or signer checks.

Larger exact integers must be strings. NaN, positive/negative infinity, lone surrogate
code points, non-string keys, functions, symbols, accessors, sparse arrays, cyclic
graphs, custom-prototype TypeScript objects, and mutable Pydantic models are outside
the accepted boundary. Avow snapshots accepted caller-owned data before canonicalizing
it, preventing a later caller mutation from changing the receipt.

## Key and data handling

- `keygen` refuses to overwrite either the private key or its `.pub` companion.
- The private key is an unencrypted 32-byte Ed25519 seed. Its only protection is the
  owner-only `0600` mode `keygen` and `save_signing_key` apply; there is no passphrase
  and no KMS/HSM seam yet.
- On POSIX systems `load_signing_key` (and therefore `avow sign`) refuses a key file
  whose mode grants any group or other permission bit, failing closed with
  `avow.key_permissions_insecure` (exit `2` at the command boundary) before the seed is
  used. Restore the mode with `chmod 600`; if another account may have read the seed,
  treat it as compromised and rotate. Non-POSIX platforms have no comparable mode bits,
  so the check is skipped there and access control is the operator's responsibility.
  The TypeScript package never reads key files: it takes the seed as caller-held hex, so
  seed storage there is entirely the integrating application's.
- Keep private-key files outside shared evidence directories.
- A signature is authenticity and integrity, not encryption. Minimize payloads before
  signing; hashes of low-entropy personal data can still be linkable personal data.
- Back up authoritative public keys and ledger heads independently of the ledger.
- Rotation, revocation, signer authorization, retention, and deletion policy belong to
  the integrating application; Avow does not infer them (see [key rotation](#key-rotation)).

## Replay protection is caller-owned

Avow is not a replay defence. A receipt carries no nonce, audience, or expiry that Avow
checks, and a valid receipt verifies identically on every presentation. A caller that
must reject reuse builds that check on top of the envelope:

1. Put the claims inside the payload you sign, so the signature covers them — for
   example `{"nonce": "<128-bit random hex>", "aud": "deploy-gate.prod",
   "exp": "2026-09-23T12:05:00Z", "evidence": {...}}`. Claims kept outside the signed
   payload can be edited freely.
2. Call `verify_signature` (or `verifySignature` in TypeScript) against the pinned key
   first. Only a receipt that verifies has claims worth reading.
3. Then check the claims yourself: `aud` equals this verifier's identity, `exp` is in
   the future by your own trusted clock, and `nonce` is absent from your seen-nonce
   store.
4. Record the nonce in a durable seen-nonce store, atomically with accepting the
   receipt, and keep each entry at least until its `exp` passes so the store can be
   pruned.

Reject the receipt if any step fails. The ledger is not a substitute: its chain detects
a recorded line copied to another position (`avow.ledger_integrity`), but repeated
`append` calls with the same receipt are the caller's to refuse.

## Key rotation

Avow has no rotation or revocation mechanism; this is the recipe it supports:

1. Generate a new pair with `avow keygen --out <new>.key` and distribute
   `<new>.key.pub` through your trusted channel.
2. During the overlap window, pin both public keys: verify each receipt against the new
   key first and, if that fails with `avow.signer_mismatch`, against the old key. Accept
   the receipt only if one of them verifies. Remove the old pin when the window closes.
3. Keep one ledger per signing key. `verify_ledger` pins exactly one expected signer, so
   start a new ledger (and a new out-of-band head pin) for the new key rather than
   appending new-key receipts to the old key's chain. Retain the old ledger, its final
   head, and its public key for as long as its receipts must stay verifiable.
4. Destroy the old private seed once no signer needs it. If rotation is because of
   suspected compromise, remove the old public-key pin immediately instead of waiting
   for the overlap window, and treat receipts it signed after the suspected exposure as
   untrusted.

## Verification limits

Avow proves that the received payload is unchanged and signed by the caller-pinned
key. With a correctly pinned ledger head, it also detects deletion, insertion,
reordering, foreign entries, and truncation of the recorded chain.

It does not prove semantic correctness, completeness, fairness, freshness, wall-clock
time, signer honesty, authorization, confidentiality, or first presentation. A valid
receipt can be replayed forever. Applications needing semantic replay prevention must
keep caller-owned nonce or request-ID state; see
[replay protection is caller-owned](#replay-protection-is-caller-owned).
