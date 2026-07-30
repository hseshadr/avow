# Changelog

## [0.2.0] - unreleased

Prepared in this repo, not yet tagged. A breaking release that makes three trust claims
literally true. Pair-versioned with `@edgeproc/avow` on npm; `@edgeproc/receipt-ui` is
versioned separately.

### Changed
- **BREAKING — ledger tamper-evidence is now real.** `avow.verify_integrity` and
  `assay verify-ledger` now require the signer's pinned **public** key and verify each
  entry's **Ed25519 signature**, not just re-derive its content hash. A hash-only check
  was an overclaim: an adversary with no signing key can still recompute an entry's
  public content hash and launder a forged payload past it. The signature — which only
  the private seed can produce — is what makes tampering detectable by anyone holding the
  public key. `verify_integrity(path, receipt_type, *, expected_public_key=...)` and
  `verify-ledger --public-key <file>` are now required arguments.
  **Scope, stated plainly:** this makes *per-entry* tamper-evidence real. Whole-entry
  attacks — deleting, truncating, reordering, replaying, or splicing in a same-signer
  entry — are still undetected, because entries are not chained to one another. The
  ledger is therefore not append-only in the tamper-evident sense; see the README's
  [Honest limits](README.md#honest-limits). A hash chain is the fix and is not in this
  release.
- **BREAKING — score receipts are self-describing, replay is unconditional.**
  `ReceiptPayload` gains a signed `determinism` field recording the settings that
  determine its numbers (`min_samples`, `bootstrap_resamples`, `confidence_level`,
  `ece_bins`, `bootstrap_seed`). `assay.replay(request, receipt)` drops its `settings`
  parameter and recomputes from the settings recorded **in the receipt**, so a legitimate
  receipt always replays — no ambient environment has to match, and a receipt computed
  under different settings is explicitly different rather than a silent replay failure.
  This changes every classification receipt's `payload_hash`.
- **BREAKING — governed effects are attested atomically.** `writ.EffectSubject` gains an
  `outcome` field (`not_run` / `attempted` / `succeeded` / `failed`); `writ.gate` and
  `governed_gate` gain an optional `emit` sink. On allow, the gate seals an `attempted`
  receipt and emits it **before** running the effect, then seals the `succeeded`/`failed`
  outcome after — so a failed or partial privileged effect always leaves a signed
  attestation of the attempt. Wire `emit` to `avow.ledger.append` for durable capture.

### Fixed
- **`assay.replay` compared the recomputed digest against the receipt's own
  `payload_hash` *field*, never against `receipt.payload`.** A payload edited behind an
  untouched hash field therefore replayed as `True` while `verify` correctly returned
  `False`. `replay` now re-derives the digest from `receipt.payload` — the same
  `payload_digest` the envelope's hash check uses — and additionally requires the stored
  `payload_hash` to agree, so a self-inconsistent receipt never replays.
- `assay.verify` now also catches `CanonicalizationFailed`, so a payload that cannot be
  canonicalized fails closed (`False`) instead of raising through the boolean facade.
- Pinned-key comparison in `verify_signature` is case-insensitive: hex identity is not
  spelling-bound, so an uppercase pinned key and a lowercase embedded key are the same
  signer.
- `avow.ledger.append` takes an exclusive advisory lock (`O_APPEND` + `flock`), so
  concurrent appenders cannot interleave a half-written line.
- `@edgeproc/receipt-ui` `StatusPill` ignores a blank (`""`/whitespace) label override
  and keeps the built-in verdict, so a fail-closed status chip never renders empty.

## [0.1.1] - 2026-07-21

First co-release through the OIDC rail: a `v*` tag fans out to PyPI (`avow`) and npm
(`@edgeproc/avow`) token-free. `@edgeproc/receipt-ui` is versioned separately and is
not part of this release.

### Added
- **`assay verify-ledger`** — re-derives every ledger entry's content hash and fails
  closed with the coded `avow.ledger_integrity` if one was edited on disk. The check
  needs no key: identity is the content hash, so anyone holding the file can run it.
  `avow.read_all` / `avow.verify_integrity` are now exported from `avow` alongside
  `avow.append`, so the ledger's read half is reachable from the public surface.
- **Coded errors for an unusable ledger:** `avow.ledger_unreadable` (missing, not a
  regular file, or permission-denied) and `avow.ledger_entry_malformed` (a line that is
  not a parseable receipt, previously surfaced as a raw pydantic traceback).
- **A wrong signer is coded apart from wrong signature bytes.** Both cases previously
  raised `SignatureInvalid` / `avow.signature_invalid`, so a caller could only tell a
  *provenance* failure from a *tamper* failure by string-matching the English message.
  Now `SignerMismatch` (`avow.signer_mismatch`) is raised when the receipt's embedded
  key is not the pinned signer, and `SignatureBytesInvalid` when the curve check
  rejects. Mirrored identically in `@edgeproc/avow` (the codes are a cross-language
  contract). **Compatibility:** both are subclasses of `SignatureInvalid`, so every
  existing `except SignatureInvalid:` / `instanceof SignatureInvalid` keeps working, and
  `SignatureBytesInvalid` deliberately keeps the published `avow.signature_invalid`
  string. The one behaviour change on upgrade: code matching
  `exc.code == "avow.signature_invalid"` to detect a *pinned-key mismatch* now sees
  `avow.signer_mismatch`. Published 0.1.0 consumers are unaffected until they upgrade.

### Fixed
- **Ledger reads no longer fail open.** `read_all` returned `()` for an absent path, so
  `verify-ledger` pointed at a typo'd or never-written file printed
  `OK: ledger verified, 0 entries intact` and exited `0` — a clean bill of health for a
  file it never opened. Reads now fail closed with `avow.ledger_unreadable`. An
  *existing but empty* ledger remains a pass: that is a legitimate initial state.
- **Coverage measured less code than it reported.** The `exclude_lines` entry `\.\.\.`
  was meant to skip bare `...` stub bodies, but it also matched the ellipsis inside
  `tuple[X, ...]` type annotations — silently excluding every function whose signature
  carried one, including the ledger's own `read_all` and `verify_integrity`. Anchored to
  `^\s*\.\.\.$`; Protocol stubs now carry an explicit `# pragma: no cover`. This
  surfaced 22 previously unmeasured statements (499 -> 521 at the time of the fix).
- **Flaky TypeScript signature test.** The corrupted-signature case overwrote only the
  final byte of an Ed25519 signature; because `S < L ≈ 2²⁵²` that byte is already `0x00`
  roughly 1 in 16 times, so the "corruption" was intermittently a no-op and the valid
  signature verified. It now replaces the whole signature, matching the Python side.
  Measured before: 6.77% failure rate; after: 0 failures in 1,000 runs.
- **Workflow pin guard no longer has two blind spots.** It globbed `*.yml` only (a
  `*.yaml` workflow bypassed the check entirely) and passed vacuously when the scan
  matched nothing at all. It now scans both extensions and asserts a non-zero ref count.

### Changed
- **Branch coverage is now measured** (`--cov-branch`), not just statement coverage.
- **Demo tests assert on captured stdout**, not only on `exit_code == 0`. They re-parse
  the demo's own printed hash, calibration numbers and composite interval, so gutting
  what the demo computes fails the tests rather than passing silently.
- `poe gate-all` runs the Python gate and the TypeScript gate together, mirroring CI's
  two jobs. `poe gate` remains Python-only; `poe gate-ts` is the TypeScript half.
- **CLI failures report their coded cause** (`avow.signature_invalid`,
  `avow.replay_mismatch`, `avow.ledger_integrity`) instead of collapsing to a bare
  pass/fail line, so a caller can branch on the cause without matching message text.
- `keygen --out` and `--ledger` now default from `AssaySettings`
  (`ASSAY_SIGNING_KEY_PATH`, `ASSAY_LEDGER_PATH`) rather than from literals inlined in
  the command signatures.

## [0.1.0] - 2026-07-19
### Changed
- **Repackaged as distribution `avow`** exposing three top-level import packages:
  `avow` (the shared trust envelope), `assay` (scoring face, `import avow`), and
  `writ` (effect face, `import avow`). The dependency edges `assay → avow` and
  `writ → avow` are import edges inside one wheel; `avow` imports neither.
- **Extras split:** base install is the envelope only (pydantic, pydantic-settings,
  pynacl, rfc8785); the scoring science stack moved behind `avow[assay]`
  (scikit-learn, scipy, numpy) and the Typer CLI behind `avow[cli]`. `import assay`
  without the extra raises coded `ScoringExtraMissing`.
- **Envelope error catalog** moved to `avow.errors` with `avow.*` codes under
  `AvowError`; scoring codes stay `assay.*` under `AssayError` (both re-exported from
  `assay.errors` for a single import site). `avow.ledger` is now subject-generic.

### Added
- Cross-language golden vectors (`testdata/vectors/`) generated by
  `tests/gen_vectors.py`, replayed by `tests/test_vectors.py`, to pin RFC 8785 byte
  identity across languages — the same vectors the `@edgeproc/avow` TypeScript package
  replays, so a receipt signed in Python verifies in the browser byte-for-byte.

## [0.0.1] - 2026-07-19
### Added
- Deterministic v0 scoring engine: metrics, calibration (ECE/Brier/reliability),
  bootstrap uncertainty with abstention floor, weighted multi-scale composite.
- Signed, offline-verifiable `ScoreReceipt` (RFC 8785 JCS + SHA-256 + Ed25519),
  built on a payload-agnostic trust envelope that a future effect-face can reuse.
- Append-only content-addressed ledger with integrity check.
- Typer CLI (`keygen`, `score`, `composite`, `verify`) and a demo proving all six
  acceptance cases.
