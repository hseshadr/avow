# Changelog

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
