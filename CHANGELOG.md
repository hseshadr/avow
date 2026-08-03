# Changelog

## [Unreleased]

### Added
- **A ranking face: `assay.ranking`, plus `assay.ranking_score` for a signed receipt.**
  Everything in `metrics.py` scores `(y_true, y_score)` pairs, a shape with no notion of
  *position* — a search engine that returns the right product tenth and one that returns
  it first produce identical numbers. The new module scores a
  `(relevance judgments, ranked list)` pair instead: `precision_at_k`, `recall_at_k`,
  `f1_at_k`, `ndcg_at_k` (graded relevance, not just binary), `mrr`,
  `average_precision` / `mean_average_precision`, and `ranking_report` for a whole query
  set. The arithmetic is scikit-learn's (`ndcg_score`,
  `label_ranking_average_precision_score`); Assay adds the `@k` forms sklearn does not
  ship, the input adaptation from a ranked id list to sklearn's label matrix, and a
  refusal on every input whose answer would be undefined.
- **`ranking_report` carries an interval, or abstains.** Mean nDCG@k comes with a
  bootstrap confidence interval over the per-query values, or an `Abstention` below
  `AssaySettings.min_samples` — the same honesty floor the classification face uses, not
  a second uncertainty story. Per-query rows are always returned alongside the means,
  because the mean is the number that hides a broken query and the rows are the number
  that names it.
- **Two coded refusals: `assay.invalid_ranking_request` and `assay.empty_relevant_set`.**
  An empty relevant set is refused rather than scored 0.0, because 0.0 reads as "the
  ranker found nothing" and would blame the ranker for missing *judgments*. `k <= 0`, an
  empty ranked list, the same document twice in one ranked list or judged twice in one
  query, and a negative gain are all refused for the same reason: the answer would be
  undefined, not merely small.
- **`AssaySettings.ranking_k` (default 10)** — the cut-off is configuration, not a
  literal in the logic, and whichever `k` applied is recorded in the receipt so a
  reported precision@k always says which k it was.

### Changed
- **BREAKING — `ReplayMismatch` is renamed `PayloadHashMismatch`, and its code
  `avow.replay_mismatch` becomes `avow.payload_hash_mismatch`.** The error fired on a
  payload edited behind a stale hash field — a **tamper** failure. It never detected
  replay, and neither does anything else in the envelope. Naming the one error in a
  cryptographic verifier's catalog "Replay" implied a property the package does not have,
  which is the same class of defect as an untrue sentence in a README: a reader who sees
  `avow.replay_mismatch` reasonably concludes replay is handled. It is not.
  `ReplayMismatch` stays as a deprecated alias so `except ReplayMismatch:` /
  `instanceof ReplayMismatch` keeps working; **a caller that branches on the literal
  string `"avow.replay_mismatch"` must be updated.** Removed in 0.4.0. Mirrored in
  `@edgeproc/avow` on npm, since the `code` strings are a cross-language contract.
- **New `assay.replay_refused` (`ReplayRefused`), raised where the scoring face used to
  raise the envelope's error.** `assay.replay` means "recompute this receipt from its
  inputs and check it reproduces" — a scoring concept, not a cryptographic one. A receipt
  recording no determinism settings now fails with an `assay.*` code instead of borrowing
  an `avow.*` one that described a hash mismatch it never measured.

### Documented
- **Freshness is now stated as an explicit limit, in every place a caller reads.**
  `verify_signature` / `verify_receipt` prove *who signed it* and *that it is unmodified*.
  They do **not** prove that a receipt is fresh or has not been presented before. A
  genuine receipt, captured and handed over again unchanged, is byte-identical to the
  original and verifies forever — which is the same determinism that makes offline
  verification years later work at all. This is correct-by-design for a bare signature;
  what was wrong was leaving it unsaid while shipping an error called `ReplayMismatch`.
  Now in the README's `Honest limits`, the tampered-record demo, the error-code table,
  both verifier docstrings, and — most importantly — `ts/README.md`, because the npm
  package ships the envelope **with no ledger at all**, so a browser caller has no
  fallback and must hold replay state itself.
- Two tests pin both halves of the boundary so neither can drift silently:
  `test_a_replayed_receipt_verifies_because_a_signature_carries_no_freshness` (the
  envelope accepts a replay, by design) and
  `test_the_ledger_chain_is_what_refuses_a_replayed_receipt` (the ledger refuses one).
  The second was watched go red with both the chain walk and the head comparison
  disabled; either one alone catches it, which is defence in depth.

## [0.2.0] - 2026-08-01

A breaking release that makes three trust claims literally true. Pair-versioned with
`@edgeproc/avow` on npm; `@edgeproc/receipt-ui` is versioned separately.

### Changed
- **BREAKING — the ledger is a hash chain with the head pinned out-of-band, so it is now
  append-only in the tamper-evident sense.** Each line is a `LedgerEntry` carrying `seq`,
  `prev_hash` and the receipt, so the last entry's hash commits to the entire history.
  `append` returns the ledger's new `LedgerHead` (count + hash);
  `verify_integrity(..., expected_head=...)` and `verify-ledger --head <file>` now require
  it, and `score` writes it to `<ledger>.head`. Verification walks the chain from genesis
  and rejects any ledger that does not end exactly at the pinned head.
  **This closes the gap the previous entry disclosed.** Deleting an entry, truncating the
  file (including emptying it), reordering, replaying, and splicing in a same-signer entry
  from another ledger each returned `OK: ledger verified, N entries intact` and exit `0`
  before; all now fail with `avow.ledger_integrity` and exit `1`. Each attack is a test in
  `tests/test_ledger.py` (the strict-`xfail` markers are gone), and each of the four guards
  has been watched go red with its own check disabled.
  **Tests inverted, loudly:** `test_an_existing_empty_ledger_verifies_as_zero_entries_which_is_a_known_gap`
  asserted the defect as the requirement — that an empty ledger *always* verifies. It is
  now `test_a_fresh_empty_ledger_verifies_only_against_the_empty_head`: an empty file
  passes against the empty head and **fails** against any other, which is what stops an
  erased audit from reading as a fresh one.
  **Honest limit, restated:** this moves the trust requirement from N lines to 32 bytes; it
  does not remove it. A head file beside the ledger is a copy for carrying away, never a
  control against an attacker who can write both. Reading an old-format (unchained) ledger
  now fails with `avow.ledger_entry_malformed`; there is no migration path in 0.x.
  New coded error: `avow.ledger_head_unreadable` (missing or unparseable pin — fails closed
  rather than falling back to the head the file computes for itself).
  New public API: `LedgerHead`, `LedgerEntry`, `EMPTY_HEAD`, `entry_hash`, `read_entries`,
  `current_head`, `save_head`, `read_head`.
- **BREAKING — ledger tamper-evidence is now real.** `avow.verify_integrity` and
  `assay verify-ledger` now require the signer's pinned **public** key and verify each
  entry's **Ed25519 signature**, not just re-derive its content hash. A hash-only check
  was an overclaim: an adversary with no signing key can still recompute an entry's
  public content hash and launder a forged payload past it. The signature — which only
  the private seed can produce — is what makes tampering detectable by anyone holding the
  public key. `verify_integrity(path, receipt_type, *, expected_public_key=...)` and
  `verify-ledger --public-key <file>` are now required arguments.
  **Scope, stated plainly:** this makes *per-entry* tamper-evidence real, and nothing
  more. Whole-entry attacks — deleting, truncating, reordering, replaying, splicing in a
  same-signer entry — remained undetected after this change, because entries were still
  not chained to one another. The chain bullet above is what closed that, in the same
  unreleased 0.2.0; this bullet is kept for the record of what each change actually
  bought.
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
