# Changelog

All notable standalone Avow changes will be recorded here.

## [Unreleased]

## [0.5.0]

The first release built from this repository, and the first clean `avow` wheel.

- **Packaging:** the release verifier now refuses any wheel or sdist that installs a
  top-level name other than `avow`, and clean-installs the wheel beside
  `assay-engine` in both orders. Every `avow` release up to `0.4.1` (published from
  the pre-split `hseshadr/assay` repo) shipped top-level `assay/` and `writ/`
  packages that overwrote `assay-engine` and broke `from assay import ScoreResult`.
  This repo has never built those packages; the guard keeps it that way.
- **Upgrade note:** if an older `avow` overwrote or, on uninstall, removed
  `assay-engine`'s files, uninstall and reinstall `assay-engine` after upgrading:
  `pip uninstall assay-engine && pip install assay-engine`.
- **Planned:** once `0.5.0` is verified on PyPI, yank `0.1.0` through `0.4.1` there so
  resolvers stop picking a release that clobbers `assay-engine`.
- Rewrite the README to the portfolio template: a plain-language first screen, a
  runnable 60-second example whose real output is the hero, and a
  `tests/test_readme_contract.py` gate that re-runs that example with network access
  disabled. The Python and npm package descriptions now equal the README tagline.
- Extract the opaque JSON receipt and ledger kernel into the standalone `avow` project.
- Release Python `avow` and npm `@edgeproc/avow` together at `0.5.0`.
- Add exact-commit Python, Node 22, parity, mutation, example, artifact, and security gates.
- Add token-free trusted-publishing workflows that remain inactive until an exact version
  tag is pushed.
- **Security:** `load_signing_key` (and so `avow sign`) now fails closed with the new
  `KeyPermissionsInsecure` error, code `avow.key_permissions_insecure`, when a POSIX key
  file grants any group or other permission bit. Keys written by `keygen` or
  `save_signing_key` are already `0600` and load unchanged; the check is skipped on
  non-POSIX platforms. No receipt, ledger, or other wire format changes.
- Document the boundary plainly: Avow is not a replay defence, and the signing key is an
  unencrypted seed protected only by filesystem permissions with no KMS/HSM seam. Add
  caller-owned replay-protection and key-rotation recipes to `docs/OPERATIONS.md`.
