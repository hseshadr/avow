# Changelog

All notable standalone Avow changes will be recorded here.

## [Unreleased]

- Extract the opaque JSON receipt and ledger kernel into the standalone `avow` project.
- Add Python `0.5.0.dev0` and npm `0.5.0-dev.0` local release candidates.
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

No standalone candidate has been tagged or published. The existing Python and npm
`0.4.1` registry releases remain untouched.
