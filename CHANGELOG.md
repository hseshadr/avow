# Changelog

## [0.0.1] - 2026-07-19
### Added
- Deterministic v0 scoring engine: metrics, calibration (ECE/Brier/reliability),
  bootstrap uncertainty with abstention floor, weighted multi-scale composite.
- Signed, offline-verifiable `ScoreReceipt` (RFC 8785 JCS + SHA-256 + Ed25519),
  built on a payload-agnostic trust envelope that a future effect-face can reuse.
- Append-only content-addressed ledger with integrity check.
- Typer CLI (`keygen`, `score`, `composite`, `verify`) and a demo proving all six
  acceptance cases.
