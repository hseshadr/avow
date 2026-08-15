# Security policy

## TL;DR

Report suspected vulnerabilities privately. Do not include private keys, production
payloads, or other secrets in the report.

## Supported versions

This repository currently contains unpublished Python `0.5.0.dev0` and npm
`0.5.0-dev.0` candidates. Neither candidate is a supported registry release. The
published `avow` `0.4.1` and `@edgeproc/avow` `0.4.1` packages remain untouched.

## Report a vulnerability

Use GitHub's private vulnerability reporting for this repository when it is available.
Until then, email `harish.seshadri@gmail.com` with:

- the affected operation and version;
- a minimal reproduction using non-sensitive data;
- the security impact; and
- any mitigation you have already tested.

Please allow time to reproduce and assess the report before public disclosure. Security
reports are handled separately from ordinary bug reports.

## Security boundaries

Avow verifies content integrity and a caller-pinned Ed25519 signer. It does not make
payloads confidential, establish that evidence is true, or prevent a valid receipt from
being presented more than once. Private signing keys remain the operator's responsibility.

Release workflows use short-lived PyPI and npm OIDC identities. They do not accept stored
registry write tokens. Eligibility, tests, dependency and secret scans, artifact builds,
and clean-install checks run before either minimal publishing job can request an OIDC
identity. Each registry is checked independently: an absent release is published, an
identical release with provenance is safely skipped, and any existing mismatch stops the
workflow.
