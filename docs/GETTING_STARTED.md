# Getting started for developers

This takes you from nothing to a green local build and your first change. Every command
here was run from a fresh clone; the times are from an Apple Silicon laptop.

## 1. What you need

| Tool | Version | How to get it |
| --- | --- | --- |
| Python | 3.12 or newer (CI uses 3.13) | `uv` installs it for you |
| [`uv`](https://docs.astral.sh/uv/) | any recent | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Bash | any | ships with macOS and Linux |
| Node.js | 22.x (22.13 or newer), only for the TypeScript package | `nvm install 22` |
| pnpm | 11.5.0, only for the TypeScript package | `corepack enable` (it reads `ts/package.json`) |

The Python side needs only Bash, Python 3.12 or newer, and `uv`. You need Node and pnpm
only if you touch `ts/` or run the release checks.

Traps we hit on a real machine:

- **Wrong Node major.** The TypeScript checks and the release scripts expect Node 22. On
  Node 24 or 26 they can fail in confusing ways. Run `node --version` first, and
  `nvm use 22` if needed.
- **A broken Corepack cache.** If pnpm fails with
  `Cannot find module '.../corepack/v1/pnpm/12.5.1/bin/pnpm.cjs'`, Corepack's download
  cache is half-written. Point it at a fresh folder and retry:
  `export COREPACK_HOME="$HOME/.cache/corepack-fresh"`. This made four release tests in
  `tests/test_workflow_contract.py` fail until it was fixed.
- **The TypeScript speed benchmark is timing-sensitive.** `pnpm --dir ts gate` ends with
  `node benchmarks/release.mjs`, which fails with `latency budget missed` if the machine
  is busy. Close heavy jobs and rerun; CI runs it on a quiet runner.

## 2. Clone, install, and run the tests

```bash
git clone https://github.com/hseshadr/avow.git
cd avow
uv sync --frozen --all-groups
uv run pytest -q
```

The clone and `uv sync` took a few seconds (longer the first time `uv` downloads Python
and packages). The test run took about 2 minutes, because some tests build and install
the real wheel and npm tarball. Success ends with a line like:

```text
265 passed in 113.22s (0:01:53)
```

(The exact count grows as tests are added.) For the TypeScript package:

```bash
pnpm --dir ts install --frozen-lockfile --ignore-scripts
pnpm --dir ts exec vitest run
```

Success is `Tests  100 passed (100)`, in a few seconds.

### Run the demo

```bash
bash examples/run_evidence_loop.sh
```

```text
Receipt schema: avow.receipt/v1
Original receipt: avow.verify.ok
Altered receipt: avow.payload_hash_mismatch (expected)
```

Beside this repository's `pyproject.toml`, the demo deliberately selects the checkout's
`uv run ... avow` path before any installed `avow` on `PATH`, so it exercises this
source checkout. When only `examples/` is copied away, it uses the installed command
instead. To test the packaged wheel instead of the source, follow
[Prove the wheel](../QUICKSTART.md#prove-the-wheel-outside-the-repository).

## 3. The full check (what CI runs)

```bash
uv run poe gate && pnpm --dir ts gate
```

`uv run poe gate` runs ruff (lint and format), `mypy --strict`, a Grade A complexity
check (`xenon`), and the Python tests with at least 90% branch coverage. It took about
2.5 minutes here. `pnpm --dir ts gate` runs Biome, strict TypeScript, Vitest with coverage, the
build, and the speed benchmark, in about 20 seconds.

The Python check runs `ruff --fix` and `ruff format`, so it may rewrite files. CI fails
if that leaves a diff, so commit what it changes.

CI also runs jobs you rarely need locally: Python/TypeScript vector parity, tamper and
mutation checks, the example against an installed wheel, and artifact builds. They are
in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## 4. Map of the code

| Path | What it is |
| --- | --- |
| `src/avow/canonical.py` | Turns JSON into one fixed byte form (RFC 8785) and hashes it |
| `src/avow/envelope.py` | The receipt format, signing, and signature checks |
| `src/avow/verify.py` | `verify_receipt`: the offline check against a pinned public key |
| `src/avow/keys.py` | Key generation, saving, and loading (refuses loosely permissioned keys) |
| `src/avow/ledger.py` | The append-only ledger that chains receipts |
| `src/avow/cli.py` | The `avow` command and its stable output codes |
| `src/avow/errors.py` | Every error type and its stable `avow.*` code |
| `ts/src/` | The TypeScript package `@edgeproc/avow` (canonical JSON and receipts) |
| `testdata/vectors/` | Shared test vectors both languages must match byte for byte |
| `tests/` | Python tests; `test_readme_contract.py` re-runs the README examples |
| `scripts/` | Release build and verification scripts |

For how the pieces fit, read [ARCHITECTURE.md](ARCHITECTURE.md).

## 5. Make your first change

A typical small change: make canonical JSON reject a new kind of value, with a test.

1. Write the failing test first, in `tests/test_canonical.py`. Tests here use a
   Given / When / Then comment style, for example:

   ```python
   def test_should_change_hash_when_a_single_value_changes() -> None:
       # Given two payloads that differ in one value
       # When hashed
       # Then the hashes differ
   ```

2. Run just that file and watch it fail:

   ```bash
   uv run pytest tests/test_canonical.py -q
   ```

3. Make the change in `src/avow/canonical.py` (the `_validate_*` functions decide what
   is accepted). Run the file again until it passes.
4. If the rule must hold in TypeScript too, add the value to `tests/gen_vectors.py`,
   regenerate the shared vectors with `uv run python tests/gen_vectors.py`, and make
   `ts/src/canonical.ts` agree. `pnpm --dir ts exec vitest run` checks it.
5. If you changed what users see (a new error code, a new command), update
   [QUICKSTART.md](../QUICKSTART.md), [OPERATIONS.md](OPERATIONS.md), and add a line
   under `## [Unreleased]` in [CHANGELOG.md](../CHANGELOG.md).
6. Run the full check from section 3.

## 6. Open a pull request

- Branch from `main` with a short prefix: `fix/...`, `docs/...`, `feat/...`, or
  `release/...`.
- Keep one change per pull request, with its tests in the same commit.
- CI runs the Python check on 3.13, the TypeScript check on Node 22, vector parity,
  tamper and mutation checks, the installed-wheel example, and artifact builds. All must
  pass.
- Reviewers look for: a test that fails without your change, no change to the receipt
  format unless it is versioned, stable error codes (callers depend on them), and docs
  that match what the code does.
- Report security problems privately, as described in [SECURITY.md](../SECURITY.md).

## Maintainer release check

Only maintainers cutting a release need this. It additionally needs Node 22, Corepack,
pnpm 11.5.0, actionlint, gitleaks, and ShellCheck. Corepack selects the pinned pnpm
version from `ts/package.json`.

```bash
node --version
pnpm --version
uv run poe release-candidate
```

The check rejects any active Node major other than 22 before installing dependencies.
Pushing the exact tag `v0.5.0` is what publishes; nothing in this guide publishes, tags,
or changes a registry release.
