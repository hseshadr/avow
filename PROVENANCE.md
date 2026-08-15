# Extraction provenance

## TL;DR

This repository was extracted locally from the Avow-owned paths in Assay commit
`3121df1af33a41b457faa2fd1ce84dc823950c39`. The filtered counterpart of that
source commit is `dda4301eab01300fea7e2f008ef7460ff009fef7`.

No remote repository was created, and nothing was pushed, tagged, published, or
merged as part of this extraction.

## Source

- Source repository: `/Users/harish/dev/oss/assay`
- Source commit: `3121df1af33a41b457faa2fd1ce84dc823950c39`
- Extraction workspace: `/Users/harish/dev/oss/avow`
- Initial filtered tip: `dda4301eab01300fea7e2f008ef7460ff009fef7`
- Commit mapping: `.git/filter-repo/commit-map`

The workspace was created with:

```bash
git clone --no-local /Users/harish/dev/oss/assay /Users/harish/dev/oss/avow
git -C /Users/harish/dev/oss/avow checkout --detach 3121df1af33a41b457faa2fd1ce84dc823950c39
```

All cloned branches, remote-tracking refs, and tags were removed after creating
the temporary `extraction-source` branch at the audited commit. This bounded the
rewrite to that commit and its ancestors. The exact bounding commands were:

```bash
git switch -c extraction-source
for ref in $(git for-each-ref --format='%(refname)' refs/heads refs/remotes refs/tags | rg -v '^refs/heads/extraction-source$'); do
  git update-ref -d "$ref"
done
```

The exact filtering command was:

```bash
uvx git-filter-repo --force \
  --path src/avow/ \
  --path tests/gen_vectors.py \
  --path tests/test_canonical.py \
  --path tests/test_envelope_split.py \
  --path tests/test_errors.py \
  --path tests/test_keys.py \
  --path tests/test_ledger.py \
  --path tests/test_receipt.py \
  --path tests/test_vectors.py \
  --path tests/test_verify.py \
  --path testdata/vectors/ \
  --path ts/.gitignore \
  --path ts/biome.json \
  --path ts/package.json \
  --path ts/pnpm-lock.yaml \
  --path ts/src/canonical.test.ts \
  --path ts/src/canonical.ts \
  --path ts/src/errors.ts \
  --path ts/src/keys.ts \
  --path ts/src/receipt.test.ts \
  --path ts/src/receipt.ts \
  --path ts/tsconfig.build.json \
  --path ts/tsconfig.json \
  --path ts/vitest.config.ts \
  --path ts/benchmarks/release.mjs \
  --path CHANGELOG.md \
  --path LICENSE \
  --path scripts/verify_release_identity.py
```

Only after filtering completed was the canonical branch established with
`git switch -C main` in `/Users/harish/dev/oss/avow`.
