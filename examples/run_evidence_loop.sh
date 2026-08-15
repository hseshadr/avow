#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v uv >/dev/null 2>&1 && [[ -f "$SCRIPT_DIR/../pyproject.toml" ]]; then
  AVOW=(uv run --project "$SCRIPT_DIR/.." avow)
elif command -v avow >/dev/null 2>&1; then
  AVOW=(avow)
else
  echo "Install the local Avow wheel or run this script from its source checkout." >&2
  exit 1
fi

if [[ -n "${AVOW_DEMO_DIR:-}" ]]; then
  WORK_DIR="$AVOW_DEMO_DIR"
  mkdir -p "$WORK_DIR"
else
  WORK_DIR="$(mktemp -d)"
  trap 'rm -rf "$WORK_DIR"' EXIT
fi

if [[ -n "$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "AVOW_DEMO_DIR must be empty." >&2
  exit 1
fi

cp "$SCRIPT_DIR/evidence.json" "$WORK_DIR/evidence.json"
"${AVOW[@]}" keygen --out "$WORK_DIR/signing.key" >/dev/null
"${AVOW[@]}" sign \
  --payload "$WORK_DIR/evidence.json" \
  --key "$WORK_DIR/signing.key" \
  --out "$WORK_DIR/receipt.json" >/dev/null

receipt_schema="$(python3 - "$WORK_DIR/receipt.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle).get("schema", ""))
PY
)"
if [[ "$receipt_schema" != "avow.receipt/v1" ]]; then
  echo "Receipt schema was not avow.receipt/v1." >&2
  exit 1
fi
printf 'Receipt schema: %s\n' "$receipt_schema"

original="$("${AVOW[@]}" verify \
  --receipt "$WORK_DIR/receipt.json" \
  --public-key "$WORK_DIR/signing.key.pub")"
printf 'Original receipt: %s\n' "$original"

python3 - "$WORK_DIR/receipt.json" "$WORK_DIR/altered-receipt.json" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    receipt = json.load(handle)
receipt["payload"]["decision"]["outcome"] = "rejected"
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(receipt, handle, ensure_ascii=False, separators=(",", ":"))
    handle.write("\n")
PY

set +e
altered="$("${AVOW[@]}" verify \
  --receipt "$WORK_DIR/altered-receipt.json" \
  --public-key "$WORK_DIR/signing.key.pub" 2>&1)"
altered_status=$?
set -e

if [[ $altered_status -ne 2 || "$altered" != "avow.payload_hash_mismatch" ]]; then
  echo "Altered receipt was not rejected as expected." >&2
  exit 1
fi
printf 'Altered receipt: %s (expected)\n' "$altered"
