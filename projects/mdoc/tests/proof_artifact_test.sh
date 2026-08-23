#!/usr/bin/env bash
set -euo pipefail

cli=$1
mdoc=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$cli" circuit_gen --zkspec 0 -c "$work/circuit.json" >/dev/null
for run in one two; do
  "$cli" mdoc_prove -c "$work/circuit.json" \
    -m "$mdoc" -p "$work/$run.json" >/dev/null
  "$cli" mdoc_verify -c "$work/circuit.json" \
    -p "$work/$run.json" >/dev/null
  jq -r '.proof_data_base64' "$work/$run.json" | base64 -d >"$work/$run.proof"
done

# The mdoc path deliberately draws SecureRandomEngine pads before committing.
# Thus exact equality (including byte length) would be wrong; each emitted
# proof must instead verify, differ from the other, and reject tampering.
test "$(wc -c <"$work/one.proof")" -gt 0
test "$(wc -c <"$work/two.proof")" -gt 0
if cmp -s "$work/one.proof" "$work/two.proof"; then
  echo "proof randomness unexpectedly produced identical bytes" >&2
  exit 1
fi
jq '.proof_data_base64 = (.proof_data_base64[0:10] + "AAAA" + .proof_data_base64[14:])' \
  "$work/one.json" >"$work/tampered.json"
if "$cli" mdoc_verify -c "$work/circuit.json" \
    -p "$work/tampered.json" >/dev/null 2>&1; then
  echo "tampered proof bytes accepted" >&2
  exit 1
fi
echo "ECDSA mdoc proof artifacts: randomized valid bytes and tamper rejection passed"
