#!/usr/bin/env bash
set -Eeuo pipefail

readonly blindzap_bin="${1:-./blindzap}"
readonly claim='0100000000000000000000000000000000000000000000000000000000000000:0:7:0400000000000000000000000000000000000000'
test_dir=''

cleanup() {
  if [[ -n "${test_dir}" && -d "${test_dir}" ]]; then
    rm -rf -- "${test_dir}"
  fi
}
trap cleanup EXIT

fail() {
  printf 'not ok - %s\n' "$1" >&2
  exit 1
}

[[ -x "${blindzap_bin}" ]] || fail "BlindZap binary is not executable"
test_dir="$(mktemp -d)"
readonly request="${test_dir}/request.bzr"
readonly testnet4_request="${test_dir}/testnet4.bzr"

"${blindzap_bin}" --help >"${test_dir}/help.out" 2>"${test_dir}/help.err"
grep -q 'testnet4' "${test_dir}/help.out" || fail "help omits testnet4"
grep -q 'signet' "${test_dir}/help.out" || fail "help omits signet"

"${blindzap_bin}" challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message reserve-test \
  --expires-in 300 \
  --claim "${claim}" \
  --output "${request}" >"${test_dir}/challenge.json"

[[ "$(stat -c '%a' "${request}" 2>/dev/null || stat -f '%Lp' "${request}")" == '600' ]] ||
  fail "request permissions are not 0600"
"${blindzap_bin}" inspect "${request}" >"${test_dir}/inspect.json"
grep -q '"network":"signet"' "${test_dir}/inspect.json" ||
  fail "signet request did not round-trip"
grep -q '"verifier":"auditor.example"' "${test_dir}/inspect.json" ||
  fail "verifier identity did not round-trip"

if "${blindzap_bin}" challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message reserve-test \
  --claim "${claim}" \
  --output "${request}" >/dev/null 2>&1; then
  fail "existing request was overwritten"
fi

"${blindzap_bin}" challenge create \
  --network testnet4 \
  --verifier auditor.example \
  --purpose proof-of-control \
  --message control-test \
  --claim "${claim}" \
  --output "${testnet4_request}" >/dev/null
"${blindzap_bin}" inspect "${testnet4_request}" >"${test_dir}/testnet4.json"
grep -q '"network":"testnet4"' "${test_dir}/testnet4.json" ||
  fail "testnet4 request did not round-trip"

if "${blindzap_bin}" challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message reserve-test \
  --claim '0100000000000000000000000000000000000000000000000000000000000000:0:0:0400000000000000000000000000000000000000' \
  --output "${test_dir}/invalid.bzr" >/dev/null 2>&1; then
  fail "zero-value claim was accepted"
fi

if "${blindzap_bin}" prove --secret=01 --request "${request}" \
  --output "${test_dir}/proof.bze" >/dev/null 2>&1; then
  fail "secret argv was accepted"
fi

printf 'BlindZap CLI tests passed\n'
