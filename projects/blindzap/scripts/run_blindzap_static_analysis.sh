#!/usr/bin/env bash
set -Eeuo pipefail

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required static-analysis tool is unavailable: %s\n' "$1" >&2
    exit 69
  }
}

require_tool clang-tidy
require_tool cppcheck
require_tool shellcheck

readonly checks='clang-analyzer-*,bugprone-*,performance-*,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier'
readonly header_filter='(^|.*/)(projects/blindzap/(include|src|tests)/)'
readonly translation_units=(
  projects/blindzap/tests/blindzap/protocol_test.cc
  projects/blindzap/tests/blindzap/integration_test.cc
  projects/blindzap/tests/blindzap/sage_vector_test.cc
  projects/blindzap/src/blindzap_main.cc
)

for source in "${translation_units[@]}"; do
  clang-tidy \
    -checks="${checks}" \
    -header-filter="${header_filter}" \
    -warnings-as-errors='clang-analyzer-*,bugprone-*' \
    "${source}" -- \
    -std=c++20 -Isrc -Iprojects/blindzap/include -Iprojects/bip340/include
done

cppcheck \
  --enable=warning,performance,portability \
  --language=c++ \
  --std=c++20 \
  --inline-suppr \
  --relative-paths=. \
  --suppress=missingIncludeSystem \
  --suppress=unmatchedSuppression \
  --suppress=normalCheckLevelMaxBranches \
  --suppress=toomanyconfigs \
  '--suppress=*:src/util/*' \
  '--suppress=*:src/circuits/*' \
  '--suppress=*:src/random/*' \
  '--suppress=*:src/algebra/*' \
  '--suppress=*:src/zk/*' \
  '--suppress=*:src/sumcheck/*' \
  '--suppress=*:projects/blindzap/src/json.hpp' \
  --error-exitcode=1 \
  -Isrc -Iprojects/blindzap/include -Iprojects/bip340/include \
  projects/blindzap/include/blindzap/statement.h \
  projects/blindzap/include/blindzap/envelope.h \
  projects/blindzap/include/blindzap/chain_state.h \
  projects/blindzap/include/blindzap/bitcoin_core.h \
  projects/blindzap/include/blindzap/nonce_store.h \
  projects/blindzap/include/blindzap/verifier.h \
  projects/blindzap/src/blindzap_main.cc

shellcheck projects/blindzap/tests/blindzap/cli_test.sh \
  projects/blindzap/scripts/run_blindzap_sage.sh \
  projects/blindzap/scripts/run_blindzap_static_analysis.sh
printf 'BlindZap static analysis passed\n'
