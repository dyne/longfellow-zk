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
readonly header_filter='(^|.*/)(src/blindzap/|src/cli/blindzap_main\.cc|test/blindzap/)'
readonly translation_units=(
  test/blindzap/protocol_test.cc
  test/blindzap/integration_test.cc
  test/blindzap/sage_vector_test.cc
  src/cli/blindzap_main.cc
)

for source in "${translation_units[@]}"; do
  clang-tidy \
    -checks="${checks}" \
    -header-filter="${header_filter}" \
    -warnings-as-errors='clang-analyzer-*,bugprone-*' \
    "${source}" -- \
    -std=c++17 -Isrc -Ivendor/zstd/lib
done

cppcheck \
  --enable=warning,performance,portability \
  --language=c++ \
  --std=c++17 \
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
  '--suppress=*:src/cli/json.hpp' \
  --error-exitcode=1 \
  -Isrc \
  src/blindzap/statement.h \
  src/blindzap/envelope.h \
  src/blindzap/chain_state.h \
  src/blindzap/bitcoin_core.h \
  src/blindzap/nonce_store.h \
  src/blindzap/verifier.h \
  src/cli/blindzap_main.cc

shellcheck test/blindzap/cli_test.sh scripts/run_blindzap_sage.sh \
  scripts/run_blindzap_static_analysis.sh
printf 'BlindZap static analysis passed\n'
