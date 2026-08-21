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

# The baseline deliberately has no path-wide suppressions.  The two excluded
# clang-tidy style checks are documented false-positive-prone API/style rules;
# the one cppcheck exception describes a tool limitation, not a source path.
readonly sources=(src/proto/circuit_reader.h src/random/transcript.h src/util/readbuffer.h)
for source in "${sources[@]}"; do
  clang-tidy -checks='clang-analyzer-*,bugprone-*,performance-*,-bugprone-easily-swappable-parameters,-performance-enum-size' \
    -warnings-as-errors='clang-analyzer-*,bugprone-*' "$source" -- \
    -x c++ -std=c++17 -Isrc -Ivendor/zstd/lib
done
cppcheck --enable=warning,performance,portability --language=c++ --std=c++17 \
  --error-exitcode=1 --suppress=missingIncludeSystem -Isrc "${sources[@]}"
shellcheck scripts/run_baseline_static_analysis.sh
printf 'baseline static analysis passed (no first-party blanket suppressions)\n'
