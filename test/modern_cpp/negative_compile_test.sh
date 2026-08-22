#!/usr/bin/env bash
set -euo pipefail

compiler=${1:?compiler required}
root_dir=$(cd "$(dirname "$0")/../.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

printf '%s\n' \
  '#include "util/byte_cursor.h"' \
  'int main() { proofs::ByteCursor cursor(nullptr, 1); }' \
  > "$work_dir/null_byte_cursor.cc"

if "$compiler" -std=c++20 -I"$root_dir/src" -c "$work_dir/null_byte_cursor.cc" \
    -o "$work_dir/null_byte_cursor.o" 2>"$work_dir/error.log"; then
  echo "ByteCursor(nullptr, size) unexpectedly compiled" >&2
  exit 1
fi

grep -Eq 'deleted|ByteCursor' "$work_dir/error.log"
