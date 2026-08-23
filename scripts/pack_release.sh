#!/usr/bin/env bash
# Assemble a release artifact from CMake's installed package, never from a
# source-tree build product.  Publishing remains a CI/release decision.
set -Eeuo pipefail

tag=${1:?usage: pack_release.sh TAG}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build=${LONGFELLOW_ZK_BUILD_DIR:-"$root/build/release"}
package_output=${LONGFELLOW_ZK_PACKAGE_OUTPUT_DIR:-"$root/build/qualified-packages"}

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1"; }
else
  printf '%s\n' 'SHA-256 tool not found (need sha256sum or shasum)' >&2
  exit 69
fi

pack_directory() {
  local source=$1
  local name=$2
  local stage="$root/$name"
  local archive="$root/$name.tar.gz"

  if [[ "$source" != "$stage" ]]; then
    cmake -E remove_directory "$stage"
    cmake -E copy_directory "$source" "$stage"
  fi
  cmake -E tar czf "$archive" --format=gnutar -- "$stage"
  cmake -E tar tzf "$archive" >/dev/null
  checksum "$archive" > "$archive.sha256"
  test -s "$archive" && test -s "$archive.sha256"
}

base_stage="$root/longfellow-zk_${tag}"
cmake -E remove_directory "$base_stage"
cmake --install "$build" --prefix "$base_stage"
pack_directory "$base_stage" "longfellow-zk_${tag}"

if [[ -d "$package_output/static/blindzap" ]]; then
  pack_directory "$package_output/static/blindzap" \
    "longfellow-zk-blindzap_${tag}"
fi
