#!/usr/bin/env bash
# Assemble a release artifact from CMake's installed package, never from a
# source-tree build product.  Publishing remains a CI/release decision.
set -Eeuo pipefail

tag=${1:?usage: pack_release.sh TAG}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build=${LONGFELLOW_ZK_BUILD_DIR:-"$root/build/release"}
stage="$root/longfellow-zk_${tag}"
archive="$root/longfellow-zk_${tag}.tar.gz"

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1"; }
else
  printf '%s\n' 'SHA-256 tool not found (need sha256sum or shasum)' >&2
  exit 69
fi

cmake --install "$build" --prefix "$stage"
cmake -E tar cf "$archive" --format=gnutar -- "$stage"
checksum "$archive" > "$archive.sha256"
test -s "$archive" && test -s "$archive.sha256"
