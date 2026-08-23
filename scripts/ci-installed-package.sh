#!/usr/bin/env bash
# Build the base once, then ensure every named project consumes only its staged
# package prefix.  This is shared by CI and the transitional `make` target.
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/longfellow-zk-package.XXXXXX")
trap 'rm -rf "$work"' EXIT
prefix="$work/prefix"

cmake -S "$root" -B "$work/base" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLONGFELLOW_ZK_BUILD_TESTING=ON \
  -DCMAKE_INSTALL_PREFIX="$prefix"
cmake --build "$work/base" --parallel
ctest --test-dir "$work/base" --output-on-failure
cmake --install "$work/base"

for project in ecdsa bip340; do
  cmake -S "$root/projects/$project" -B "$work/$project" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$prefix" \
    -DCMAKE_INSTALL_PREFIX="$prefix"
  cmake --build "$work/$project" --parallel
  ctest --test-dir "$work/$project" --output-on-failure
  cmake --install "$work/$project"
done

for project in mdoc blindzap; do
  cmake -S "$root/projects/$project" -B "$work/$project" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$prefix" \
    -DCMAKE_INSTALL_PREFIX="$prefix"
  cmake --build "$work/$project" --parallel
  ctest --test-dir "$work/$project" --output-on-failure
  cmake --install "$work/$project"
done

# A relocated base package must still configure independent static and shared
# consumers without a repository source include path.
relocated="$work/relocated"
cmake -E copy_directory "$prefix" "$relocated"
for linkage in static shared; do
  cmake -S "$root/test/cmake/consumer-$linkage" -B "$work/consumer-$linkage" -G Ninja \
    -DCMAKE_PREFIX_PATH="$relocated"
  cmake --build "$work/consumer-$linkage" --parallel
  "$work/consumer-$linkage/consumer"
done

cmake -E tar cf "$work/longfellow-zk.tar.gz" --format=gnutar "$prefix"
sha256sum "$work/longfellow-zk.tar.gz" > "$work/longfellow-zk.tar.gz.sha256"
test -s "$work/longfellow-zk.tar.gz.sha256"
