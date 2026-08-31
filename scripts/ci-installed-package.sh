#!/usr/bin/env bash
# Build the base once, then ensure every named project consumes only a staged,
# relocatable package prefix in both supported native linkage modes.  This is
# shared by CI and the transitional `make` target.
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/longfellow-zk-package.XXXXXX")
trap 'rm -rf "$work"' EXIT
base_prefix="$work/base-prefix"
build_type=${LONGFELLOW_ZK_BUILD_TYPE:-Release}
linkages=${LONGFELLOW_ZK_LINKAGES:-"static shared"}
package_output=${LONGFELLOW_ZK_PACKAGE_OUTPUT_DIR:-}
release_version=${LONGFELLOW_ZK_VERSION:-1.0.0}

case " $linkages " in
  *" static "*|*" shared "*) ;;
  *)
    printf '%s\n' 'LONGFELLOW_ZK_LINKAGES must contain static and/or shared' >&2
    exit 64
    ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1"; }
else
  printf '%s\n' 'SHA-256 tool not found (need sha256sum or shasum)' >&2
  exit 69
fi

configure_args=(
  "-DCMAKE_BUILD_TYPE=$build_type"
  "-DCMAKE_C_COMPILER_LAUNCHER=ccache"
  "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache"
  "-DLONGFELLOW_ZK_VERSION=$release_version"
)
base_configure_args=("${configure_args[@]}")
ctest_args=(--output-on-failure)
if [[ ${LONGFELLOW_ZK_SANITIZERS:-OFF} == ON ]]; then
  sanitizer_flags='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1'
  configure_args+=(
    "-DCMAKE_CXX_FLAGS=$sanitizer_flags"
    "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"
    "-DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address,undefined"
  )
  base_configure_args=(
    "${configure_args[@]}"
    "-DLONGFELLOW_ZK_ENABLE_SANITIZERS=ON"
  )
  ctest_args+=(--timeout 5400)
fi

cmake -S "$root" -B "$work/base" -G Ninja \
  "${base_configure_args[@]}" \
  -DLONGFELLOW_ZK_BUILD_TESTING=ON \
  -DCMAKE_INSTALL_PREFIX="$base_prefix"
cmake --build "$work/base" --parallel
ctest --test-dir "$work/base" "${ctest_args[@]}"
cmake --install "$work/base"

for linkage in $linkages; do
  case "$linkage" in
    static|shared) ;;
    *)
      printf 'unsupported linkage: %s\n' "$linkage" >&2
      exit 64
      ;;
  esac

  prefix="$work/$linkage/prefix"
  cmake -E copy_directory "$base_prefix" "$prefix"

  for project in ecdsa bip340 mdoc; do
    project_build="$work/$linkage/$project"
    cmake -S "$root/projects/$project" -B "$project_build" -G Ninja \
      "${configure_args[@]}" \
      -DCMAKE_PREFIX_PATH="$prefix" \
      -DCMAKE_INSTALL_PREFIX="$prefix" \
      -DLONGFELLOW_ZK_TARGET="LongfellowZK::$linkage"
    cmake --build "$project_build" --parallel
    ctest --test-dir "$project_build" "${ctest_args[@]}"
    cmake --install "$project_build"

    if [[ -n "$package_output" && "$project" == bip340 ]]; then
      metrics_dir="$package_output/metrics"
      mkdir -p "$metrics_dir"
      metrics_file="$project_build/results/native_bip340_metrics.csv"
      [[ -s "$metrics_file" ]] || {
        printf 'BIP340 test did not produce metrics: %s\n' "$metrics_file" >&2
        exit 1
      }
      cmake -E copy "$metrics_file" \
        "$metrics_dir/${linkage}_native_bip340_metrics.csv"
    fi
  done

  # Relocation must preserve the selected base and named-project package graph.
  relocated="$work/$linkage/relocated"
  cmake -E copy_directory "$prefix" "$relocated"
  cmake -S "$root/test/cmake/consumer-$linkage" -B "$work/consumer-$linkage" -G Ninja \
    -DCMAKE_PREFIX_PATH="$relocated"
  cmake --build "$work/consumer-$linkage" --parallel
  "$work/consumer-$linkage/consumer"

  archive="$work/longfellow-zk-$linkage.tar.gz"
  cmake -E tar czf "$archive" --format=gnutar "$prefix"
  cmake -E tar tzf "$archive" >/dev/null
  checksum "$archive" > "$archive.sha256"
  test -s "$archive.sha256"
done
