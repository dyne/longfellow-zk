#!/usr/bin/env bash
# Opt-in parity entry point.  It is intentionally the only Make orchestration.
set -Eeuo pipefail

die() { printf 'google-rust-parity: %s\n' "$*" >&2; exit 1; }
root=$(git -C "${BASH_SOURCE[0]%/*}/.." rev-parse --show-toplevel 2>/dev/null) || die "Git is required to discover the repository root"
cd "$root"
command -v git >/dev/null 2>&1 || die "Git is required"
path=vendor/longfellow-zk
expected_url=https://github.com/google/longfellow-zk
configured_path=$(git config -f .gitmodules --get submodule.vendor/longfellow-zk.path || true)
configured_url=$(git config -f .gitmodules --get submodule.vendor/longfellow-zk.url || true)
[[ "$configured_path" == "$path" && "$configured_url" == "$expected_url" ]] || die "expected $path to be configured as $expected_url"
expected=$(git ls-tree HEAD -- "$path" | awk '$1 == "160000" { print $3 }')
[[ -n "$expected" ]] || die "missing gitlink for $path"
if [[ ! -e "$path/.git" && ! -d "$path/.git" ]]; then
  git submodule update --init -- "$path" || die "could not initialize $path (check clone/fetch access)"
else
  git -C "$path" diff --quiet && git -C "$path" diff --cached --quiet || die "$path is dirty; refusing to modify it"
  actual_url=$(git -C "$path" remote get-url origin 2>/dev/null || true)
  [[ "$actual_url" == "$expected_url" ]] || die "$path origin is '$actual_url', expected '$expected_url'; refusing to modify it"
fi
actual=$(git -C "$path" rev-parse HEAD 2>/dev/null) || die "$path is not a usable Git checkout"
[[ "$actual" == "$expected" ]] || die "$path is at $actual, expected $expected; refusing to modify it"
printf 'google-rust-parity: google commit %s\n' "$expected"
command -v cargo >/dev/null 2>&1 || die "Cargo is required for the opt-in Rust oracle"
command -v cmake >/dev/null 2>&1 || die "CMake is required for the opt-in C++ oracle"
command -v python3 >/dev/null 2>&1 || die "Python 3 is required for the record runner"
build_dir=${GOOGLE_RUST_PARITY_BUILD_DIR:-$root/build/google-rust-parity}
cargo_target=${GOOGLE_RUST_PARITY_CARGO_TARGET_DIR:-$build_dir/cargo}
cmake_args=(-S "$root" -B "$build_dir/cpp" -DLONGFELLOW_ZK_BUILD_GOOGLE_RUST_PARITY=ON -DCMAKE_BUILD_TYPE=Release)
if command -v ccache >/dev/null 2>&1; then
  cmake_args+=(-DCMAKE_CXX_COMPILER_LAUNCHER=ccache)
  printf 'google-rust-parity: C++ launcher=ccache\n'
else
  printf 'google-rust-parity: C++ launcher=none (ccache unavailable)\n'
fi
cmake "${cmake_args[@]}"
cmake --build "$build_dir/cpp" --target longfellow-zk-google-cpp-oracle --parallel
CARGO_TARGET_DIR="$cargo_target" cargo build --release --manifest-path "$root/test/google_rust_parity/rust/Cargo.toml"
python3 "$root/test/google_rust_parity/runner.py" --cpp "$build_dir/cpp/longfellow-zk-google-cpp-oracle" --rust "$cargo_target/release/google-rust-parity-oracle" --commit "$expected"
