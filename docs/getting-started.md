---
title: Getting started
description: Clone, build, test, install, and consume Longfellow-ZK on native and WASI toolchains.
---

# Getting started

## Prerequisites

Use a C++20 compiler, CMake 3.20 or newer, and Git with submodule support. Ninja
is used by the supplied presets. Project-specific builds may also require zstd,
Node.js for WASM smoke tests, Rust for interoperability checks, or a WASI SDK.

```sh
git clone --recurse-submodules https://github.com/dyne/longfellow-zk.git
cd longfellow-zk
```

If the repository was cloned without submodules:

```sh
git submodule update --init --recursive
```

## Native build and tests

```sh
cmake --preset release
cmake --build --preset release --parallel
ctest --preset release
```

For development, use `debug`. To exercise AddressSanitizer and
UndefinedBehaviorSanitizer with GCC or Clang:

```sh
cmake --preset sanitizers
cmake --build --preset sanitizers --parallel
ctest --preset sanitizers
```

The `GNUmakefile` remains a compatibility front-end (`make`, `make test`,
`make sanitizers`, `make wasm`), but CMake presets own the build contract.

## Install and consume

```sh
cmake --install build/release --prefix "$PWD/build/prefix"
```

```cmake
find_package(LongfellowZK CONFIG REQUIRED)
add_executable(app app.cc)
target_link_libraries(app PRIVATE LongfellowZK::shared) # or ::static
```

Configure the consumer with
`-DCMAKE_PREFIX_PATH=/absolute/path/to/build/prefix`. Do not add source or build
directories as include paths; the installed package is designed to be
relocatable.

## WASI / WebAssembly

Set `WASI_SDK_PATH` if the SDK is not installed at `/opt/wasi-sdk`, then use the
WASI preset:

```sh
WASI_SDK_PATH=/path/to/wasi-sdk cmake --preset wasi
cmake --build --preset wasi --parallel
```

WASI produces the static base library and a reactor-style smoke module. The
configuration does not claim that native CTest executables can run inside WASI.

## Named projects

The release qualification script demonstrates the canonical order: build,
test, install, relocate, and consume the base; then configure ECDSA, BIP340, and
mdoc against that installed prefix.

```sh
bash scripts/ci-installed-package.sh
```

See [Packaging](packaging.md) for target names and release artifacts.
