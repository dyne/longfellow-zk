---
title: Getting started
description: Clone, build, test, install, and consume Longfellow-ZK on native and WASI toolchains.
---

# Getting started

This is the shortest supported path from a checkout to an application that
links an installed Longfellow-ZK package.

## 1. Build and test the base library

Install a C++20 compiler, CMake 3.20 or newer, Ninja, and Git, then run:

```sh
git clone --recurse-submodules https://github.com/dyne/longfellow-zk.git
cd longfellow-zk
cmake --preset release
cmake --build --preset release --parallel
ctest --preset release
```

Use the `debug` preset for development or `sanitizers` with GCC or Clang for
AddressSanitizer and UndefinedBehaviorSanitizer coverage. The `GNUmakefile` is a
compatibility front-end; CMake presets define the supported build contract.

## 2. Install to a staging prefix

```sh
cmake --install build/release --prefix "$PWD/build/prefix"
```

The prefix now contains the static and versioned shared libraries, public
headers under `include/longfellow-zk/`, and relocatable CMake package files.

## 3. Consume the installed package

In your application's `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.20)
project(example LANGUAGES CXX)

find_package(LongfellowZK CONFIG REQUIRED)
add_executable(example main.cc)
target_link_libraries(example PRIVATE LongfellowZK::shared) # or ::static
```

A minimal compile check can include a generic circuit from the base package:

```cpp
#include <circuits/merkle/fixed_depth_sha256_merkle_membership.h>

int main() {
  constexpr proofs::FixedDepthSha256MerklePath<0> path{};
  return path.direction_bits.size();
}
```

Configure and run it against the staged installation:

```sh
cmake -S /path/to/example -B /path/to/example/build \
  -DCMAKE_PREFIX_PATH="$PWD/build/prefix"
cmake --build /path/to/example/build
/path/to/example/build/example
```

Use an absolute prefix. Do not add this repository's `src/`, `projects/`, or
build directories to consumer include or link paths. For a shared build, use
your platform's normal loader configuration or application rpath.

## Add an application circuit

ECDSA, BIP340, and mdoc are separate packages layered on the installed base.
Choose the relevant [named project](projects/index.md); do not copy its headers
into the base include tree. The [packaging guide](packaging.md) gives the
canonical configure order and target names.

## WASI / WebAssembly

Set `WASI_SDK_PATH` if the SDK is not at `/opt/wasi-sdk`:

```sh
WASI_SDK_PATH=/path/to/wasi-sdk cmake --preset wasi
cmake --build --preset wasi --parallel
```

This builds the static base library and a reactor-style smoke module. Native
CTest executables are not run under WASI. Node.js is needed only to execute the
WASM smoke test; Rust is not a base build requirement.

## Before production

Pin the library, named-project, circuit, format, and vector versions together.
Review the [API and ABI contract](api.md) and
[security qualification guidance](security.md). For integration assistance,
contact [info@dyne.org](mailto:info@dyne.org).
