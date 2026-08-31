# Longfellow-ZK

Longfellow-ZK is a community-maintained C++20 library for building and
verifying zero-knowledge proofs. This Dyne.org distribution turns Google's
[Longfellow-ZK](https://github.com/google/longfellow-zk) work into a reusable,
installable base library, with separate ECDSA, BIP340, and mdoc packages.

Use it when you need the proof system in a native, mobile, or WebAssembly
project without depending on a proprietary operating-system API. The project
is pre-1.0 cryptographic software; read the
[security boundaries](docs/security.md) before production use.

## Choose your path

- **Building on the library?** Start with [Getting started](docs/getting-started.md),
  then use the supported [API and ABI](docs/api.md) surface. The installed CMake
  package is the integration boundary.
- **Maintaining a distribution package?** Start with
  [Packaging](docs/packaging.md) for dependencies, install layout, package
  splits, ABI policy, and release checks.
- **Evaluating the protocol?** Read the [architecture](docs/architecture.md),
  [specification map](docs/specifications/index.md), and
  [security guidance](docs/security.md).

## Build, test, and install

Requirements: a C++20 compiler, CMake 3.20 or newer, Ninja, and Git.

```sh
git clone --recurse-submodules https://github.com/dyne/longfellow-zk.git
cd longfellow-zk
cmake --preset release
cmake --build --preset release --parallel
ctest --preset release
cmake --install build/release --prefix /path/to/prefix
```

Consume the installed package from CMake:

```cmake
find_package(LongfellowZK CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE LongfellowZK::shared) # or ::static
```

Set `CMAKE_PREFIX_PATH` when installing to a non-system prefix. Do not depend on
source-tree or build-tree include paths. See [Getting started](docs/getting-started.md)
for a complete consumer example and WASI instructions.

## Packages

| Package | CMake target | Purpose |
| --- | --- | --- |
| `LongfellowZK` | `LongfellowZK::shared` or `LongfellowZK::static` | Base proof system and generic circuits |
| `LongfellowZKECDSA` | `LongfellowZKECDSA::ecdsa` | ECDSA circuit headers |
| `LongfellowZKBIP340` | `LongfellowZKBIP340::bip340` | BIP340 circuit headers |
| `LongfellowZKMDoc` | `LongfellowZKMDoc::mdoc` | mdoc library and command-line tool |

The named projects consume an installed base package and can be packaged
independently. They are not part of the base library's public boundary.

## License and support

This distribution is free software under the
[GNU General Public License, version 3 or later](LICENSE). You may use, study,
modify, and redistribute it. If you distribute software that uses this library,
you must release that software under the same GPL terms and provide its
corresponding source. Files inherited from upstream retain their original
copyright and license notices.

For integration and packaging support, security coordination, or licensing
needs that the GPL does not accommodate, contact [info@dyne.org](mailto:info@dyne.org).
We will work with you toward a suitable solution.

Longfellow-ZK is maintained by the [Dyne.org foundation](https://dyne.org) with
support from EU Horizon grant 101132610 through
[PACESETTERS](https://pacesetters.eu).
