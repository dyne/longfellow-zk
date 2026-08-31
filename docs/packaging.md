---
title: Packaging for distributions
description: Dependencies, staged installation, package splits, ABI policy, licensing, and release checks.
---

# Packaging for distributions

Package the base library and each named circuit project separately. Downstream
projects must consume installed CMake packages; source-tree paths are not a
supported integration boundary.

## Package map

| Source directory | Suggested package | Installed CMake target | Additional dependency |
| --- | --- | --- | --- |
| repository root | `liblongfellow-zk` plus a development package | `LongfellowZK::shared`, `LongfellowZK::static` | None beyond the C++ toolchain |
| `projects/ecdsa` | `longfellow-zk-ecdsa-devel` | `LongfellowZKECDSA::ecdsa` | Installed `LongfellowZK` |
| `projects/bip340` | `longfellow-zk-bip340-devel` | `LongfellowZKBIP340::bip340` | Installed `LongfellowZK` |
| `projects/mdoc` | `longfellow-zk-mdoc` plus a development package | `LongfellowZKMDoc::mdoc` | Installed base and ECDSA packages; zstd |

ECDSA and BIP340 are header/interface packages. mdoc installs a static library
and the `longfellow-zk-mdoc` executable. Adjust package names to distribution
policy, but preserve the CMake package and target names.

## Base package recipe

Build requirements are CMake 3.20 or newer, Ninja (or another CMake generator),
and a C++20 compiler. For a release source checkout, initialize the pinned Git
submodules before running the full test suite.

```sh
cmake -S . -B build-package -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DBUILD_TESTING=OFF \
  -DLONGFELLOW_ZK_BUILD_TESTING=OFF
cmake --build build-package --parallel
DESTDIR="$pkgdir" cmake --install build-package
```

Use the distribution's multiarch library directory where applicable. Native
builds currently produce both static and shared libraries; WASI produces only
the static target. Do not patch public include paths or exported target names.

Split the staged files according to local policy:

- Runtime: the versioned shared object (or dylib).
- Development: the unversioned linker entry, static archive if shipped,
  `include/longfellow-zk/`, and `lib/cmake/LongfellowZK/`.
- Common documentation: `share/doc/LongfellowZK/` and the license under
  `share/licenses/LongfellowZK/`.

## Named project recipe

Build named projects only after their dependencies have been installed into a
staging or dependency prefix. The selected base linkage is explicit:

```sh
cmake -S projects/ecdsa -B build-ecdsa -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_PREFIX_PATH=/path/to/dependency-prefix \
  -DLONGFELLOW_ZK_TARGET=LongfellowZK::shared \
  -DBUILD_TESTING=OFF
cmake --build build-ecdsa --parallel
DESTDIR="$pkgdir" cmake --install build-ecdsa
```

Apply the same pattern to BIP340 and mdoc. Build ECDSA before mdoc, and make
zstd headers and library discoverable for mdoc. Use `LongfellowZK::static`
instead when the distribution intentionally packages a static dependency graph.

## Verify the installed contract

At minimum, configure and build both consumers in `test/cmake/consumer-shared`
and `test/cmake/consumer-static` against the staged prefix. Before a release,
run from a clean checkout:

```sh
bash scripts/ci-installed-package.sh
```

This builds and tests the base, installs and relocates it, builds every named
project against that installation, and verifies both linkage modes. The broader
[production qualification](production-qualification.md) covers platform,
sanitizer, static-analysis, compatibility, and optional Rust parity evidence.

CPack can produce an upstream `TGZ` with `cmake --build build-package --target
package`; distribution recipes should normally use the staged CMake install.

## ABI, upgrades, and rollback

The native shared library starts its stable release line at version `1.0.0`
with SOVERSION `1`. Release CI supplies the semantic version calculated from
conventional commits through `LONGFELLOW_ZK_VERSION`; source-tree builds default
to `1.0.0`. Longfellow-ZK does not promise binary compatibility across compilers
or C++ standard libraries. Follow the [ABI policy](abi.md), coordinate major
transitions, and never mix headers from one release with libraries from another.
Pin circuit IDs, formats, specifications, and vectors with the package version.

## Automated release versions

Successful `main` CI runs continue to publish the same platform archives,
checksums, BIP-340 metrics, generated notes, and non-draft GitHub release. The
release tag is now calculated by the pinned `ietf-tools/semver-action` action:

- the first semantic release is bootstrapped as `v1.0.0`;
- `BREAKING CHANGE` commits select a major increment;
- `feat` and `feature` select a minor increment;
- `fix`, `bugfix`, `perf`, `refactor`, and test commits select a patch;
- other or non-conventional commits fall back to a patch so the existing
  release-on-every-successful-main-push behavior is preserved;
- rerunning the same tagged commit reuses the current version.

Historical commit-SHA tags are ignored when locating the latest semantic
release. The strict version without the leading `v` is passed to CMake as
`LONGFELLOW_ZK_VERSION`; the leading-`v` form is used for the GitHub release
and metrics links.

## License and maintainer contact

The distribution is GPL-3.0-or-later. Ship the top-level `LICENSE`, preserve
copyright and license notices on inherited upstream files, and ensure software
distributed using the library is released under the same GPL terms with
corresponding source. For package review, security coordination, licensing
compatibility, or unusual platform requirements, contact
[info@dyne.org](mailto:info@dyne.org); we will work toward a suitable solution.
