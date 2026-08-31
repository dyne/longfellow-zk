---
title: API and ABI
description: Supported package targets, public headers, dynamic-link policy, and mdoc C/WASM boundaries.
---

# API and ABI

Longfellow-ZK exposes three distinct integration surfaces: installed C++ CMake
targets, explicitly exported dynamic-link symbols, and application-specific C
or WASM adapters.

For a new integration, use an installed CMake target and public installed
headers. Do not treat source paths, build paths, or unexported symbols as API.

## Installed C++ targets

| Package | Target | Kind |
| --- | --- | --- |
| `LongfellowZK` | `LongfellowZK::static`, `LongfellowZK::shared` | Compiled base library |
| `LongfellowZKECDSA` | `LongfellowZKECDSA::ecdsa` | Header/interface circuit library |
| `LongfellowZKBIP340` | `LongfellowZKBIP340::bip340` | Header/interface circuit library |
| `LongfellowZKMDoc` | `LongfellowZKMDoc::mdoc` | Static application library |

WASI builds only the static base target. The native shared target starts at
version `1.0.0` and SOVERSION `1`; release builds use the version selected by
the semantic-version workflow.

## 1.x dynamic-link policy

Only declarations marked `LONGFELLOW_ZK_API` are supported shared-library entry
points. Header-only templates and inline gadgets compile inside the consumer.
Callers retain ownership of their allocations; STL containers and
allocator-owned objects must not cross the ABI.

Public operations do not throw as part of their contract. Exception- and
RTTI-disabled builds remain supported. Independent calls using caller-owned
state are safe, but callers must synchronize any shared mutable object.

The project does not promise C++ ABI compatibility across compilers or standard
libraries during 0.x. Read the full [ABI policy](abi.md) before distributing a
shared-library integration.

## Public headers

The CMake manifest is authoritative. Base headers install under
`include/longfellow-zk/` while preserving their paths below `src/`; named
projects install under their own `longfellow-zk-*` include roots. Do not include
private build-tree paths in a consumer.

## mdoc C and WASM conventions

The mdoc API exposes explicit prover and verifier error-code enums. Prover output
uses caller-visible length fields and allocated proof bytes; follow the matching
release/ownership contract in the header used by your version.

The WASM adapter's preferred `_tobuf` entry points write JSON or encoded results
into caller-supplied output buffers and diagnostics into separate error buffers.
Binary inputs and outputs use lowercase hexadecimal text. Return `0` means
success; any non-zero return must be handled as a failure even if output text is
present.

::: danger Version the full boundary
Pin the library version, named-project version, circuit ID, ZK specification
index, wire format, and test vectors together. A compatible C++ call signature
alone does not establish protocol compatibility.
:::

If the supported boundary does not cover an integration or platform need,
contact [info@dyne.org](mailto:info@dyne.org) before depending on an internal
surface.
