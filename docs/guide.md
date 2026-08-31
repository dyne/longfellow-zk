---
title: Start here
description: Choose the shortest route into Longfellow-ZK for your background and goal.
---

# Start here

Longfellow-ZK lets a prover demonstrate that a private value satisfies a public
rule without disclosing the private value itself. This distribution packages
the reusable proof machinery separately from application circuits for mdoc,
ECDSA, and BIP340.

## Choose your route

| If you are… | Start with… | Then read… |
| --- | --- | --- |
| Curious about privacy | [Zero-knowledge, gently](zero-knowledge.md) | [Present and future uses](use-cases.md) |
| Building digital identity | [mdoc](projects/mdoc.md) | [Security](security.md) |
| Integrating C++ or WASM | [Getting started](getting-started.md) | [API and ABI](api.md) |
| Reviewing the cryptography | [Architecture](architecture.md) | [Specifications](specifications/index.md) |
| Maintaining a release | [Packaging](packaging.md) | [Production qualification](production-qualification.md) |
| Comparing with Google Rust | [Optional parity suite](google-rust-parity.md) | [Interoperability](interoperability.md) |

## What it is

- A C++20 library for compiling and evaluating arithmetic circuits and for
  generating and verifying zero-knowledge arguments.
- A combination of a sumcheck-based interactive proof with Ligero commitments,
  made non-interactive through a Fiat–Shamir transcript.
- A base package plus named reference projects. Dependencies flow from a named
  project into the base library, never the reverse.
- A soft fork of Google's Longfellow-ZK, maintained by Dyne.org under Apache-2.0.

## What it is not

- It is not a blockchain, cryptocurrency, credential issuer, or wallet.
- It does not make a false statement true. The circuit defines exactly what a
  valid witness must satisfy.
- It does not make all surrounding metadata private. Session identifiers,
  timing, and application behavior still require privacy engineering.
- It does not provide a blanket production-safety claim. Parameters, circuits,
  integrations, and release artifacts must be reviewed together.

## The shortest technical path

```sh
git clone --recurse-submodules https://github.com/dyne/longfellow-zk.git
cd longfellow-zk
cmake --preset release
cmake --build --preset release --parallel
ctest --preset release
```

Continue with [Getting started](getting-started.md) for prerequisites, debug and
sanitizer builds, WASI, installation, and package consumption.
