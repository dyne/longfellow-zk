---
title: About this implementation
description: Provenance, stewardship, scope, and licensing of the Dyne.org Longfellow-ZK distribution.
---

# About this implementation

Longfellow-ZK was developed by engineers at Google for zero-knowledge proofs
about established identity formats and signature systems. This repository is a
soft fork maintained by the Dyne.org foundation in Amsterdam.

## Why a community distribution?

Dyne's goal is deployment freedom: applications should be able to use the
cryptographic implementation through native, mobile, WebAssembly, and
command-line environments without depending on a single mobile OS vendor API.
That choice matters when privacy infrastructure must remain inspectable,
portable, and under the control of the institutions and people operating it.

The base library is deliberately separated from the named mdoc, ECDSA, and
BIP340 projects. The split makes the reusable cryptographic boundary explicit
and lets integrators install only the packages they need.

## European digital identity context

The maintenance effort supports work around the European Digital Identity
Architecture and Reference Framework. It is supported by EU Horizon grant
101132610 through the [PACESETTERS project](https://pacesetters.eu).

## Provenance and licenses

- [Dyne distribution](https://github.com/dyne/longfellow-zk)
- [Google upstream](https://github.com/google/longfellow-zk)
- [Apache License 2.0](https://github.com/dyne/longfellow-zk/blob/main/LICENSE)
- Contributions may be submitted under MIT and/or Apache-2.0 terms, following
  repository policy.

The upstream code remains identifiable in the vendored submodule. Dyne-owned
additions carry their own copyright notices.

## Documentation layers

This website distinguishes explanatory guides, current integration pages,
maintainer compatibility records, and upstream specification mirrors. The
mirror's source of truth remains the vendored upstream directory.
