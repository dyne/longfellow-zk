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
- [GNU General Public License, version 3 or later](https://github.com/dyne/longfellow-zk/blob/main/LICENSE)

This distribution is free to use, study, modify, and redistribute. Software
distributed using the library must be released under the same GPL terms and
with corresponding source. The upstream code remains identifiable, and files
inherited under compatible licenses retain their original copyright and license
notices.

## Contact

Contact [info@dyne.org](mailto:info@dyne.org) for adoption and packaging
support, security coordination, contributions, or licensing needs. If the GPL
does not fit a particular requirement, talk to us and we will work toward a
suitable solution.
