# Dyne.org Longfellow-ZK

Prove attributes without revealing the underlying credential data: privacy-preserving verification of digital credentials using zero-knowledge proofs.

## Project Overview

This is a community based distribution of Google's **Longfellow-ZK** library, maintained by **Dyne.org**.

The purpose of this distribution is to make Longfellow-ZK available for community use and contributions, ensuring full portability to WebAssembly (WASM) builds, native mobile environments (Android and iOS) as well add usable command-line tools (CLI).

Longfellow-ZK is a C++ zero-knowledge proof system specifically designed to help the design of complex circuits that can be executed at competitive speed both for creating and verifying proofs.

Our distribution includes the upstream implementation for ISO mDoc (U.S. mobile driver's license) credentials for identity verification, as well as stubs for JWT parsing and plans for additional circuits supporting EUDI and e-ID implementations.


## References
- [Anonymous credentials from ECDSA](https://eprint.iacr.org/2024/2010)
- [libzk: A C++ Library for Zero-Knowledge Proofs](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)
- [Independent benchmark at Dyne.org](https://news.dyne.org/longfellow-zero-knowledge-google-zk/)
- [Privacy analysis](https://news.dyne.org/privacy-in-eudi) explaining why one should never use a ZK library via OS API.

## Known implementations

- Upstream Longfellow-zk: https://github.com/google/longfellow-zk
- Zenroom VM: https://zenroom.org via "no-code" Zencode
- Multipaz https://github.com/openwallet-foundation/multipaz API library by Google and OWF
- Rust: https://github.com/abetterinternet/zk-cred-longfellow experimental port by ISRG

## Licensing

The upstream Google implementation is mostly left untouched in this distribution and it is licensed as **Apache 2.0**.

This distribution project and all additional code contributed by Dyne.org on top of the upstream project is licensed under **GNU AGPL v3**. If you need this to change: let's talk.

Everyone is welcome to submit patches under Apache 2.0 license.
