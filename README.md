# Longfellow-ZK - made in Europe

Longfellow-ZK is a **Zero Knowledge** circuit [system developed by engineers at Google](https://github.com/google/longfellow-zk) and specifically designed to create ad-hoc ZK circuits that can be executed at competitive speed both for presenting and verifying proofs. Here is [our independent benchmark](https://news.dyne.org/longfellow-zero-knowledge-google-zk/) and the results are impressive.

This repository is a soft fork of [Google's Longfellow-ZK library](https://github.com/google/longfellow-zk), it is made in **Europe** and maintained by the **Dyne.org foundation**, based in Amsterdam to best serve the purposes of the [EUDI ARF development](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework). Our effort is currently supported by the EU HORIZON grant nr.[101132610](https://cordis.europa.eu/project/id/101132610) (PACESETTERS).

[![PACESETTERS project](/docs/pacesetters_logo.svg)](https://pacesetters.eu)

## Purpose and strategy

The purpose of this distribution is to make Longfellow-ZK available for European wallets and to welcome contributions without the need to sign any development agreement with Google. We work to grant full portability to WebAssembly (WASM) builds, native mobile environments (Android and iOS) as well add usable command-line tools (CLI) for testing purposes.

By **soft fork** we mean that changes we make to the code are fully backward compatible with Google's upstream code, while we may adopt different implementation approaches: for instance we already removed the OpenSSL dependency with embedded code, we added a bunch of SIMD128 assembler primitives and made a few more lower-system changes for portability.

This If Longfellow-ZK will ever include changes that break EUDI functionalities or go against the interest of European implementations, this will turn into an hard-fork and we'll publish a roadmap to highlight divergent paths and compatibilities.

## Current Status

This distribution is at an early stage and includes all upstream primitives for circuit design, as well the upstream implementation for ISO mDoc (U.S. mobile driver's license) credentials for identity verification, and stubs for JWT parsing and plans for additional circuits supporting EUDI and e-ID implementations.

For now, just like the upstream code, this is a demonstrator at TRL 4 and we just focus on portability and test environment, but we also devleoping a [language (DSL) to design longfellow-zk circuits](https://github.com/dyne/Zenroom/pull/1143) which will soon be ready to ease the customization of circuits fitting EUDI standard formats.

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

This distribution project and all additional code contributed by Dyne.org is also licensed as **Apache 2.0**.

Everyone is welcome to submit patches under MIT and/or Apache 2.0 licenses.

![Funded by the European Union](https://www.pacesetters.eu/sites/default/files/inline-images/EN_FundedbytheEU_RGB_POS.png)
