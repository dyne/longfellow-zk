# Longfellow-ZK - made in Europe

Longfellow-ZK is a **Zero Knowledge** circuit [system developed by engineers at Google](https://github.com/google/longfellow-zk) and specifically designed to create ad-hoc ZK circuits that can be executed at competitive speed both for presenting and verifying proofs. Here is [our independent benchmark](https://news.dyne.org/longfellow-zero-knowledge-google-zk/) and the results are impressive.

This repository is a soft fork of [Google's Longfellow-ZK library](https://github.com/google/longfellow-zk), it is made in **Europe** and maintained by the **Dyne.org foundation**, based in Amsterdam to best serve the purposes of the [EUDI ARF development](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework).

Our effort is currently supported by the EU HORIZON grant nr.[101132610](https://cordis.europa.eu/project/id/101132610) (PACESETTERS).

[![PACESETTERS project](/docs/eurobuild_card.jpg)](https://pacesetters.eu)

## Purpose and strategy

This is **the community maintained Longfellow-ZK C++ implementation**. It doesn't depend from the Google Play API and **grants freedom of choice for mobile OS**, whilst solving a [privacy problem impacting the use of ZK](https://news.dyne.org/privacy-in-eudi).

Is is also fully portable to **WebAssembly (WASM) builds**, native mobile environments (Android and iOS) and adds usable command-line tools (CLI) for testing purposes.

## References
- [Anonymous credentials from ECDSA](https://eprint.iacr.org/2024/2010)
- [libzk: A C++ Library for Zero-Knowledge Proofs](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)
- [Independent benchmark at Dyne.org](https://news.dyne.org/longfellow-zero-knowledge-google-zk/)
- [Privacy analysis on integration](https://news.dyne.org/privacy-in-eudi) explaining why one should never use a ZK library via OS API.

## Known implementations

- Upstream Longfellow-zk: https://github.com/google/longfellow-zk
- ZKCC: Circuit Compiler DSL inside Zenroom VM: https://zenroom.org
- EUDI-zk: EUDI compliant implementation journeys and [specifications](https://github.com/MyNextID/eudi-zk/tree/main/specs)
- Multipaz https://github.com/openwallet-foundation/multipaz API library by Google and OWF
- Rust: https://github.com/abetterinternet/zk-cred-longfellow experimental port by ISRG

## Licensing

The upstream Google implementation is mostly left untouched in this distribution and it is licensed as **Apache 2.0**.

Some additional code is Copyright (C) by the Dyne.org foundation is also licensed as **Apache 2.0**.

The Blindzap circuit implementation is Copyright (C) by the Plan-B foundation and licensed as **GPLv3+**.

Everyone is welcome to submit patches under MIT and/or Apache 2.0 licenses.

![Funded by the European Union](https://www.pacesetters.eu/sites/default/files/inline-images/EN_FundedbytheEU_RGB_POS.png)
