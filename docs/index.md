---
layout: home
title: Longfellow-ZK
description: Privacy-preserving proofs for identity, signatures, and portable applications.
hero:
  name: "Longfellow-ZK"
  text: "Prove what matters. Keep the rest private."
  tagline: "A community-maintained C++ zero-knowledge system for existing identity and signature infrastructure — portable across native, mobile, and WebAssembly environments."
  actions:
    - theme: brand
      text: Understand the idea
      link: /zero-knowledge
    - theme: alt
      text: Explore use cases
      link: /use-cases
    - theme: alt
      text: Build from source
      link: /getting-started
features:
  - title: "Selective disclosure"
    details: "Show that a credential supports a claim without exposing every field in the credential."
    link: /projects/mdoc
  - title: "Existing signatures"
    details: "Build proofs around widely deployed ECDSA and BIP340 signatures instead of replacing issuer infrastructure."
    link: /projects/
  - title: "No trusted setup"
    details: "Longfellow combines sumcheck and Ligero, a hash-based argument system that avoids a ceremony-generated reference string."
    link: /architecture
  - title: "Portable by design"
    details: "The Dyne distribution targets C++20, WASI/WebAssembly, Android, iOS, and command-line workflows."
    link: /getting-started
---

## One project, three ways in

You do not need to be a cryptographer to understand why Longfellow-ZK exists.
Start with [zero-knowledge in plain language](zero-knowledge.md) and the
[problems it can solve](use-cases.md). Implementers can move directly to the
[mdoc, ECDSA, and BIP340 reference projects](projects/index.md). Protocol
reviewers can follow the [specification map](specifications/index.md) into the
full draft algorithms and test vectors.

## Why Dyne maintains this distribution

Longfellow-ZK began at Google. Dyne.org maintains this European soft fork as a
community-controlled implementation that can be deployed without depending on
a proprietary mobile operating-system API. The work supports open digital
identity infrastructure, including the European Digital Identity Wallet
ecosystem, while keeping the core library reusable beyond identity.

::: warning Project status
Longfellow-ZK is pre-1.0 software and active cryptographic engineering. Read the
[security and qualification boundaries](security.md) before a production
deployment. Documentation, test matrices, and external reviews are evidence;
they are not a substitute for a use-case-specific security assessment.
:::

[![PACESETTERS project, funded by the European Union](/project/eurobuild-card.jpg)](https://pacesetters.eu)
