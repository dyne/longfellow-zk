---
title: Research and standards
description: Primary academic and standards references behind Longfellow-ZK and its reference projects.
---

# Research and standards

This bibliography follows the implementation from its direct design paper to
the proof-system components and application standards. Links point to primary
paper archives, standards bodies, or canonical specification repositories.

## Direct Longfellow references

**Matteo Frigo and abhi shelat (2024), “Anonymous Credentials from ECDSA.”**
The paper constructs efficient proofs of knowledge for ECDSA signatures and
combines them with SHA-256 and ISO document parsing. It reports 60 ms ECDSA
proof generation and mobile mdoc presentation proofs around 1.2 seconds for its
tested configurations. Those figures describe the paper's benchmarks, not a
guarantee for every device or this fork.
[IACR ePrint 2024/2010](https://eprint.iacr.org/2024/2010)

**Matteo Frigo and abhi shelat (2025), “libZK: a zero-knowledge proof
library.”** The Internet-Draft specifies the argument for a circuit relation
`C(x,w)=0`, combining a sumcheck-based verifiable-computation protocol with
Ligero. Internet-Drafts expire and may change.
[IETF Datatracker](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)

## Proof-system foundations

**Scott Ames, Carmit Hazay, Yuval Ishai, and Muthuramakrishnan
Venkitasubramaniam (2022), “Ligero: Lightweight Sublinear Arguments Without a
Trusted Setup.”** Ligero supplies the Reed–Solomon-based commitment and
zero-knowledge argument for linear and quadratic constraints. The 2022 ePrint
is the extended version of the CCS 2017 paper.
[IACR ePrint 2022/1608](https://eprint.iacr.org/2022/1608)

**Shafi Goldwasser, Silvio Micali, and Charles Rackoff (1989), “The Knowledge
Complexity of Interactive Proof Systems.”** This work formalized
zero-knowledge interactive proofs.
[SIAM Journal on Computing](https://doi.org/10.1137/0218012)

**Amos Fiat and Adi Shamir (1986), “How to Prove Yourself: Practical Solutions
to Identification and Signature Problems.”** The Fiat–Shamir transformation is
the basis for deriving verifier challenges from an ordered transcript.
[CRYPTO proceedings](https://doi.org/10.1007/3-540-47721-7_12)

**Sian-Jheng Lin, Wei-Ho Chung, and Yunghsiang S. Han (2014), “Novel Polynomial
Basis and Its Application to Reed–Solomon Erasure Codes.”** Longfellow's
binary-field extension machinery draws on this additive-FFT basis.
[arXiv:1404.3458](https://arxiv.org/abs/1404.3458)

## Signature and identity standards

**BIP340, “Schnorr Signatures for secp256k1.”** Pieter Wuille, Jonas Nick, and
Tim Ruffing specify the 64-byte Schnorr signature verified by the BIP340
reference circuit.
[Canonical Bitcoin BIPs repository](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

**ISO/IEC 18013-5:2021, “Personal identification — ISO-compliant driving
licence — Part 5: Mobile driving licence (mDL) application.”** This published
edition defines the mobile-document interfaces on which the mdoc application
is based. ISO lists the edition as published and under revision.
[ISO catalogue](https://www.iso.org/standard/69084.html)

**OpenID for Verifiable Presentations 1.0 and Digital Credentials Query
Language.** The OpenID Foundation published OpenID4VP 1.0 as a Final
Specification in July 2025; section 6 defines DCQL. A Longfellow-specific mdoc
proof profile still needs an explicitly pinned format and parameter contract.
[OpenID4VP specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

## Engineering sources

- [Google Longfellow-ZK upstream](https://github.com/google/longfellow-zk)
- [Dyne Longfellow-ZK distribution](https://github.com/dyne/longfellow-zk)
- [ISRG experimental Rust implementation](https://github.com/abetterinternet/zk-cred-longfellow)
- [EUDI zero-knowledge proof technical specification](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts14-zkps-from-mms.md)
