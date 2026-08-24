---
title: Present and future use cases
description: What Longfellow-ZK enables now and where its reusable circuits may lead.
---

# Present and future use cases

Longfellow-ZK is especially useful when an issuer already signs data with a
widely deployed scheme and cannot be upgraded merely to support selective
disclosure. It moves privacy work to the presentation step: the holder proves a
claim about an existing signed object.

## Present: private identity presentation

The mdoc project targets ISO mobile-document flows. A holder can prove that a
document carries a valid issuer signature and selectively reveal requested
attributes. Circuits cover document parsing, SHA-256 hashing, ECDSA signature
verification, and policy checks such as time validity.

This can support age thresholds, residency, entitlement, and other
minimal-disclosure claims. The verifier must still request a sensible claim: a
query unique to one person can defeat privacy even if the proof reveals nothing
else.

## Present: proofs about deployed signatures

The ECDSA project packages circuits for a scheme already embedded in identity,
hardware, and institutional infrastructure. The BIP340 project does the same
for Schnorr signatures over secp256k1. Each can become one hidden fact inside a
larger proof.

## Present: portable verification

The C++ package builds as a native static or shared library. WASI enables
sandboxed WebAssembly verification, and the Dyne work targets Android and iOS
without requiring a proprietary proof API.

## Future: reusable privacy predicates

New circuits could prove membership in an allowed set, a value within a range,
or consistency between signed records. These are plausible extensions, not
features already implemented by the base library. Each circuit needs an
explicit statement, witness layout, vectors, and security review.

## Future: cross-domain credentials

Education, professional licensing, mobility, and regulated services use signed
records whose issuers change slowly. Longfellow's approach could add private
presentation without forcing every issuer onto a new signature suite.
Integration still depends on standards, revocation, freshness, verifier policy,
and wallet UX.

## Future: local-first and edge proofs

Native and WebAssembly implementations make it possible to generate or verify
proofs close to the user. Local processing can reduce data exposure and
centralized correlation, provided telemetry, stable identifiers, and server
orchestration do not reintroduce tracking.

::: tip Evaluate a use case with five questions
What precise fact is proven? What remains hidden? Which public inputs can link
sessions? Who chooses and reviews the circuit? How are parameters, versions,
and revocation handled over time?
:::
