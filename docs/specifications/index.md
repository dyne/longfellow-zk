---
title: Specifications map
description: Navigate from the Longfellow construction to Ligero, sumcheck, storage formats, and executable vectors.
---

# Specifications map

These pages descend from the whole protocol into its components. The long-form
mirrors preserve upstream draft material for study alongside the Dyne
implementation. They are not rewritten as independent standards.

## Read in this order

1. [Architecture](../architecture.md) gives the compact implementation map.
2. [libzk draft mirror](libzk.md) defines the complete construction, notation,
   transcript, fields, circuit relation, prover, and verifier.
3. [Sumcheck](sumcheck.md) explains the layered circuit argument and its
   transcript constraints.
4. [Ligero](ligero.md) defines commitments, Merkle openings, low-degree tests,
   and linear/quadratic constraint checks.
5. [Test vectors](test-vectors.md) provide concrete encodings for Merkle,
   Fiat–Shamir, circuits, sumcheck, Ligero, and the combined protocol.
6. [LFC2](../lfc2.md) specifies Dyne's compact circuit-storage format and
   compatibility boundary.

## Source and status

The mirrored algorithm pages come from
`vendor/longfellow-zk/docs/specs/` at the upstream submodule revision pinned by
this repository. The libzk document identifies itself as
`draft-google-cfrg-libzk-01`, dated 24 July 2025. Internet-Drafts are working
documents, not final standards; consult the
[IETF Datatracker](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)
for publication status and newer revisions.

## Normative implementation records

The specification describes algorithms. The following local records constrain
this distribution's artifacts and maintenance:

- [0.x ABI policy](../abi.md)
- [Package boundary](../liblongfellow-zk-boundary.md)
- [Compiler pass ownership](../compiler-ownership.md)
- [Production qualification](../production-qualification.md)
- [C++20 migration measurements](../cpp20_migration_metrics.md)

When prose and executable compatibility vectors disagree, stop the release and
resolve the versioning decision explicitly. Do not regenerate reviewed vectors
to make a changed implementation appear compatible.
