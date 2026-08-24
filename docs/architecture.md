---
title: Architecture
description: How circuits, sumcheck, Ligero commitments, transcripts, and project packages fit together.
---

# Architecture

Longfellow-ZK separates the statement being proved from the generic machinery
that proves it. An application circuit describes a relation between public
inputs and a private witness; the base library compiles, evaluates, proves, and
verifies that relation.

## End-to-end proof flow

```text
Application data
  → witness construction
  → arithmetic circuit and canonical circuit ID
  → sumcheck transcript for circuit evaluation
  → Ligero commitment and constraint proof
  → Fiat–Shamir challenges
  → serialized non-interactive proof
  → verifier reconstructs challenges and checks all constraints
```

The prover commits before learning later challenges. The Fiat–Shamir transcript
derives those challenges from the statement and ordered protocol messages, so a
single proof can be verified without a live multi-round exchange.

## Base-library layers

| Layer | Representative source | Responsibility |
| --- | --- | --- |
| Fields and coding | `src/algebra/`, `src/gf2k/` | Finite-field operations, FFTs, Reed–Solomon encoding |
| Circuit model | `src/circuits/`, `src/sumcheck/circuit*` | Logic gadgets, compiler, layers, canonical circuit identity |
| Interactive proof | `src/sumcheck/` | Reduce circuit evaluation to polynomial claims |
| Commitment proof | `src/ligero/`, `src/merkle/` | Commit to encoded values and open challenged positions |
| Transcript and randomness | `src/random/` | Domain-separated messages and Fiat–Shamir challenges |
| Proof composition | `src/zk/` | Orchestrate prover, verifier, and proof objects |
| Serialization | `src/proto/`, `src/util/byte_cursor.h` | Circuit formats, bounds, canonical parsing |

## Sumcheck's role

The compiler represents the computation as layered arithmetic constraints.
Sumcheck lets the prover convince the verifier that these large collections of
constraints evaluate correctly while the verifier checks a much smaller number
of field operations. Longfellow specializes the representation and transcript
for its circuit structure.

## Ligero's role

Ligero encodes witness-related values with Reed–Solomon codes, commits to them
with a Merkle tree, and proves linear and quadratic constraints by opening a
challenge-selected subset. Its soundness derives from coding distance,
unpredictable challenges, and collision resistance. A random padding row hides
the witness-related rows used by the argument.

## Trust and assumption profile

Longfellow avoids a trusted setup and does not require pairing-friendly curves.
Its deployed assumptions include collision-resistant hashing, sound parameter
selection, secure randomness, the Fiat–Shamir model and transcript construction,
and correct circuit compilation. “No trusted setup” does not mean “no trust”: a
deployment still trusts reviewed code, build artifacts, parameters, circuits,
and the verifier's interpretation of public inputs.

## Package boundary

The base follows the architecture of the upstream Rust workspace without
copying its Cargo directory structure. Named mdoc, ECDSA, and BIP340 projects
depend on the base. The ownership manifest rejects missing, duplicate, stale,
or reverse dependencies. Read the [boundary document](liblongfellow-zk-boundary.md)
for the precise rule.

## Artifact boundaries

Circuits have canonical identifiers. LFC1 remains the default storage writer;
LFC2 is a compact, opt-in circuit format that preserves circuit IDs, arithmetic,
transcripts, and proof bytes. See [LFC2 circuit storage](lfc2.md).
