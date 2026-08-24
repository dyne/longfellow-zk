---
title: Zero-knowledge, gently
description: A plain-language introduction to zero-knowledge proofs and how Longfellow-ZK uses them.
---

# Zero-knowledge, gently

Suppose a venue needs to know that you are over 18. A conventional identity
check may reveal your name, exact birth date, address, document number, and
photo. The venue needed one fact and received an entire identity record.

A zero-knowledge proof changes the exchange. You hold a private *witness*—for
example, a signed credential containing your birth date. A public *statement*
says what must be true—such as “the credential is authentic and its holder is
at least 18 today.” The proof convinces a verifier that the statement is true
without sending the witness itself.

## The three roles

- The **issuer** signs a credential in the ordinary way.
- The **prover** holds the signed credential and generates a proof about it.
- The **verifier** checks the proof and learns only the public claim and any
  attributes deliberately disclosed by the prover.

The circuit is the rulebook. It encodes signature verification, document
parsing, comparison, hashing, and other checks needed to connect the hidden
witness to the public statement.

## Four properties to keep separate

**Completeness** means an honest prover with a valid witness can produce a proof
that verifies. **Soundness** means a prover should not be able to convince the
verifier of a false statement. **Zero-knowledge** means the proof reveals no
information about the private witness beyond what follows from the public
statement. **Knowledge soundness** ties acceptance to possession of a witness,
not merely to a lucky transcript.

These are protocol properties under stated assumptions. An application can
still leak through logs, timing, network identifiers, overly specific queries,
or repeated identifiers. Zero-knowledge is a powerful component of privacy
engineering, not a privacy force field.

## Where Longfellow fits

Longfellow compiles checks into arithmetic circuits, runs a sumcheck-based
interactive proof, commits to relevant values with Ligero, and derives the
verifier's challenges with a Fiat–Shamir transcript. The result is a
non-interactive argument that can be sent and verified later.

The design uses collision-resistant hashing and does not require a trusted setup
ceremony. This removes one operational dependency; it does not remove the need
to review circuit correctness, parameters, randomness, transcript binding,
parsers, or the surrounding protocol.

## A useful mental model

Think of a sealed, transparent-to-the-rules machine. You put the private
credential into the machine. The verifier can inspect the machine's rulebook
and verify its tamper-evident receipt, but cannot see the credential. The proof
is that receipt; the circuit is the rulebook; the witness is what stayed sealed.

Next: explore [present and future use cases](use-cases.md), or descend into the
[technical architecture](architecture.md).
