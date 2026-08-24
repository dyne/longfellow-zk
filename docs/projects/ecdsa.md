---
title: ECDSA reference project
description: P-256 ECDSA verification circuits packaged independently from the Longfellow-ZK base.
---

# ECDSA reference project

ECDSA is deeply deployed in identity documents, secure elements, and public-key
infrastructure. The reference project makes verification of an ECDSA signature
part of a zero-knowledge statement, allowing the signature and signed values to
remain inside the witness when the larger circuit permits it.

## Circuit structure

The header-only project separates types, witness generation, circuit layout,
evaluation, and the composed verification circuit:

- `verify_types.h` defines the input and witness shapes.
- `verify_witness.h` derives witness values from a signature instance.
- `verify_layout.h` lays out the arithmetic constraints.
- `verify_evaluate.h` evaluates the same relation outside compilation.
- `verify_circuit.h` composes the verifier circuit.

## Consume the package

```cmake
find_package(LongfellowZK CONFIG REQUIRED)
find_package(LongfellowZKECDSA CONFIG REQUIRED)
target_link_libraries(app PRIVATE LongfellowZKECDSA::ecdsa)
```

The exported target is an interface target and therefore compiles the circuit
headers in the consumer's C++20 toolchain. Native tests exercise the module;
the WASI configuration builds an exported verification smoke function.

## Why it matters for credentials

The *Anonymous Credentials from ECDSA* construction by Matteo Frigo and abhi
shelat shows how proof-of-signature circuits, SHA-256, and document parsing can
support private presentation without changing the issuer's signature process.
The mdoc project builds directly on this package.

::: warning Scope
This module proves the relation encoded by its circuit. It does not define
credential issuance, revocation, holder binding, verifier policy, or the entire
presentation protocol.
:::
