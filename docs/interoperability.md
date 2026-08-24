---
title: Interoperability
description: C++/Rust vectors, LFC1 and LFC2 circuit formats, WASI, and compatibility discipline.
---

# Interoperability

Interoperability is established by canonical artifacts and executable vectors,
not by similar type names in two implementations.

## C++ and Rust

The Dyne repository vendors Google's C++ source and carries a read-only upstream
Rust implementation for comparison. The qualification matrix checks
byte-identical LFC1 fixtures and C++↔Rust LFC2 round trips. The Rust source is a
reference and interop dependency; it is not silently rewritten to follow local
C++ changes.

## Circuit storage

LFC1 is the historical and default writer format. Readers accept LFC1 and LFC2.
LFC2 begins with `LFC2` magic, uses minimal unsigned LEB128 values and compact
layer dictionaries, ends in the unchanged 32-byte circuit ID, and retains the
same resource limits as LFC1.

LFC2 changes storage only. It does not change circuit arithmetic, canonical IDs,
proof bytes, or transcripts. Parser rejection covers truncation, malformed or
non-minimal varints, overflow, invalid indices, noncanonical field elements, ID
mismatch, trailing data, and configured allocation limits.

## WASI

The WASI preset exercises a reactor-style module and avoids the native shared
library. Application adapters should keep binary serialization and return-code
semantics identical across native and WebAssembly boundaries.

## Compatibility evidence

```sh
make qualification-matrix
cat test/results/qualification_matrix.csv
```

Rows cover C++20 contracts, reviewed LFC fixtures, cross-language round trips,
seeded parser/transcript fuzz replays, application modules, ownership checks,
and deterministic metrics. Any non-`pass` row rejects the candidate.

## Change discipline

A change to a parser, transcript, circuit metadata, canonical ID, proof bytes,
or resource limit is a protocol decision. It requires a versioned compatibility
record and focused vectors; it must not arrive as incidental optimization or
cleanup.
