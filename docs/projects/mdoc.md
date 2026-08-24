---
title: mdoc reference project
description: Zero-knowledge presentation of ISO mobile documents with ECDSA verification and selective attributes.
---

# mdoc reference project

The mdoc project is the most complete application in this distribution. It owns
the document circuits, public C API, command-line tool, WASM adapter, fixtures,
and zstd decompression support. It consumes installed base and ECDSA packages;
zstd remains a private dependency.

## What the proof connects

The private witness contains the signed mobile document and undisclosed
attributes. The circuit parses the CBOR structure, hashes the relevant data,
verifies the issuer's ECDSA P-256 signature, applies the requested attribute and
time checks, and binds the result to a session transcript. Public inputs include
the verifier's request context and the claims intentionally revealed.

## Command-line workflow

After installing the base and ECDSA packages and building `projects/mdoc`, the
`longfellow-zk-mdoc` executable exposes three main operations:

```sh
# Inspect available parameter sets and generate a circuit artifact.
longfellow-zk-mdoc circuit_gen --zkspec list
longfellow-zk-mdoc circuit_gen --zkspec latest --circuit circuit.json

# Generate a proof from a circuit and an mdoc fixture.
longfellow-zk-mdoc mdoc_prove \
  --circuit circuit.json \
  --mdoc mdoc.json \
  --proof proof.bin

# Verify the proof and its metadata.
longfellow-zk-mdoc mdoc_verify \
  --circuit circuit.json \
  --proof proof.bin
```

The CLI also accepts `--benchmark <file>` to append nanobenchmark output.
Treat the exact artifact schema and ZK specification index as versioned inputs,
not values to hard-code independently.

## C++ package

```cmake
find_package(LongfellowZK CONFIG REQUIRED)
find_package(LongfellowZKECDSA CONFIG REQUIRED)
find_package(LongfellowZKMDoc CONFIG REQUIRED)
target_link_libraries(app PRIVATE LongfellowZKMDoc::mdoc)
```

The installed public headers remain under `include/longfellow-zk-mdoc/`. The
mdoc library is static in the current project configuration.

## WASM boundary

The adapter uses preallocated output and error buffers. Binary values cross the
text boundary as lowercase hexadecimal strings, and functions return `0` on
success and a non-zero error code on failure. Prefer the
`longfellow_zk_*_tobuf` functions; compatibility wrappers that print to
standard output are retained only for older callers.

## Standards boundary

The implementation concerns mobile-document proofs and references ISO/IEC
18013-5. The published 2021 edition is under revision, while ZK presentation
parameters appear in newer working material. Pin the exact standard edition,
ZK specification index, circuit hash, and verifier request format for every
deployment.
