---
title: Optional Google Rust parity suite
description: Run and interpret the opt-in comparison against the pinned Google Rust implementation.
---

# Optional Google Rust parity suite

`make google-rust-parity` is an opt-in developer qualification command. It
compares bounded, deterministic records produced by this repository's C++
implementation and the Google Rust implementation at the gitlink pinned in
`vendor/longfellow-zk`. CI runs it as a dedicated `Google Rust parity` job;
it is not folded into the normal build, CTest, install, package, consumer, or
release-qualification matrix.

## Run it

The command needs Git, CMake, a C++20 compiler, Python 3, Cargo, and network
access only if the configured Google submodule is absent. `ccache` is used for
the C++ oracle when available; its absence is supported and reported as
`C++ launcher=none (ccache unavailable)`.

```sh
make google-rust-parity
```

It resolves the repository root, checks that `vendor/longfellow-zk` is the
configured `https://github.com/google/longfellow-zk` submodule, and reads the
expected commit from the superproject gitlink. If that checkout is absent it
runs a targeted `git submodule update --init -- vendor/longfellow-zk`. An
existing checkout is never reset: a dirty tree, different `origin`, or a HEAD
that differs from the gitlink stops with a nonzero actionable diagnostic.

The C++ build is isolated under `build/google-rust-parity/cpp` and Cargo output
under `build/google-rust-parity/cargo`. Override those locations only when
needed:

```sh
GOOGLE_RUST_PARITY_BUILD_DIR=/tmp/lf-parity \
GOOGLE_RUST_PARITY_CARGO_TARGET_DIR=/tmp/lf-parity-cargo \
make google-rust-parity
```

After the first successful run, Cargo's cached dependencies permit an offline
rerun when the submodule and cache remain available. Remove the selected build
and Cargo-target directories to clean parity artifacts; do not remove or edit
the submodule to clean them.

The success output includes the exact Google gitlink and record count. On a
drift, it identifies the primitive subset, case ID, pinned commit, and the two
normalized outcomes. It intentionally does not print witnesses, proofs,
language-specific exception text, addresses, or timings.

## What a passing comparison means

The binary `LFP2` record runner compares canonical values and normalized
success/rejection decisions for a fixed corpus. It does not establish a general
proof of equivalence, cross-version compatibility, constant-time behavior, or
interoperability with an arbitrary Google checkout.

| Area | Comparison asserted | Not asserted |
| --- | --- | --- |
| Transcript | Exact deterministic byte streams, including clone and PRF-boundary cases | Randomized transcript behavior |
| Fields and curve | Canonical field/affine bytes and shared decode decisions for bounded inputs | C++ wrong-length decoding, whose public API is fixed-width rather than recoverable |
| LCH14 and Reed-Solomon | Exact transform, basis, and bounded interpolation arrays | All dimensions or every field configuration |
| Merkle | Roots/path values and normalized valid/tampered verification outcomes | Every malformed-proof class |
| Circuit | Shared LFC1/LFC2 bytes, circuit ID, and bounded parser decisions | Equality of implementation-specific circuit geometry |
| Ligero | Bounded geometry, commitment-root/proof-shape bytes, and valid/tampered outcomes | Full proof-byte or reciprocal-proof parity |
| RFC ZK | Deterministic commitment root plus valid/tampered public verification outcomes | Full ZK proof, sumcheck, transcript, or reciprocal-proof byte equality |

Local algebraic invariants and ordinary native regressions are diagnostic tests:
they can locate a fault, but are not cross-language parity evidence. Conversely,
an exact-byte row is a claim only for the named deterministic fixture and pinned
revision. Rows carrying booleans compare semantic acceptance/rejection rather
than diagnostic wording.

## Updating the Google revision

Changing the `vendor/longfellow-zk` gitlink is a reviewed compatibility event,
not a routine dependency refresh. Update it separately, run the relevant
upstream Rust package tests and this parity command, inspect every drift, and
add a narrow local regression for confirmed local defects. Never accept
regenerated records merely because the upstream revision changed.

For ordinary C++ release qualification, continue to use
[`make qualification-matrix`](production-qualification.md). Keep this manual
parity command separate unless a later policy decision deliberately adds it to
the release matrix.
