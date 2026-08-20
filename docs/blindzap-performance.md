# BlindZap v1 performance and portability

BlindZap v1 has two fixed native circuit shapes: one or two distinct P2WPKH
witness programs.  A statement may contain up to 16 public claims, but claims
sharing a program reuse its relation; more than two distinct programs are
rejected before circuit allocation.  Four relations exceed Longfellow's CRT
block-encoding guard and are deliberately unsupported.

## Reproducing native metrics

Run `make blindzap-test` twice on an otherwise idle machine.  Each run writes
`test/results/native_blindzap_metrics.csv` with one row per real
prove/verify round:

```
target,circuit,build_ms,prove_ms,verify_ms,proof_bytes,public_inputs,total_inputs,quad_terms,crt_block_enc
```

The values are descriptive, not timing thresholds.  Record the commit SHA,
compiler/version and flags, CPU/OS, elapsed wall time and peak resident memory
next to a release candidate.  The deterministic columns (`proof_bytes`, input
and term counts, CRT block encoding) must agree across the two runs; the
timing columns are expected to vary.  The circuit digest is independently
checked by `blindzap_test`, and changing a circuit shape changes the digest.

## Current support boundary

The release target is native 64-bit C++17 on a Linux/x86_64 host using the
repository's hardened default flags (`-O3 -fstack-protector-all
-D_FORTIFY_SOURCE=2 -fno-strict-overflow`).  The checked envelope ceiling is
128 MiB, selected to bound allocation while admitting the supported proof
family.  32-bit and wasm builds are not release-supported BlindZap targets in
this repository; operators must not infer portability from the presence of a
generic wasm build target.  Re-run the compatibility and metric checks before
accepting any parameter, compiler, or circuit-digest change.
