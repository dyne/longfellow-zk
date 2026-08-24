# Production qualification and staged rollout

This record qualifies the C++20 boundary migration as an additive release. It
does not authorize protocol changes or replace an independent cryptographic
audit.

## Release evidence

Run the portable matrix from a clean checkout with the Rust submodule present:

```sh
make qualification-matrix
cat test/results/qualification_matrix.csv
```

The raw CSV is included in the native CI release package. Its fixed rows cover
C++20 contract/negative compilation, byte-identical LFC1 vectors from both C++
and Rust, C++↔Rust LFC2 round trips, seeded parser and transcript fuzz replay,
ECDSA module/artifact and Dense ownership boundaries, compiler
assertion/ownership boundaries, and the deterministic metric schema.
Any non-`pass` row rejects the candidate; the script never writes reviewed
vectors.

`baseline-metrics` publishes the input-size CSV alongside that matrix. It has
three rows each for synthetic, BIP340, and mdoc inputs. Budgets are:
no reviewed-vector or canonical-ID drift; no >10% C++20 contract elapsed-time
increase on the same host; and native/static/WASM size growth above 1% requires
release review. The current recorded baseline and its limitations are in
[C++20 migration measurements](cpp20_migration_metrics.md).

GitHub Actions is the authoritative platform matrix: native Clang/Linux runs
mdoc Bats; WASI builds and executes `test/wasm_test.mjs`; macOS ARM64 builds and
runs the mdoc gates; separate jobs run ASan/UBSan and static analysis. A release
candidate must retain successful artifacts for every job, including the BIP340
aggregate CSV, before promotion.

## Boundary audit checklist

The release reviewer records the candidate SHA, toolchain/version, platform,
CSV artifacts, and reviewer in the deployment ticket, then confirms:

- Transcript cloning preserves active PRF state; parser limits reject malformed
  input before allocation; and LFC1 serialization remains byte-identical.
- Canonical circuit IDs, metadata, and proof bytes are unchanged; LFC2 detects
  magic, malformed/non-minimal values, ID mismatches, and trailing bytes.
- Compiler assertion symbols and witness-layer ownership remain covered by
  their dedicated tests; release scheduling has no retained mutable layer.
- Optimizer changes do not alter circuit IDs or compatibility vectors. Any such
  change is a protocol review, not a performance-only release.
- mdoc and BIP340 results are consumed only within their documented support
  boundaries.

## Upgrade, observation, and rollback

Deploy canaries with the existing LFC1 default first. LFC2 is opt-in through
`CircuitFormat::kLfc2`; detection is its `LFC2` magic and the reader continues
to accept historical LFC1. Record format counts, parse rejection reason,
canonical circuit ID, proof verification outcome, peak memory, latency, and
the deployed SHA without logging witnesses, secrets, or full proofs.

Roll back by disabling the LFC2 writer selection and redeploying the previous
binary. No artifact conversion is required: the reader accepts both formats,
LFC1 remains the default writer, and proofs/circuit IDs are not reformatted.
Keep historical LFC1/LFC2 artifacts and the compatibility manifest accessible
until the retention policy expires. Stop rollout on any vector drift, parser
limit rejection increase, ID mismatch, sanitizer issue, or unsupported-platform
result; preserve the raw CSV and logs for investigation.

Maintainability rule: new format, parser, transcript, metadata, ownership, or
optimizer work must add a narrow contract test and update this matrix only with
a reviewer-approved, explicitly versioned compatibility decision. Do not widen
resource limits or replace legacy adapters as incidental cleanup.
