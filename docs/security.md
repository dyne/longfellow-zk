---
title: Security and qualification
description: Assumptions, external reviews, parser limits, release evidence, and claims this project does not make.
---

# Security and qualification

Security spans the mathematical protocol, circuit correctness, implementation,
build artifacts, application integration, and operational environment. Passing
the repository's release gates is necessary evidence, not a universal safety
certificate.

For security reports or private coordination, contact
[info@dyne.org](mailto:info@dyne.org). Include the affected revision, platform,
and a minimal reproduction when possible; do not include real witnesses or
other user secrets.

## Protocol assumptions

- Collision-resistant hashes and secure transcript domain separation.
- Secure prover randomness and unpredictable Fiat–Shamir challenges.
- Sound Ligero and sumcheck parameters for the target security level.
- Correct arithmetic circuit compilation and witness construction.
- Correct binding of the circuit ID, public statement, session, and ordered
  protocol messages.

The protocol avoids a trusted setup. Its non-interactive form uses the
Fiat–Shamir transform and therefore inherits the assumptions documented by the
specification.

## Implementation defenses

Circuit readers enforce dimensional, byte, allocation, element, and layer
limits before accepting artifacts. Compatibility tests protect canonical IDs,
LFC1 bytes, and cross-language LFC2 behavior. Sanitizer, static-analysis, native,
WASI, and macOS jobs cover different failure classes.

Production observability should record deployed SHA, format, circuit ID,
rejection class, verification result, latency, and peak memory—never witnesses,
secrets, or complete proofs.

## External review record

Google's upstream documentation records an external Trail of Bits review, an
ISRG review, and an academic analysis of the concrete Ligero security bounds.
Review documents apply to their named revisions and scopes. Confirm that every
finding relevant to your pinned revision is addressed; do not transfer a review
claim automatically across a fork or later protocol change.

See the [upstream review page](https://google.github.io/longfellow-zk/docs/reviews/)
and the repository's [production qualification record](production-qualification.md).

## Release boundary

The current base package is pre-stable (`0.1.0`, SOVERSION `0`). The release
matrix tests source, artifact, and protocol compatibility, but does not promise
cross-toolchain C++ ABI compatibility. LFC2 remains opt-in and reversible;
LFC1 remains the default writer.

## Before production

1. Pin repository SHAs, toolchains, packages, circuits, parameters, and vectors.
2. Run the complete qualification matrix on every supported target.
3. Review the statement and witness boundary for the actual use case.
4. Threat-model linkability, replay, revocation, freshness, logs, and transport.
5. Arrange independent cryptographic and implementation review for material
   deviations from reviewed upstream code.
6. Canary the deployment and retain a rollback path with historical artifacts.
