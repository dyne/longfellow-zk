# ECDSA verification module contract

This pilot keeps the triple-scalar ECDSA equation and its historical advice
layout unchanged while separating responsibilities:

- `verify_types.h` defines native and circuit-side advice storage.
- `verify_layout.h` is the single source of native filler and circuit input
  allocation order. Its `1034` native values are protocol compatibility data.
- `verify_evaluate.h` derives native precomputation, advice bits, and
  intermediate points for `g*e + pk*r + R*-s = identity`.
- `verify_circuit.h` owns only the circuit relation and assertions.
- `verify_witness.h` remains the compatibility facade used by mdoc callers.

Use `make ecdsa-module-test` to check a valid P-256 fixture, the exact native
layout length/order, and rejection of a targeted intermediate-point corruptor.
The mdoc integration suite remains the artifact-level regression for circuit
and proof compatibility.
