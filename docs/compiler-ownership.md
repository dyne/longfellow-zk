# Compiler pass ownership

`QuadCircuit` owns the source DAG (`nodes_`), its CSE table, constants, and
assertion-path side table for the complete construction lifetime.  A compiled
`Circuit` owns only its final compressed layers and optional assertion-symbol
artifact; it never borrows compiler storage.

Compilation has four ownership boundaries:

1. Algebraic construction/CSE creates stable node indices in `QuadCircuit`.
2. `order_by_layer` creates the scheduler-only layered DAG and copy segments.
3. `assign_wire_ids` creates one per-depth renamed view in a monotonic
   `PassArena`; the arena is released before advancing to the next depth.
4. `fill_layers` compresses each output layer, then swaps its layered source
   storage out immediately after its last read.  Assertion symbols are copied
   before that consuming pass begins.

The scheduler exposes two test/debug invariants after `mkcircuit`: every
renaming arena has been released, and every layered temporary has been
released.  The arena rejects double release and resource access after release;
its destructor rejects a forgotten release.  These checks deliberately guard
lifetimes, not algebraic rewrites.

## Optimization evidence boundary

The retained change is lifetime-only: CSE, copy-wire construction, canonical
scheduling order, and segment layout retain their exact algorithms.  The
`compiler-ownership-test` constructs isolated CSE and copy-segment cases,
repeats compilation, and compares serialized artifacts byte-for-byte.  It
also confirms the existing CSE and copy telemetry.  Larger application and
sanitizer gates remain required before accepting a future term-rewriting,
scheduling, or segment optimization; such changes must carry independent
artifact-size and differential evidence.
