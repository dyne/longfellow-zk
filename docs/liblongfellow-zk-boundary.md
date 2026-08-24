# liblongfellow-zk boundary

`cmake/manifests/longfellow-zk-boundary.cmake` is the authoritative ownership
inventory.  It classifies every tracked `src/**/*.cc` and `src/**/*.h` exactly
once.  The verifier rejects missing, duplicate, and stale entries.

The reusable base follows the Rust workspace shape without mirroring Cargo
directories: C++ algebra/arrays map to `core` and `compile`; compiler, logic,
MAC, SHA-256, RIPEMD-160, CBOR parsing, and generic secp256k1 gadgets map to
`compile/*` and `circuits/*`; transcript, Merkle, Ligero, sumcheck, random and
proof machinery map to `runtime/*` and `core/proto`.  This is an architectural
comparison only: `vendor/longfellow-zk` is read-only.

Named projects own mdoc, ECDSA, BIP340, and application CLIs.  The
only allowed dependency direction is named project -> base (plus explicitly
declared named-project dependencies).  Base files may not include those named
paths.  Test helper code is tooling, never a package input.

`longfellow-zk-sources.cmake` and `longfellow-zk-public-headers.cmake` expose
the base-owned subsets for the following CMake milestone.  Public headers are
installed beneath `include/longfellow-zk/` while retaining their path below
`src/`, so existing source-relative include spellings remain valid.  The first
package release is `0.1.0` / `SOVERSION 0`: source and protocol compatibility
are checked, but cross-toolchain C++ ABI compatibility is not promised.
