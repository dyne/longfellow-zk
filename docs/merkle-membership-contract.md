# Fixed-depth SHA-256 Merkle membership: ownership inventory

This document records the ownership boundary for the reusable membership
relation planned for `longfellow-zk`.  It is intentionally caller-neutral:
issuer authorization, credential status, leaf domains, snapshots, epochs,
validity windows, and policy remain outside this library contract.

## Native parity and ownership

The controlled European headers are byte-identical to their Google sources:

| Concern | Canonical implementation | Contract boundary |
| --- | --- | --- |
| Digest and `SHA256(left || right)` | `merkle/merkle_tree.h`: `Digest::hash2` | Existing native primitive; no replacement or circuit-local host hash. |
| Tree construction | `MerkleTree::set_leaf`, then `MerkleTree::build_tree` | Exclusive host-side construction API. |
| Single- or multi-open compressed proof generation | `MerkleTree::generate_compressed_proof` | Exclusive host-side path-generation API. |
| Compressed proof verification | `MerkleTreeVerifier::verify_compressed_proof` | Verify host-side before any adapter consumes a single-leaf proof. |
| Commitment leaf hashing and opening | `merkle/merkle_commitment.h` | Existing native commitment layer; it delegates to the four operations above. |
| SHA-256 circuit | `circuits/sha/flatsha256_circuit.h`: `FlatSHA256Circuit` | Reused by the future relation for every node hash. |
| Packed circuit inputs and bit recovery | `circuits/logic/bit_plucker.h`: `BitPlucker`; host packing in `BitPluckerEncoder` | Reused; the relation must not introduce a second packing format. |
| Constrained selection | `Logic::mux` and `Logic::assert_is_bit` | Reused for conditional child ordering. |
| Circuit allocation and SHA witness filling | `Logic::{input,vinput,eltw_input}` and `FlatSHA256Circuit::BlockWitness::input` | The future public witness helper only composes these inputs. |

`test/tooling/merkle_contract_inventory_test.py` checks both native headers
byte-for-byte, runs the same four-leaf root/proof fixture against the European
installed package and the controlled Google build, and rejects edits to either
immutable European native header or another host tree/path implementation.
It also configures an installed-package probe with `find_package(LongfellowZK
CONFIG REQUIRED)` and `ccache`.

### Exact native ordering

`Digest` is exactly 32 bytes.  `Digest::hash2(L, R)` feeds the 32 bytes of `L`
followed by the 32 bytes of `R` to SHA-256, with no node domain separator.
`MerkleTree` stores leaves at `layers_[n, 2*n)`, computes decreasing node
indices, and therefore preserves this `left || right` order even for its
heap-style tree representation.  A compressed proof is emitted while walking
those same decreasing inner-node indices; it is **not** a fixed-depth sibling
array.  Only the native verifier interprets that compressed order.

The sole missing primitive is consequently a reusable *in-circuit* verifier
for one already host-verified, fixed-depth path.  Native construction, native
compression/decompression semantics, SHA-256, packing, conditional selection,
and witness allocation already have one owner in European Longfellow.

## V1 reusable circuit contract

The production header introduced by the following implementation milestone is
to expose a fixed compile-time depth factory, conceptually:

```c++
template <class Logic, std::size_t Depth, std::size_t PluckerLog = 4>
class FixedDepthSha256MerkleMembership {
 public:
  struct Input {
    typename Logic::v256 leaf_digest;                 // constrained private
    std::array<typename Logic::v256, Depth> siblings; // constrained private
    std::array<typename Logic::BitW, Depth> direction_bits;
    typename Logic::template bitvec<Depth> index_bits;
    typename Logic::v256 expected_root;               // constrained/public by caller
    std::array<typename FlatSHA256Circuit<
        Logic, BitPlucker<Logic, PluckerLog>>::BlockWitness, 2 * Depth>
        sha_witness;
  };

  void assert_member(const Input&) const;
};
```

The spelling may follow the repository's reviewed public-header conventions,
but these fields and constraints are the V1 contract.  `leaf_digest`, every
`siblings[level]`, `direction_bits[level]`, `index_bits[level]`, SHA witness,
and `expected_root` are circuit values; the caller decides which values are
allocated as public inputs.  For every level `level`, the gadget asserts both
`direction_bits[level]` is boolean and
`direction_bits[level] == index_bits[level]`.  Index bits are little-endian by
level: bit 0 describes the leaf pair, and a one means the current digest is
the right child.  The gadget does not infer an index range, tree capacity,
epoch, or application authorization from them.

For each level, with `current` initially equal to `leaf_digest`:

```text
direction = 0: left = current, right = sibling
direction = 1: left = sibling, right = current
next = SHA-256(left || right)
```

Both selections are constrained with the existing `Logic::mux`; `next` is
constrained with the existing `FlatSHA256Circuit` and `BitPlucker`, and then
becomes `current`.  After exactly `Depth` hashes the gadget constrains
`current == expected_root`.  There is no unconstrained intermediate-digest
advice: each intermediate is the target of its own SHA constraint.

### Digest representation

An external digest is a 32-byte array in SHA-256 output order (`byte[0]` is
the first byte emitted by SHA-256).  In the existing `Logic::v256`, external
digest byte `b` is bound bit-for-bit to `v256[(31 - b) * 8 + bit]`, for
`bit = 0..7`; this is the same reverse-byte mapping used by
`FlatSHA256Circuit::assert_hash`.  A `v8` byte has its normal existing bit
indices, so the 64-byte node message binds bytes 0..31 from `left` and bytes
32..63 from `right` in that order.  Node hashing has no implicit domain tag.
Callers that require leaf or node domain separation place it in their own leaf
encoding before supplying the constrained leaf digest; V1 never inserts an
SD-JWT, issuer, status, or other application label.

### Native proof adapter boundary

V1 provides a bounded host adapter only for one leaf, and only after:

1. the caller used unchanged `MerkleTree::generate_compressed_proof`, and
2. `MerkleTreeVerifier::verify_compressed_proof` accepted that exact native
   proof, leaf, position, tree size, and root.

The adapter accepts a power-of-two `tree_size == 1 << Depth`, one selected
position, and the native compressed proof in native emission order.  It
rejects non-power-of-two sizes, size/depth disagreement, a position outside
the tree, overflow, malformed digest lengths, and any proof length other than
`Depth`; it produces `Depth` bottom-up sibling digests and the little-endian
direction/index bits defined above.  `Depth == 0` represents the single-leaf
tree and therefore requires an empty path.

Compressed multi-open proofs are deliberately outside V1.  Their shared
branches and variable proof length do not denote one fixed-depth private
path, and accepting them would require a separate compressed-proof parser and
tree/path algorithm in the circuit.  That would duplicate native ownership.

## Canonical vector schema and required cases

`test/merkle/canonical_merkle_membership_vector.schema.json` is the checked
schema shared by native, adapter, Evaluation, and compiler qualification.
Every vector contains:

| Field | Canonical form |
| --- | --- |
| `treeSize`, `depth`, `leaves`, `selectedIndex` | Non-negative sizes/indices; `treeSize == 2^depth` for V1 adapter vectors. |
| `nativeCompressedProof` | Ordered 32-byte digest hex strings exactly as emitted by the native API; `nativeCompressedProofBytes` is their concatenation. |
| `expandedPath` | Bottom-up sibling digests with `siblingIsLeft` direction bits. |
| `indexBitsLsbFirst` | One bit per level; equal to each `siblingIsLeft`. |
| `levels` | At each level: ordered 64-byte `leftRightPreimage` and its SHA-256 `digest`. |
| `root` | 32-byte final digest hex, equal to the last level digest or the leaf at depth zero. |

The corpus must include depth 0, depth 1, and multiple depths; leaves on both
left and right sides; native proof ordering; an adapter rejection for a
non-power-of-two tree; a no-domain-separator example; and an example whose
caller-owned leaf domain is visible before leaf hashing.  For every positive
vector, negative cases independently mutate the leaf, one sibling, one
direction/index bit, the expected root, and the declared depth identity.  The
validator rejects inconsistent preimages, intermediate digests, proof-byte
concatenation, and all of those mutations.

This schema deliberately lets an issuer-authorization caller and a credential
status caller supply different leaf encodings and policy inputs while reusing
the exact same path relation.  Neither caller imports SD-JWT types or rewrites
the SHA-256 path loop.
