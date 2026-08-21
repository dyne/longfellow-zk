# BlindZap v1 circuit

This directory implements the arithmetic relation behind BlindZap. It is a
single Longfellow circuit over `Fp256k1Base`, assembled from modular secp256k1,
SHA-256, and RIPEMD-160 gadgets. It is not an mdoc-style composition of two
independent proofs: intermediate values are ordinary constrained wires inside
one compiled circuit and one `ZkProof`.

## Proven relation

For each distinct public P2WPKH witness program `program`, the circuit proves
knowledge of a scalar `x` such that

```text
1 <= x < secp256k1_order
P = xG
SEC = (0x02 + parity(P.y)) || uint256_be(P.x)
program = RIPEMD160(SHA256(SEC))
```

The scalar, point, compressed SEC key, SHA trace, and SHA digest are private.
Only the 20-byte witness program is public. Bitcoin outpoints, values,
network, expiry, nonce, chain state, and bridge policy are bound by the
canonical envelope and checked outside this arithmetic circuit.

## Constraint flow

```text
public encoded program bytes
              ▲
              │ equality and byte-shape constraints
private x ──> xG ──> canonical compressed SEC ──> SHA-256 ──> RIPEMD-160
  │          │                 │                    │
  │          │                 │                    └─ private constrained digest
  │          │                 └─ private constrained coordinate bits and parity
  │          └─ finite, normalized, on-curve point
  └─ canonical, nonzero scalar
```

`BlindzapCircuitV1::assert_program` is the composition root. It plucks each
public field element into eight canonical bits, derives a compressed key with
`KeyOwnershipCircuit`, then sends that value directly into
`Hash160Circuit`. No host-computed digest is accepted as a public or private
shortcut.

### 1. Public input allocation

`BlindzapBuildCircuit<Keys>` allocates all program elements before calling
`private_input()`. Longfellow's mandatory constant-one input is followed by
exactly `20 * Keys` byte-shaped program elements:

```text
[ constant one | program_0[0..19] | program_1[0..19] ]
```

The second program exists only in the two-key family member. Programs are
sorted and deduplicated by the protocol layer before circuit selection.

### 2. Key ownership

`KeyOwnershipCircuit::derive` constrains:

- the 256 scalar-advice bits and their canonical range;
- equality between the packed scalar and scalar-multiplication advice;
- scalar nonzeroness using a constrained inverse;
- the double-and-add trace for `xG`;
- conversion from the final projective point to a finite normalized affine
  point; and
- canonical 256-bit encodings of both coordinates.

`Secp256k1Encoding::compressed` then produces the prefix parity bit and the
MSB-first x-coordinate bits used by the hashing stage. The public key is never
made public.

### 3. Fixed compressed-key SHA-256

`CompressedKeySha256Circuit::derive` constructs exactly one 64-byte SHA block
inside the circuit:

```text
SEC[33] || 0x80 || zero[28] || uint64_be(264)
```

The SEC prefix and x-coordinate are taken directly from the ownership wires.
`FlatSHA256Circuit::assert_message` constrains the one-block round witness,
padding, and length. The adapter unpacks the constrained final `H1` words into
a private 256-bit digest; it does not depend on a fork-specific SHA API or
allocate a separate digest input.

The native `CompressedKeySha256Witness` only supplies packed round advice.
Incorrect advice fails the circuit constraints.

### 4. Fixed RIPEMD-160

`Ripemd160Fixed32::derive` maps the constrained SHA digest into RIPEMD-160's
single padded block:

```text
SHA256_digest[32] || 0x80 || zero[23] || uint64_le(256)
```

The adapter explicitly reconciles FlatSHA's field-integer bit order with the
SHA byte stream before applying RIPEMD-160. Its resulting 20 bytes are
constrained equal to the plucked public program bytes.

## One- and two-key circuit family

BlindZap v1 compiles two exact circuit shapes:

| Distinct keys | Public inputs | Private inputs | Total inputs | Quadratic terms | Serialized circuit |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 21 | 3,010 | 3,031 | 2,067,522 | 24,876,346 B |
| 2 | 41 | 6,020 | 6,061 | 4,133,092 | 49,663,186 B |

There is no inactive padded relation. A statement with several claims that
share one program uses the one-key member; two distinct programs use the
two-key member; three distinct programs are rejected before circuit
allocation. This makes unused-witness semantics unambiguous and gives each
shape a distinct circuit identity.

The serialized circuit bytes, circuit version `1`, Ligero rate `4`, and `128`
queries are hashed into the proof identity. Verification selects the family
member from the canonical distinct-program count and rejects an identity or
parameter mismatch before accepting the proof.

## Witness construction is not a trust boundary

`BlindzapWitnessV1` computes native advice for performance:

- scalar and inverse;
- scalar-multiplication trace and affine normalization values;
- canonical coordinate bits;
- packed SHA-256 round values; and
- the expected HASH160 program used to match secrets to sorted programs.

This native computation does not replace constraints. The arithmetic circuit
independently checks the scalar, point, encoding, SHA trace, RIPEMD computation,
and public equality. Mutating public bytes, intermediate witnesses, circuit
identity, or serialized proof is covered by negative tests.

## Files

- `blindzap_circuit.h`: composition root and one/two-key family.
- `key_ownership.h`: scalar validity, `xG`, affine normalization, and canonical
  compressed-key derivation.
- `compressed_key_sha256.h`: fixed 33-byte SEC SHA-256 adapter.
- `hash160.h`: direct SHA-to-RIPEMD wire composition and public equality.
- `blindzap_witness.h`: validated native witness construction and filling.
- `key_ownership_witness.h`: scalar multiplication and coordinate advice.
- `compressed_key_sha256_witness.h`: one-block SHA round advice.

## Validation

Run the focused gates from the repository root:

```sh
make blindzap-key-ownership-test
make blindzap-sha256-test
make blindzap-ripemd160-test
make blindzap-proof-test
```

The full proof gate exercises both circuit-family members with real proofs,
checks deterministic circuit serialization and identity, accepts valid scalar
boundary cases, and rejects altered public inputs and tampered proof bytes.
See [the integration README](../../blindzap/README.md) and
[security claim matrix](../../../docs/blindzap-security.md) for protocol and
operational boundaries.
