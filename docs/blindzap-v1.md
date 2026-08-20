# BlindZap v1 specification

Status: normative draft. An implementation claiming BlindZap v1 compatibility
MUST follow this document exactly. The format remains experimental until an
independent cryptographic and protocol audit is complete.

BlindZap v1 is an off-chain proof of control for a bounded set of native P2WPKH
outputs. It neither spends nor locks Bitcoin. P2SH-wrapped P2WPKH, P2WSH,
multisig, P2TR, and arbitrary scripts are unsupported.

## 1. Conventions and constants

All multi-byte protocol integers are fixed-width unsigned big-endian values.
`u8`, `u16`, `u32`, and `u64` name their widths. Hex strings in this document
are lowercase and omit `0x`. `||` concatenates bytes.

secp256k1 uses prime field

```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
```

and subgroup order

```
n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

The private scalar is an integer `x` with `1 <= x < n`. Let `P = xG`, normalized
to a finite affine point `(Px, Py)`. `Px_be` is exactly 32 big-endian bytes.
`SEC = (0x02 + (Py mod 2)) || Px_be`. The public witness program is

```
program = RIPEMD160(SHA256(SEC))
```

and the only accepted script is `00 14 || program` (22 bytes). The circuit MUST
constrain scalar range/bitness, `P = xG`, finiteness, curve membership,
canonical coordinates, compressed-key parity and byte order, both hash
functions, fixed padding, and equality with the public 20-byte program.

## 2. Network identifiers

Network IDs are protocol values, not Bitcoin magic bytes. Values assigned by
the initial v1 draft are retained; testnet4 is appended.

| ID | BlindZap name | Bitcoin Core `chain` |
| --- | --- | --- |
| `00` | `mainnet` | `main` |
| `01` | `testnet3` (`testnet` CLI alias) | `test` |
| `02` | `signet` | `signet` |
| `03` | `regtest` | `regtest` |
| `04` | `testnet4` | `testnet4` |

Other values are unsupported. Implementations MUST compare the node-reported
`chain` value with the statement network before accepting chain evidence.

## 3. Circuit input layout and identity

The Longfellow public vector begins with its mandatory constant-one slot,
followed by 20 byte-shaped inputs for each distinct program. Programs are
sorted lexicographically and unique. The circuit family contains exactly one
or two ownership relations; no inactive padding relation exists.

The circuit digest is SHA-256 over the exact Longfellow circuit serialization
followed by three little-endian `u64` values: circuit version, proof rate, and
query count. v1 fixes these to circuit version `1`, rate `4`, and `128` queries.

## 4. Canonical statement encoding

The statement starts with ASCII `BZP1`, then:

| Field | Encoding and rule |
| --- | --- |
| statement version | `u8`, exactly `01` |
| network | `u8`, section 2 |
| verifier/entity ID | `u16(length) || UTF-8`, 1..256 bytes |
| purpose | `u16(length) || UTF-8`, one of `proof-of-control`, `proof-of-funds`, `bridge-authorization` |
| verifier nonce | exactly 32 bytes, not all zero |
| BIP-322 message hash | exactly 32 bytes, not all zero |
| not-before | `u64` Unix seconds |
| expiry | `u64` Unix seconds, strictly greater than not-before |
| snapshot present | `u8`, `00` or `01` |
| snapshot | when present: 32-byte displayed block hash followed by `u32` height; hash is not all zero |
| bridge binding present | `u8`, `00` or `01` |
| bridge binding | section 5, only when present |
| claim count | `u16`, 1..16 |
| claims | section 4.1 |

Every string MUST be shortest-form valid UTF-8. C0 control characters
(U+0000 through U+001F) and U+007F are forbidden.

The complete statement MUST be at most 4096 bytes. A statement without a
snapshot MUST encode neither hash nor height; its in-memory hash and height are
zero. Current-tip providers MUST reject snapshot requests, and historical
providers MUST authenticate the exact hash and height.

The statement digest is the BIP-340-style tagged hash

```
TaggedHash("BlindZap/statement/v1", canonical_statement_bytes)
```

where `TaggedHash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`.

### 4.1 Claim encoding

Each claim is:

| Field | Encoding and rule |
| --- | --- |
| txid | 32 bytes in Bitcoin RPC/display order, not all zero |
| vout | `u32` |
| amount | `u64`, 1..2,100,000,000,000,000 satoshis |
| program | exactly 20 bytes |

Claims are sorted strictly by `(txid, vout)`; duplicates are malformed. The
script is not redundantly serialized: verifiers reconstruct exactly
`00 14 || program` and require the chain output to equal it. More than two
distinct programs is malformed. The checked aggregate claim value MUST NOT
exceed 2,100,000,000,000,000 satoshis.

## 5. Optional bridge binding

A bridge binding is permitted only for purpose `bridge-authorization` and is:

```
destination_network:u8
destination_commitment:32 bytes, not all zero
asset_id:u16(length) || UTF-8, 1..256 bytes
lock_id:32 bytes, not all zero
```

`bridge-authorization` without this binding is malformed. The binding does not
prove a lock; successful verification additionally requires an independent,
atomic lock/custody and one-time-mint policy callback.

## 6. Envelope and transcript

The proof envelope starts with ASCII `BZE1`, then:

```
envelope_version:u8 = 01
statement_size:u32
statement_bytes
circuit_digest:32 bytes
circuit_version:u32 = 1
rate:u32 = 4
queries:u32 = 128
proof_size:u32
proof_bytes
```

`statement_size` is 1..4096. `proof_size` is 1..128 MiB and MUST equal the
remaining envelope length. The circuit digest MUST NOT be all zero. The entire envelope is bounded before any nested
allocation. Unknown envelope/statement/network/circuit versions or proof
parameters are `unsupported`; malformed lengths or fields are
`malformed_statement`.

The Fiat-Shamir seed is

```
TaggedHash(
  "BlindZap/transcript/v1",
  statement_digest || circuit_digest ||
  circuit_version:u32 || rate:u32 || queries:u32)
```

The proof therefore binds every statement byte, the exact circuit, and proof
parameters.

## 7. Verification and result selection

The verifier returns one of `invalid_proof`, `malformed_statement`,
`unsupported`, `state_inconclusive`, `spent_at_snapshot`, `stale_snapshot`,
`bridge_rejected`, `valid_historical`, or `valid_current`.

1. Enforce the outer size cap and canonical decoding.
2. Reject unsupported versions, networks, or proof parameters during decoding.
3. Enforce verifier identity, exact purpose, validity window, maximum lifetime,
   and replay precheck before expensive proof verification.
4. Reject an unsupported circuit identity, then verify the proof and transcript
   binding before querying chain state.
5. For every outpoint, verify the selected Bitcoin network, exact amount,
   exact `00 14 || program` script, and unspent state using one stable chain
   tip shared by every claim or an authenticated historical snapshot.
6. Apply confirmation/finality policy and sum amounts with checked arithmetic.
7. Apply bridge authorization when present.
8. Atomically consume the nonce only after every preceding check succeeds.

A current `gettxout` null result cannot distinguish a nonexistent output from a
spent output and is therefore `state_inconclusive` without additional evidence.
Historical providers may return `spent_at_snapshot` only when they can
authenticate existence and spending state at the named snapshot.

## 8. Required test corpus

Implementations MUST test every network mapping, unsupported IDs/versions,
empty/all-zero nonce, zero message hash, invalid UTF-8, invalid purpose,
duplicate/unsorted/zero/excess claims, more than two programs, lifetime
boundaries, snapshot consistency, bridge consistency, truncated/trailing and
oversized encodings, wrong proof parameters, exact BTC-to-satoshi boundaries,
wrong-node networks, within-lookup and cross-claim node tip races, replay
races, and circuit mutations.

`test/blindzap/testdata/blindzap_vectors.json` is generated independently by
`scripts/generate_blindzap_vectors.py`. It contains secp256k1/HASH160 vectors
and a complete canonical statement encoding/digest vector. Regenerate it with:

```
python3 scripts/generate_blindzap_vectors.py | diff -u test/blindzap/testdata/blindzap_vectors.json -
```
