# BlindZap v1 specification

Status: normative. The product rationale is in [BLINDZAP.md](../BLINDZAP.md).
An implementation MUST follow this document exactly. BlindZap v1 is an
off-chain proof of control for a bounded set of native P2WPKH outputs. It
neither spends nor locks Bitcoin and does not change consensus. P2SH-wrapped
P2WPKH, P2WSH, multisig, and P2TR are unsupported.

## 1. Conventions and constants

`u8`, `u32`, and `u64` are unsigned integers. All multi-byte protocol integers
are big-endian, fixed-width, unsigned encodings. A byte string is lowercase
hexadecimal without `0x`. `||` concatenates bytes. Length-prefixed strings use
`u32_be(length) || UTF-8 bytes`; reserved fields MUST be absent in v1.

secp256k1 has prime field

```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
```

and subgroup order

```
n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

with generator `G` as defined by SEC 2. The private scalar is an integer `x`
with `1 <= x < n`; it is not merely a congruent field element. Let `P = xG`,
normalized to a finite affine point `(Px, Py)`. The circuit MUST constrain
`0 <= Px, Py < p` as integers before encoding. It MUST reject zero, `n`,
non-bit scalar advice, infinity, noncanonical coordinates, a point not equal
to `xG`, wrong parity, reversed bytes, and incorrect hash padding.

`Px_be` is exactly 32 big-endian bytes for `Px`. Let `parity = Py mod 2` and
`prefix = 0x02 + parity`. `SEC = prefix || Px_be` is exactly 33 bytes. Define
`inner = SHA256(SEC)` (the usual 32 output bytes in digest order) and
`program = RIPEMD160(inner)` (the usual 20 output bytes in digest order).
The required scriptPubKey is exactly `00 14 || program`, 22 bytes total.

The circuit's relation is `HASH160(SEC_compressed(xG)) = program`. The final
proof keeps `x`, `P`, parity, the 33 SEC bytes, and `inner` private. Host-side
checks are defense in depth and MUST NOT be the only enforcement.

## 2. Circuit input layout

The Longfellow witness/public vector begins with its mandatory constant-one
slot, followed by 20 byte-shaped inputs for every distinct program. The
supported circuit family contains exactly 1 or 2 ownership relations;
the selected relation count is committed by the circuit digest. No inactive
padding relation exists. All bytes are constrained to `[0,255]`; scalar bits,
point coordinates, parity, SEC bytes, and hash intermediates stay private.

## 3. Protocol statement

The canonical statement is the concatenation below. Its digest is
`SHA256("BlindZap/v1/statement" || statement_bytes)`, where the tag is literal
ASCII bytes without a terminator. Every value is public and bound by the
Fiat-Shamir transcript together with the circuit digest and public inputs.

| field | encoding and v1 rule |
| --- | --- |
| protocol version | one byte, exactly `01` |
| circuit digest | 32 bytes |
| network | one byte: `00` mainnet, `01` testnet, `02` signet, `03` regtest |
| snapshot block hash | 32 bytes in displayed Bitcoin hash byte order |
| snapshot height | `u32_be` |
| verifier nonce | exactly 32 nonzero bytes |
| verifier/entity ID | length-prefixed UTF-8, 1..256 bytes |
| purpose | length-prefixed UTF-8, exactly `proof-of-control` or `proof-of-funds` |
| issue time | `u64_be`, Unix seconds |
| expiry time | `u64_be`, strictly greater than issue time |
| claim count | `u16_be`, 1 through 16 |
| outpoint txid | 32 bytes in Bitcoin RPC/display byte order |
| outpoint vout | `u32_be` |
| amount | `u64_be`, 1..2,100,000,000,000,000 satoshis |
| scriptPubKey | one-byte length (`16`) followed by exactly `00 14 || program` |

Claims are sorted strictly by `(txid, vout)` and duplicate outpoints are
rejected. Distinct 20-byte programs are sorted lexicographically and derived
again by the verifier from the public claims; each claim maps to exactly one
such relation. More than two distinct programs is rejected before circuit
allocation. A statement may carry an optional bridge binding containing a
destination network, 32-byte destination commitment, UTF-8 asset ID, and
32-byte lock identifier. These fields and the statement nonce are transcript
bound; they do not establish that the Bitcoin output is locked.

| malformed or boundary input | required result |
| --- | --- |
| empty or all-zero nonce | `malformed_statement` |
| duplicate outpoint or noncanonical claim order | `malformed_statement` |
| unsupported network or version | `unsupported` |
| zero claims, more than 16 claims, or more than 2 distinct programs | `malformed_statement` |
| expiry at or before issue time | `malformed_statement` |
| amount zero, overflow, or above the Bitcoin monetary maximum | `malformed_statement` |
| script length other than 22, or bytes other than `00 14 || program` | `malformed_statement` |
| malformed bridge destination, asset, or lock identifier | `malformed_statement` |

BlindZap's BIP-322 companion is named `blindzap-pof-v1`. It reuses the
`BIP0322-signed-message` tagged message digest and Proof-of-Funds workflow for
the human/message layer, then domain-separates this statement and proof. It is
not a BIP-322 signature: an unmodified BIP-322 script verifier MUST NOT be
expected to accept it.

## 4. Verification and result selection

The verifier returns exactly one enum, never a success boolean:
`invalid_proof`, `malformed_statement`, `unsupported`, `state_inconclusive`,
`spent_at_snapshot`, `stale_snapshot`, `bridge_rejected`, `valid_historical`,
or `valid_current`.

Validation is ordered:

1. Parse bounded fields and require canonical encoding; failure is
   `malformed_statement`.
2. Check version, circuit digest, network, purpose, and reserved fields;
   failure is `unsupported`.
3. Verify statement/transcript binding and the ZK proof; failure is
   `invalid_proof`.
4. Enforce verifier ID, nonce freshness, purpose, and issue/expiry policy;
   failure is `invalid_proof`.
5. Check named chain snapshot and exact outpoint script/amount. Missing,
   unavailable, inconsistent, or unauthenticated historical evidence is
   `state_inconclusive`.
6. Evidence of spending at the snapshot is `spent_at_snapshot`; an output
   unspent then but spent later is `valid_historical`.
7. Sum exact chain-checked satoshi values with checked `uint64_t` arithmetic
   and apply an optional public minimum threshold.
8. A bridge statement additionally requires an independent lock/custody and
   one-time-mint callback; missing or failed evidence is `bridge_rejected`.
9. A freshness/finality policy failure is `stale_snapshot`; a currently
   unspent exact match is `valid_current`.

An earlier step wins. In particular, malformed input is never sent to a chain
provider and an invalid proof cannot become a chain-state result. The circuit
proves no UTXO existence or unspentness.

## 5. Independent vector provenance

`test/blindzap/testdata/blindzap_vectors.json` is generated by the
dependency-free `scripts/generate_blindzap_vectors.py`, using Python integer
arithmetic and `hashlib.sha256`/`hashlib.new("ripemd160")`, never circuit code.
Regenerate and compare with:

```
python3 scripts/generate_blindzap_vectors.py | cmp -s - test/blindzap/testdata/blindzap_vectors.json
```

Scalar 1's compressed key is
`0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`; scalar
`n-1` is the same X coordinate with `03` prefix. These are the documented
secp256k1 generator and its negation. As an independent local cross-check,
OpenSSL 3.5.6 (7 Apr 2026) produced scalar 1's uncompressed generator from
the SEC1 DER private-key bytes with:

```
printf '%s' '302e02010104200000000000000000000000000000000000000000000000000000000000000001a00706052b8104000a' | xxd -r -p | openssl ec -inform DER -text -noout
```

The resulting X and Y match vector 1; negating that Y modulo `p` matches the
`n-1` vector. The corpus also includes deterministic scalar 153 (leading-zero
X coordinate) and scalar 382 (leading-zero SHA-256 digest). It records
Python/hashlib provenance.

## 6. Required malformed and boundary corpus

Implementations MUST test empty nonce, duplicate outpoint, unsupported
network/version, zero/excess claims, expiry before issue, amount overflow,
wrong script length/opcodes, and destination fields on a non-bridge purpose.
They MUST also reject the scalar and coordinate cases listed in section 1.
