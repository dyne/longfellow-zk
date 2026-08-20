# BlindZap Product Strategy

## Status

Working product strategy for an experimental privacy-preserving Bitcoin proof
of control. This document is non-normative: the byte-exact v1 relation,
statement encoding, validation order, and result selection rules are defined
in [the BlindZap v1 specification](docs/blindzap-v1.md).  If this strategy and
that specification disagree, the specification controls.

BlindZap v1 exposes the claimed outpoints and amounts. It is off-chain and
supports native P2WPKH outputs only; it does not support P2SH-wrapped P2WPKH,
P2WSH, multisig, or P2TR.

## Executive summary

BlindZap lets a holder prove control of one or more P2WPKH Bitcoin outputs
without revealing the public keys hidden behind those outputs and without
creating reusable Bitcoin signatures.

The initial product is off-chain. It does not spend, lock, or transfer bitcoin,
and it requires no Bitcoin consensus change. An auditor or application:

1. issues a fresh, purpose-bound challenge;
2. receives a BlindZap proof for up to sixteen specified P2WPKH outpoints
   controlled by at most two distinct keys in v1;
3. verifies the zero-knowledge proof; and
4. independently checks that the outpoints are unspent at the declared Bitcoin
   snapshot.

The resulting claim is:

> At the stated Bitcoin snapshot, the prover demonstrated knowledge of the
> private keys controlling these P2WPKH outputs without revealing their public
> keys.

The primary use cases are private proof of funds and proof of reserves. A
secondary use case is private claim authorization for bridges and sidechains,
where BlindZap complements—but never replaces—an enforceable Bitcoin lock.

## Problem

A P2WPKH output contains a 20-byte commitment:

```text
HASH160(compressed_public_key)
```

Conventional proof of control satisfies the output as though it were being
spent. This normally discloses the compressed public key and an ECDSA
signature. The disclosure is undesirable when the output is still untouched:

- it permanently removes the public-key privacy provided by P2WPKH;
- it creates additional identifying material that can be correlated between
  services and audits;
- it exposes a secp256k1 public key that was previously protected by a hash;
- it encourages custodians to publish reserve wallet structure; and
- it produces signatures that require careful domain and replay handling.

Existing proof-of-reserves systems often protect customer liabilities with
Merkle trees or zero-knowledge proofs while proving control of assets through
public wallet addresses and ordinary signatures. BlindZap targets this
asset-side privacy gap.

## Product thesis

Proof of key control and proof of current UTXO status are separate claims.

BlindZap proves the first:

```text
I know x and P such that:
    P = xG
    HASH160(compressed(P)) = the P2WPKH witness program
```

A Bitcoin node or trusted snapshot proves the second:

```text
The referenced outpoint exists and is unspent at block B.
```

Combining both checks produces a useful snapshot attestation without revealing
`P` or `x`.

## Guarantees and non-guarantees

### BlindZap can establish

- knowledge of the secret key corresponding to a P2WPKH commitment;
- binding of that proof to a fresh verifier challenge;
- binding to an entity, purpose, network, and protocol version;
- binding to explicit outpoints and a Bitcoin snapshot;
- control of up to sixteen claimed outputs backed by at most two distinct
  P2WPKH programs in a v1 proof.

### BlindZap does not establish by itself

- that an outpoint is currently unspent;
- that the listed UTXOs are the prover's complete holdings;
- that the prover will retain control after producing the proof;
- that keys were not temporarily borrowed or jointly controlled;
- that assets exceed complete liabilities;
- that bitcoin has been locked for a bridge;
- exclusive ownership of a key; or
- control of P2SH-wrapped P2WPKH, P2WSH, multisig, or P2TR policies.

## Verification result model

The product must never collapse cryptographic proof validity and chain state
into one ambiguous boolean.

| Proof | UTXO state at requested snapshot | Result |
| --- | --- | --- |
| Valid | Unspent | Current control accepted |
| Valid | Spent after the snapshot | Valid historical snapshot; not current reserves |
| Valid | Already spent at the snapshot | Reject the reserve/control claim |
| Invalid | Any | Reject |
| Valid | State unavailable | Cryptographically valid, chain state inconclusive |

A proof remains mathematically valid after its referenced output is spent. It
becomes a historical proof rather than proof of current reserves. Applications
requiring continuous assurance must monitor the UTXO set or request fresh
proofs periodically.

## Core statement

### Public statement

```text
protocol_version
circuit_id
bitcoin_network
optional_snapshot_block_hash
optional_snapshot_block_height
verifier_challenge
verifier_or_entity_id
purpose
claims[]:
    outpoint
    amount
    P2WPKH witness program
```

For bridge authorization, the public statement additionally contains:

```text
destination_network
destination_commitment
deposit_or_lock_identifier
```

### Private witness

For the v1 claim:

```text
secret scalar x
public point P
compressed-key parity
elliptic-curve witness data
HASH160 witness data
```

### Required relation

For every claim, prove:

```text
1 <= x < secp256k1_order
P = xG
P is finite and on secp256k1
compressed_P = (0x02 or 0x03) || x_coordinate(P)
prefix parity matches y_coordinate(P)
HASH160(compressed_P) = claimed P2WPKH witness program
```

The complete proof must be bound to the full public statement, including the
snapshot, verifier challenge, purpose, and destination commitment when used.

## Priority use cases

### 1. Private proof of control

An exchange, custodian, fund, OTC desk, lender, or auditor asks a holder to
prove control of specified P2WPKH UTXOs. BlindZap replaces ordinary address
signatures with a zero-knowledge proof.

Functional value:

- untouched public keys remain hidden;
- one verifier-specific proof cannot be presented as a proof issued for a
  different entity or purpose;
- a proof can cover multiple UTXOs;
- the verifier can reproduce the chain-state check independently; and
- the proof format can be made deterministic and machine-verifiable.

This use case requires no Bitcoin protocol change.

### 2. Private proof of funds

A holder demonstrates control of an explicit set of UTXOs and optionally a
minimum total value. The verifier checks each outpoint against a Bitcoin node
at the declared snapshot.

This can support:

- OTC settlement qualification;
- credit or counterparty assessments;
- fund and treasury attestations;
- non-custodial account tiering;
- collateral monitoring; and
- private membership or eligibility based on BTC holdings.

The proof is a snapshot, not a lock. It is insufficient as enforceable
collateral unless the bitcoin is placed under a separate spending restriction.

### 3. Exchange proof of reserves

BlindZap can be the asset-control component of a solvency report:

```text
BlindZap-controlled assets
        +
complete liabilities commitment and proof
        =>
assets >= liabilities at snapshot B
```

BlindZap does not solve liabilities. A complete product must combine it with a
liability system that provides customer inclusion, prevents negative-account
manipulation, and commits to the complete liability set.

Initial reserve reports should disclose claimed outpoints so independent
verifiers can check amounts and UTXO status. Hiding the outpoints themselves is
out of scope until there is an authenticated and efficiently provable Bitcoin
UTXO-set commitment.

### 4. Bridge and sidechain claim authorization

BlindZap can privately bind a Bitcoin-side claimant to a sidechain destination:

```text
Bitcoin deposit/lock
    + confirmation or SPV validation
    + BlindZap destination-bound authorization
    => mint or claim on destination network
```

It must not be used as the sole basis for minting a BTC-backed asset. Proof of
control over an ordinary UTXO does not prevent the prover from spending that
UTXO elsewhere. A safe bridge must first establish an enforceable lock or
custody condition and must enforce one-time minting.

Potential bridge functions include:

- privately mapping a confirmed Bitcoin deposit to a destination account;
- authorizing a claim without a separate public ownership signature;
- binding a claim to a chain ID, asset ID, amount, and deposit outpoint;
- preventing proof replay across bridges or destination networks; and
- proving reserve-wallet control to bridge users without revealing previously
  hidden P2WPKH public keys.

BlindZap does not replace federation, threshold-custody, SPV, finality, fraud
proof, or peg-out security mechanisms.

## Relationship with BIP-322

[BIP-322](https://bips.dev/322/) defines generic signed messages and a Proof of
Funds variant for arbitrary UTXO sets. It provides an important interoperability
model:

- a domain-separated message challenge;
- support for simple, full, and Proof-of-Funds encodings;
- use of PSBT and ordinary Bitcoin script satisfaction;
- explicit UTXO lists; and
- an external UTXO-set check for current unspent status.

BlindZap should initially be described as a privacy-preserving companion or
experimental extension to BIP-322, not as a compliant BIP-322 signature. A
BlindZap proof does not contain a Bitcoin-valid P2WPKH witness and therefore
cannot be processed by an unmodified BIP-322 script verifier.

### Proposed integration direction

Define a namespaced, versioned experimental envelope:

```text
blindzap-pof-v1 {
    network
    circuit_id
    optional_snapshot_block_hash
    optional_snapshot_block_height
    message
    verifier_challenge
    claims[] {
        outpoint
        amount
        script_pubkey
    }
    proof
}
```

The signed-message digest should reuse BIP-322's domain-separated message
construction where appropriate, while adding BlindZap-specific domain
separation over the entire envelope. The encoding must be deterministic.

The verifier pipeline becomes:

```text
decode and canonicalize envelope
verify circuit ID and supported protocol version
reconstruct the public statement
verify BlindZap proof
query Bitcoin node or snapshot for every outpoint
verify script, value, network, block and unspent status
produce structured result
```

### Compatibility goals

- Reuse BIP-322 terminology and Proof-of-Funds workflow.
- Support the same verifier challenge/message at the user-interface level.
- Return the normative structured result enum rather than an ambiguous success
  boolean.
- Permit wallets and hardware signers to identify the request as a proof of
  control rather than a transaction signature.
- Avoid implying that a BlindZap proof can be broadcast as a Bitcoin spend.
- Keep the experimental format namespaced until there is interoperability and
  external review.

## Comparison with systems in use today

| System | Asset-control mechanism | BlindZap contribution |
| --- | --- | --- |
| Legacy message signing | ECDSA signature over a challenge | Hide the public key and use an explicit UTXO statement |
| BIP-322 Proof of Funds | Satisfy claimed UTXOs in a non-broadcast transaction/PSBT | Replace disclosed P2WPKH witnesses with a ZK proof |
| BIP-127 Proof of Reserves | Intentionally invalid transaction with signed reserve inputs | Improve privacy of the asset-control portion |
| Exchange PoR | Public address signatures plus Merkle/ZK liability reports | Prove control without publishing previously hidden public keys |
| Federated Bitcoin bridge | BTC lock controlled by federation or threshold wallet | Private claimant/destination authorization after a real lock |
| SPV sidechain peg | Bitcoin inclusion and confirmation proof | Add private ownership or claim binding, not backing or finality |

Relevant standards and deployed patterns:

- [BIP-322 Generic Signed Message Format](https://bips.dev/322/)
- [BIP-127 Simple Proof-of-Reserves Transactions](https://bips.dev/127/)
- [Kraken Proof of Reserves](https://www.kraken.com/proof-of-reserves)
- [OKX Proof of Reserves](https://www.okx.com/proof-of-reserves)
- [Liquid peg-in and peg-out](https://docs.liquid.net/docs/advanced-pegin-pegout)
- [tBTC bridge documentation](https://docs.threshold.network/tbtc-v2)

## Target users

### Primary

- exchanges and custodians with untouched P2WPKH cold-storage outputs;
- independent proof-of-reserves auditors;
- funds, treasuries, and OTC counterparties;
- wallet and hardware-signing vendors; and
- Bitcoin infrastructure providers operating full nodes and UTXO indexes.

### Secondary

- bridge and sidechain developers;
- lending and collateral-monitoring systems;
- regulated service providers needing proof of asset control; and
- researchers working on post-quantum migration and privacy-preserving
  reserve attestations.

## Product surfaces

### Prover SDK

Responsibilities:

- parse and validate proof requests;
- obtain explicit wallet consent;
- resolve the requested P2WPKH keys;
- generate witnesses and proofs;
- avoid exporting private/public key material; and
- return a canonical BlindZap envelope.

### Verifier SDK

Responsibilities:

- validate envelope encoding and domain separation;
- verify the proof and circuit identifier;
- query Bitcoin chain state;
- reject stale, spent, mismatched, or duplicate claims;
- calculate accepted value totals; and
- return structured, auditable results.

### CLI

The implemented request/proof interface is:

```text
blindzap challenge create --network signet --verifier ID --purpose proof-of-funds --message TEXT --claim TXID:VOUT:SATS:PROGRAM --output request.bzr
blindzap prove --request request.bzr --output proof.bze
blindzap verify proof.bze --bitcoin-cli /absolute/path --verifier ID --purpose proof-of-funds --nonce-store FILE
blindzap inspect request.bzr
blindzap inspect proof.bze
```

### Auditor service

Responsibilities:

- create unpredictable, expiring challenges;
- pin snapshot blocks;
- retain the proof and verification transcript;
- monitor claimed outpoints after the snapshot; and
- publish signed reports with clear scope and limitations.

## Security requirements

### Domain separation and replay protection

Every proof must commit to:

- protocol name and version;
- circuit identifier;
- Bitcoin network;
- verifier or relying-party identifier;
- unpredictable challenge;
- purpose;
- snapshot block;
- complete ordered claim set; and
- expiry policy.

A proof for an auditor must not be reusable as a bridge claim, exchange proof,
or proof for another network.

### Canonical Bitcoin encoding

The relation must enforce:

- canonical scalar range;
- finite secp256k1 points;
- correct compressed SEC-key prefix and y parity;
- exactly 33 compressed-key bytes;
- exact SHA-256 and RIPEMD-160 byte ordering; and
- exact P2WPKH witness-program encoding.

### Chain-state validation

The verifier must check:

- transaction and output existence;
- output index and amount;
- exact `scriptPubKey` type and bytes;
- membership in the verifier's selected Bitcoin chain;
- unspent status at the requested snapshot;
- snapshot confirmation/finality policy; and
- duplicate outpoints within and across reports where relevant.

### Operational limitations

Reports must disclose that:

- proof of key knowledge is not proof of exclusive control;
- proof of assets is not proof of solvency;
- a snapshot becomes stale;
- address reuse may already have exposed the public key;
- outputs can be spent immediately after proof generation; and
- colluding or temporary key holders can produce valid proofs.

## Privacy model

### Hidden from the verifier

- secret scalar;
- compressed public key;
- public-key parity; and
- internal circuit witness data.

### Public in the first product

- P2WPKH outpoints;
- output amounts;
- P2WPKH script commitments;
- snapshot block;
- verifier challenge and purpose; and
- proof metadata necessary for verification.

Hiding outpoints or reserve composition is a separate research problem. It
requires a trusted UTXO snapshot or an authenticated UTXO-set commitment that
can be checked inside the proof.

## Adoption requirements

| Product mode | Bitcoin consensus change | Other requirements |
| --- | --- | --- |
| Private proof of control | None | Prover/verifier SDK and Bitcoin node access |
| Private BIP-322-style Proof of Funds | None | Experimental format and wallet integration |
| Exchange proof of reserves | None | Liability proof, audit policy, chain-state service |
| Bridge claim authorization | None on L1 for the proof | Actual BTC lock and destination-chain verification rules |
| Native BlindZap Bitcoin output | Soft fork | New witness version/opcode and consensus cost model |
| Proof-only spend of existing P2WPKH | Hard fork | Replacement of existing P2WPKH authorization rules |

The product strategy prioritizes modes requiring no Bitcoin consensus change.

## Delivery roadmap

### Phase 0: specification and independent model

- Freeze the single-UTXO statement and byte encodings.
- Define canonical request and proof envelopes.
- Build independent secp256k1 and HASH160 reference vectors.
- Specify verifier result states and snapshot semantics.
- Document threat model and non-goals.

### Phase 1: single-UTXO proof of control

- Native prover and verifier.
- Fresh-challenge workflow.
- Bitcoin Core RPC integration for UTXO checks.
- Positive, negative, mutation, replay, and spent-output tests.
- Circuit/proof size and performance reports.

### Phase 2: experimental BIP-322 integration

- `blindzap-pof-v1` envelope.
- BIP-322-compatible message/challenge user experience.
- Multiple verifier implementations.
- Wallet and hardware-signer proof-request UX.
- Interoperability test vectors.

### Phase 3: multi-UTXO proof of reserves

- Aggregate claims and minimum-value assertions.
- Duplicate and overlap detection.
- Snapshot report generation.
- Liability-proof integration interface.
- Auditor tooling and reproducible reports.

### Phase 4: bridge authorization profile and audit

- Destination-bound claims.
- Deposit/SPV adapter interface.
- One-time claim/nullifier semantics on the destination chain.
- Bridge-specific domain separation and replay tests.
- Integration with one experimental sidechain or bridge environment.

## Success criteria

The first product is successful when:

- a standard wallet can prove control of an untouched P2WPKH UTXO without
  releasing its public key;
- an independent verifier can validate the proof and current UTXO state;
- spending the UTXO changes the verification result to historical/spent;
- proofs cannot be replayed across challenges, entities, purposes, or networks;
- two independent implementations agree on canonical test vectors;
- proof generation and verification have documented resource bounds; and
- the result is understandable to auditors without overstating what it proves.

## Positioning

BlindZap is not a private Bitcoin transaction system and not a complete
proof-of-solvency protocol. It is a privacy-preserving replacement for the
asset-side signature used to demonstrate control of hashed-key Bitcoin
outputs.

The concise product promise is:

> Prove control of P2WPKH funds at a Bitcoin snapshot without revealing the
> public keys hidden by those outputs.

## Post-v1 research

Larger key sets, hidden outpoints, liability formats, authenticated historical
snapshot providers, and bridge integrations remain deferred. Changes to the
bounded v1 circuit family or canonical wire relation require a new protocol
version and circuit identity.
