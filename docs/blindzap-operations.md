# BlindZap v1 operator and review guide

BlindZap is an off-chain proof of control for native P2WPKH outputs.  It does
not spend bitcoin, reserve a UTXO, prove liabilities, or constitute a standard
BIP-322 signature.  In particular, an unmodified BIP-322 script verifier does
not verify a `blindzap-pof-v1` envelope.

## Minimal native workflow

Build and run the deterministic checks from the repository root:

```
make posix
make blindzap-spec-test blindzap-protocol-test blindzap-integration-test
make blindzap-cli
./blindzap challenge create --network regtest --purpose proof-of-funds
```

For proof creation, provide one 32-byte hexadecimal secret on standard input;
the CLI deliberately rejects `--secret` arguments.  A caller supplies an
explicit 32-byte snapshot hash and keeps the resulting envelope only as long
as its operational policy permits:

```
printf '%064x\n' 1 | ./blindzap prove --network regtest --purpose proof-of-funds \
  --snapshot 0000000000000000000000000000000000000000000000000000000000000000 \
  --output proof.bze
./blindzap inspect proof.bze
./blindzap verify proof.bze --bitcoin-cli /usr/bin/bitcoin-cli
```

The final command requires a correctly configured Bitcoin Core node for the
selected network.  `--bitcoin-cli` is an explicit executable path (the
adapter uses `execv`, not PATH lookup); use a wrapper with an absolute path if
you need fixed arguments such as `-regtest`.  For a regtest fixture, start
Bitcoin Core with `-regtest`, create and confirm the relevant native P2WPKH
output, and pass that wrapper path.  Treat `valid_historical` as evidence at
the named snapshot only, and treat `state_inconclusive`, `stale_snapshot`, or
`spent_at_snapshot` as non-authorization results.

## Required operating policy

- Issue a high-entropy nonce for each verifier/purpose request, persist it,
  and atomically consume it only after a valid proof and policy check.
- Set a bounded expiry/staleness policy and retain the snapshot identifier,
  provider response, envelope, verifier decision, and software/circuit digest
  for audit.  Never reuse a nonce after a failed or interrupted workflow.
- The public statement reveals outpoints and amounts.  It therefore reveals
  reserve composition; a later spend makes a proof historical rather than
  current.
- Independently choose and monitor the Bitcoin provider, confirmation and
  reorg policy.  Proof validity never establishes UTXO existence/unspentness.
- A bridge additionally needs an independently enforced Bitcoin lock/custody
  rule, destination-chain finality, and one-time mint/nullifier policy.

## Deliberately unsupported in v1

P2SH-wrapped P2WPKH, P2WSH, multisig, P2TR, generic script verification,
unbounded batches, confidential outpoints/amounts, Bitcoin consensus changes,
proof of liabilities/solvency, standard BIP-322 verification, and bridge lock
or mint enforcement are outside v1.

## External-review checklist

1. Rebuild from a clean native tree and reproduce the spec vectors, circuit
   digests, proof metrics, and full BlindZap/BIP-340 test suite.
2. Trace every product claim through [the security matrix](blindzap-security.md)
   to a circuit constraint, verifier check, test, or explicitly external
   assumption.
3. Review scalar/point/SEC/SHA/RIPEMD constraints, public input ordering,
   Fiat-Shamir transcript binding, parser bounds, proof parameter identity,
   replay storage, and all result-code precedence.
4. Assess proof-system/parameter assumptions, chain-provider and snapshot
   trust, nonce-store atomicity, operational logs, and bridge lock/mint logic
   independently.  This repository has not received an independent security
   audit.
