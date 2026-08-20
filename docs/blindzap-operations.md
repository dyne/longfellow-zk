# BlindZap operations

BlindZap is experimental and MUST NOT authorize production funds or minting
until an independent cryptographic/protocol audit is complete. The controls
below are mandatory for production-oriented testing.

## Build and quick verification

```
make blindzap-ci-test
```

The high-memory proof gate is separate:

```
make blindzap-proof-test
```

## Supported Bitcoin networks

The CLI accepts `mainnet`, `testnet3` (or alias `testnet`), `testnet4`, `signet`,
and `regtest`. Prefer signet for public integration testing and regtest for
deterministic local tests. The verifier compares the proof network with Bitcoin
Core's `getblockchaininfo.chain`; a mismatch is never accepted as evidence. It
also invokes `bitcoin-cli` with the corresponding explicit selector
(`-testnet`, `-testnet4`, `-signet`, or `-regtest`) so the ambient Core default
cannot silently select another chain.

## Challenge → proof → verification

The verifier creates a short-lived canonical request. Every `--claim` is
`TXID:VOUT:SATOSHIS:PROGRAM`, where `PROGRAM` is the 40-hex-character P2WPKH
witness program (the bytes after `0014`). Requests and proofs are created with
mode `0600` and existing destinations are not overwritten.

```
./blindzap challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message '2026-Q3 reserve attestation' \
  --expires-in 300 \
  --claim TXID:0:100000:PROGRAM \
  --output request.bzr
```

The prover reviews the request, then supplies one 32-byte hexadecimal secret
per distinct program. Interactive terminal input has echo disabled; automation
should provide secrets through a protected pipe, never argv or shell history.

```
./blindzap inspect request.bzr
./blindzap prove --request request.bzr --output proof.bze
```

The verifier supplies its expected identity and purpose rather than trusting
those values from the proof. `--bitcoin-cli` MUST be an absolute executable
path. The nonce store is owner-only, locked, atomically checked/appended, and
fsynced before authorization succeeds.

```
./blindzap verify proof.bze \
  --bitcoin-cli /usr/bin/bitcoin-cli \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --nonce-store ./consumed-nonces \
  --min-confirmations 6 \
  --minimum-total-sats 100000 \
  --max-lifetime 300
```

The bundled Bitcoin Core provider verifies only a stable current tip. Snapshot
statements require a separately configured authenticated historical provider
through the library API; the CLI does not claim historical support.

## Bitcoin Core configuration

Use a dedicated least-privilege RPC configuration and a fully validated node on
the expected network. The provider:

- executes an absolute argv vector without a shell;
- separates stdout and stderr;
- caps each stream at 1 MiB and kills the process group on limit/timeout;
- validates structured JSON and the exact node `chain` value;
- converts the original decimal BTC token to satoshis without floating point;
- requires `gettxout.bestblock` and two surrounding chain-tip observations to
  agree; and
- treats a null `gettxout` result as inconclusive, not proof of spending.

If RPC authentication needs wrapper arguments, create a fixed, audited wrapper
with no user-controlled shell expansion and pass its absolute path.

## Production controls

- Generate verifier nonces with the operating-system CSPRNG and never reuse
  them, including after failed or interrupted workflows.
- Keep lifetimes short. The CLI caps them at 24 hours; deployments should
  normally use minutes.
- Persist the request, proof, verification result, node identity, chain tip,
  software/circuit digest, and policy version in an append-only audit log.
- Protect proof parsing and verification with process memory/CPU quotas. A
  valid proof is intentionally large and expensive.
- Monitor claimed outpoints after verification. Proof of key knowledge is not a
  lock, exclusive ownership proof, or solvency proof.
- Require independent bridge lock/custody evidence and atomic one-time minting;
  a BlindZap proof alone never authorizes issuance.
- Treat `state_inconclusive`, `stale_snapshot`, `spent_at_snapshot`,
  `bridge_rejected`, `unsupported`, and all parse/proof failures as
  non-authorization outcomes.

## Release gate

Before a production-oriented release:

1. Rebuild from a pinned clean checkout and pinned toolchain.
2. Run quick, sanitizer, static-analysis, one-key proof, and maximum two-key
   proof gates.
3. Compare canonical vectors and circuit digests across two independent builds.
4. Exercise regtest, signet, testnet3, and testnet4 node-network mismatch tests.
5. Complete independent circuit, proof-system, parser, RPC, replay-store, and
   operational audits.
6. Publish resource measurements and all residual assumptions/limitations.
