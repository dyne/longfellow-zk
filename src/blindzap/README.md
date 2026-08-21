# BlindZap

BlindZap v1 proves knowledge of the private keys for one or two native
P2WPKH witness programs without revealing the keys or compressed public keys.
The proof is off-chain: verification must also authenticate the claimed
Bitcoin outputs, their amounts, network, confirmation state, and replay
policy.

BlindZap is experimental and has not completed an independent cryptographic
or protocol audit. Do not use it to authorize production funds or minting.
Use signet for public integration testing and regtest for deterministic local
testing.

## Build and test

Build the CLI and run the production-oriented test gate:

```sh
make -j"$(nproc)" blindzap
make -j"$(nproc)" blindzap-ci-test
```

The real proof test is intentionally separate because it is memory- and
CPU-intensive:

```sh
make blindzap-proof-test
```

The CLI supports `mainnet`, `testnet3` (and the `testnet` alias), `testnet4`,
`signet`, and `regtest`. It always passes the corresponding explicit network
selector to Bitcoin Core and rejects a node whose reported chain differs from
the proof statement.

## Signet walkthrough

The verifier first obtains the output's displayed transaction ID, output
index, value in satoshis, and 20-byte P2WPKH witness program. `PROGRAM` is the
40 hexadecimal characters after `0014` in the scriptPubKey.

Create a short-lived request:

```sh
./blindzap challenge create \
  --network signet \
  --verifier verifier.example \
  --purpose proof-of-funds \
  --message 'signet reserve check 2026-08-21' \
  --expires-in 300 \
  --claim TXID:VOUT:SATOSHIS:PROGRAM \
  --output request.bzr
```

Multiple `--claim` options are allowed. Claims may reference at most two
distinct witness programs; claims sharing a program require only one key
relation. Inspect the canonical request before proving:

```sh
./blindzap inspect request.bzr
./blindzap prove --request request.bzr --output proof.bze
```

`prove` reads one 32-byte hexadecimal secret from protected standard input for
each distinct program; input order does not matter because every secret is
matched to its derived program. Interactive input disables terminal echo.
Never put a secret in argv, an environment variable, or shell history. For
automation, feed it through a protected pipe whose producer does not log its
output.

Verify against a fully validated signet Bitcoin Core node:

```sh
./blindzap verify proof.bze \
  --bitcoin-cli /usr/bin/bitcoin-cli \
  --verifier verifier.example \
  --purpose proof-of-funds \
  --nonce-store ./consumed-nonces \
  --min-confirmations 1 \
  --minimum-total-sats SATOSHIS \
  --max-lifetime 300
```

The expected verifier and purpose are supplied locally, not trusted from the
proof. The nonce store is locked, owner-only, atomically updated, and synced
before authorization succeeds. Request and proof files are created with mode
`0600`; an existing output path is never overwritten.

The bundled Bitcoin Core provider verifies a stable current tip. It treats a
null `gettxout` response as inconclusive rather than as proof that an output
was spent. Historical snapshot statements require a separately implemented
authenticated historical provider through the library API.

## Library entry points

Applications can use the header-only integration layer directly:

- `BlindzapProve(...)` proves one distinct witness program.
- `BlindzapProveKeys<1|2>(...)` selects an exact circuit-family member.
- `BlindzapProofSupported(...)` checks the circuit identity and fixed proof
  parameters before proof parsing.
- `BlindzapVerifyProof(...)` verifies only the zero-knowledge relation.
- `VerifyBlindzap(...)` applies policy, proof verification, chain evidence,
  confirmation/value thresholds, optional bridge authorization, and atomic
  nonce consumption.

Production integrations should call `VerifyBlindzap`, provide an appropriate
`BlindzapChainProvider`, and fail closed for every result except
`valid_current` or an explicitly supported `valid_historical`. A valid proof
alone does not establish that an output exists, is unspent, is exclusively
controlled, is locked, or proves solvency.

## Current metrics

The following measurements were taken on 2026-08-21 at commit `315aeea812f`
on Linux x86-64, an Intel Core i9-12900HK, Debian clang 19.1.7, C++17, and the
hardened release flags (`-O3 -fstack-protector-all -D_FORTIFY_SOURCE=2
-fno-strict-overflow`). The host exposed 20 logical CPUs, but each measured
API call was single-process. Timings are wall-clock observations, not
performance requirements.

| Distinct keys | End-to-end prove API | End-to-end verify API | Raw proof | Full envelope | Serialized circuit |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 29.892 s | 19.899 s | 46,879,852 B (44.71 MiB) | 46,880,097 B | 24,876,346 B (23.72 MiB) |
| 2 | 60.200 s | 38.967 s | 91,263,372 B (87.04 MiB) | 91,263,681 B | 49,663,186 B (47.36 MiB) |

These end-to-end measurements include native witness preparation, circuit
construction, proving or verification, and proof serialization/parsing as
performed by the public API. Verification ran in the same process immediately
after proving, so its static expected-circuit-digest cache was warm; a first
verification in a fresh process also constructs that identity circuit. The
measurements are one observation per shape and should be treated as indicative.
Envelope size also varies with the canonical statement, while serialized
circuit size is deterministic.

The proof gate also records six lower-level one-key samples that exclude
circuit construction from the prove/verify intervals. On the same checkout,
proving ranged from 25.882 to 26.149 seconds (mean 25.977 seconds), verification
from 18.067 to 18.207 seconds (mean 18.152 seconds), and raw proofs from
46,878,796 to 46,879,788 bytes. Randomized commitments make small proof-size
variation expected.

Circuit structure is deterministic. Current fixed metrics are:

| Distinct keys | Public inputs | Total inputs | Private inputs | Quadratic terms | CRT block encoding |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 21 | 3,031 | 3,010 | 2,067,522 | 2,070,533 |
| 2 | 41 | 6,061 | 6,020 | 4,133,092 | 4,139,113 |

Reproduce the real one-key samples with `make blindzap-proof-test`; results are
written to `test/results/native_blindzap_metrics.csv`. Circuit and proof sizes
must be remeasured after any compiler, circuit, field, rate, query-count, or
serialization change. For release comparisons, use an otherwise idle machine,
record peak resident memory separately, and run multiple samples.

## Further documentation

- [Circuit construction](../circuits/blindzap/README.md)
- [Independent Sage reference model](../../spec/blindzap/README.md)
- [Normative v1 format](../../docs/blindzap-v1.md)
- [Operations and production controls](../../docs/blindzap-operations.md)
- [Security claim matrix](../../docs/blindzap-security.md)
- [Performance methodology](../../docs/blindzap-performance.md)
