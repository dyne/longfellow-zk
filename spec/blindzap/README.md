# BlindZap Sage reference model

`blindzap_reference.sage` is an executable mathematical oracle for BlindZap
v1. It is intentionally independent of the production C++ circuit and is not
linked into any release binary.

## What it checks

The model uses Sage's `GF(p)` and elliptic-curve implementation to check:

- primality of the secp256k1 base-field modulus `p` and subgroup order `n`;
- generator membership, `nG = infinity`, and `(n - 1)G = -G`;
- the canonical scalar interval `1 <= x < n`;
- compressed SEC creation, decompression, parity, curve membership, and
  canonical x-coordinate bounds;
- fixed 33-byte SEC SHA-256 and HASH160 results;
- SHA-256 and RIPEMD-160 padding and byte order using local compression
  implementations rather than OpenSSL or `hashlib`;
- canonical BlindZap statement encoding and tagged hashing; and
- transcript binding to the statement digest, circuit digest, circuit version,
  Ligero rate, and query count.

It generates positive scalar vectors for `1`, `2`, `3`, leading-zero edge
cases `153` and `382`, and `n - 1`. Negative data covers `-1`, `0`, `n`,
`n + 1`, unsupported SEC prefixes, `x = p`, and a non-curve compressed SEC.

## Reproducible execution

From the repository root:

```sh
make blindzap-sage-test
```

If Sage 10.6 is installed, the runner uses the local `sage` executable. Set
`BLINDZAP_SAGE_BIN` to an explicit Sage 10.6 path when required. Other local
versions are not used; the runner instead selects the official SageMath 10.6
container pinned by OCI digest. The container runs with no network, a
read-only root filesystem and repository mount, and a bounded temporary
filesystem. Its image is pinned for `linux/amd64`; non-amd64 hosts need Docker
architecture emulation or a native Sage 10.6 installation.

The gate requires exact equality with
`test/blindzap/testdata/blindzap_sage_vectors.json` and compares all shared
curve, statement, and HASH160 values with the independently generated
`blindzap_vectors.json` fixture.

To inspect a freshly generated corpus with an installed Sage:

```sh
sage -python spec/blindzap/blindzap_reference.sage --emit
```

Fixture updates must be reviewed as cryptographic changes. Do not overwrite a
fixture merely to make a changed model pass; inspect the semantic difference,
compare it with an external Bitcoin implementation, and run the C++ circuit
mutation and real-proof gates.

## Assurance boundary

Agreement between Sage, Python, and C++ provides strong differential evidence
for the intended mathematical relation. It does not prove that the arithmetic
circuit contains every intended constraint. In particular, this model cannot
detect an unconstrained C++ witness wire when valid native calculations still
produce the expected output, nor can it prove Longfellow soundness, parser/RPC
safety, replay-store correctness, or Bitcoin chain state.

Keep the Sage oracle alongside:

1. C++ positive and adversarial witness mutation tests;
2. deterministic circuit serialization and identity checks;
3. sanitizer and static-analysis gates;
4. real one-key and maximum two-key proofs; and
5. independent cryptographic, circuit, protocol, and operational review.
