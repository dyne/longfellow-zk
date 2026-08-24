---
title: Reference projects
description: mdoc, ECDSA, and BIP340 show how the Longfellow-ZK base becomes an application circuit.
---

# Reference projects

The base library owns generic algebra, circuit compilation, transcripts,
commitments, sumcheck, and proof machinery. Named projects turn those tools into
statements about particular formats or signature schemes.

| Project | Proves or packages | Curve / format | Package target |
| --- | --- | --- | --- |
| [mdoc](mdoc.md) | Signed mobile-document parsing and selective disclosure | ISO mdoc, CBOR, ECDSA P-256 | `LongfellowZKMDoc::mdoc` |
| [ECDSA](ecdsa.md) | ECDSA signature verification circuits | P-256 | `LongfellowZKECDSA::ecdsa` |
| [BIP340](bip340.md) | Schnorr verification circuits and witnesses | secp256k1 / BIP340 | `LongfellowZKBIP340::bip340` |

## Dependency direction

```text
mdoc ──────> ECDSA ──────> liblongfellow-zk
BIP340 ──────────────────> liblongfellow-zk
```

The base never includes named-project headers. This keeps application-specific
document and signature logic outside the reusable cryptographic boundary. See
the [library boundary inventory](../liblongfellow-zk-boundary.md) for the
enforced ownership rules.

## Why these three?

They cover two complementary goals. mdoc is an end-to-end identity application:
it parses a deployed document, checks its signature, and supports selective
claims. ECDSA and BIP340 are smaller cryptographic building blocks that show how
legacy and modern signature verification can live inside a private statement.
