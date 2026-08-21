# BlindZap v1 security-claim matrix

This matrix is the review map for the current BlindZap implementation.  It
separates a statement that is enforced by the arithmetic circuit from one
enforced by the envelope, verifier policy, or an external Bitcoin/bridge
system.  A successful proof is **not** by itself proof that an output exists,
is unspent, is locked, or is a proof of solvency.

The named tests are in `test/blindzap/` unless noted otherwise.  A negative
test means an expected rejection, not merely a host-side precondition.

| Claim and attacker strategy | Trusted/enforcing component | Source constraint or check | Positive / negative evidence | Residual limitation |
| --- | --- | --- | --- | --- |
| The prover knows a nonzero scalar in `[1,n-1]`; try `0`, `n`, or non-bit advice. | Arithmetic circuit and its soundness assumptions. | `Secp256k1EcGadget::assert_canonical_scalar` and `assert_nonzero_scalar`; `KeyOwnershipCircuit::derive`. | `key_ownership_test`: valid scalar; zero/order/non-bit mutations. Sage oracle: primality, group order, negation, and `-1,0,n,n+1` rejection. | Soundness depends on the proof system and field/CRT assumptions, not an independent audit. |
| The hidden point is `P=xG`, finite, and on the curve; substitute a point or infinity. | Arithmetic circuit. | `Secp256k1EcGadget::scalar_mult`, `Secp256k1Affine::assert_normalized`, and `KeyOwnershipCircuit::derive`. | `ec_gadget_test`, `key_ownership_test`: altered scalar-multiplication/point witness rejected. | The point is deliberately not a public output. |
| Coordinates and SEC encoding are canonical; use values equal only modulo `p`, a wrong prefix, parity, or byte order. | Arithmetic circuit. | `Secp256k1Encoding::assert_canonical` / `Secp256k1Encoding::compressed`; `KeyOwnershipCircuit::derive`. | `ec_gadget_test`, `key_ownership_test`: `p-1,p,p+1`, parity, prefix and reversed-byte cases. | Canonicality applies to the relation, not to arbitrary external SEC parsers. |
| The program equals `RIPEMD160(SHA256(SEC_compressed(xG)))`; alter a SEC, SHA, RIPEMD, or public-program byte. | Arithmetic circuit. | `CompressedKeySha256Circuit::derive`, `Ripemd160Fixed32::derive`, `Hash160Circuit::assert_hash160`, `BlindzapCircuitV1::assert_program`. | `compressed_key_sha256_test`, `ripemd160_test`, `blindzap_test`: byte and digest/program mutations. Sage oracle: independent curve/SEC and local hash-compression vectors cross-checked with Python. | SHA/RIPEMD design security is assumed; no digest or SEC byte is exposed by the proof. |
| A proof uses exactly the selected one- or two-claim circuit; add inactive relations or swap the circuit. | Circuit construction and proof identity check. | `BlindzapBuildCircuit`, `BlindzapMultiCircuitV1::assert_programs`, `BlindzapCircuitDigest`, `BlindzapProofIdentityMatches`, `BlindzapVerifyProof`. | `blindzap_test`: one/two-claim proof, duplicate-program and digest/version mutations. | v1 intentionally supports at most two distinct programs. |
| Public statement fields cannot be replayed across verifier, purpose, network, nonce, expiry, circuit, or proof parameters. | Canonical statement/envelope, verifier policy, and durable nonce store. | `BlindzapStatementValid`, `Encode/DecodeBlindzapStatement`, `BlindzapTranscriptSeed`, `BlindzapCheckPolicy`, `BlindzapConsumeNonce`, `BlindzapConsumeNonceFile`. | `protocol_test`: canonical round-trip and expiry/replay cases; `integration_test`: durable replay and insecure-permission rejection. | Distributed deployments must provide an equivalently atomic shared nonce store. |
| Parser inputs are bounded and canonical; use truncation, length overflow, bad UTF-8, reserved values, or trailing bytes. | Local parser implementation. | `BlindzapReader::{bytes,text,u8,u16,u32,u64}`, `DecodeBlindzapStatement`, `DecodeBlindzapEnvelope`. | `protocol_test`: statement/envelope truncation, malformed lengths/UTF-8/network/version cases. | Parser testing cannot establish absence of all implementation defects. |
| A claimed outpoint has the exact P2WPKH program and amount at the selected snapshot/current tip; race, substitute script/value/network, or report spent. | Independently selected chain provider. | `BlindzapChainProvider::Lookup`, `BlindzapIsP2wpkh`, `VerifyBlindzap`, `BitcoinCoreCurrentTipProvider`. | `integration_test`: exact decimal amounts, all network mappings, wrong node network, tip race, null, script/amount and confirmation cases. | The bundled provider is current-tip only. A null `gettxout` is inconclusive; authenticated historical state remains an external provider responsibility. |
| Total claimed value is the checked sum of accepted chain evidence; overflow or claim an insufficient total. | Verifier implementation and chain provider. | `VerifyBlindzap` checked `uint64_t` addition and `minimum_total_sats` comparison. | `integration_test`: multi-claim totals, threshold and overflow/inconclusive cases. | This is not a liability proof and therefore not solvency. |
| A bridge claim has a destination/asset/lock binding and cannot mint without bridge authorization. | Bridge operator/destination-chain callback. | `BlindzapStatementValid` bridge validation and `BlindzapVerifierConfig::bridge_authorized`. | `protocol_test` bridge encoding/mutations; `integration_test` accepted/rejected bridge callback. | BlindZap does not prove a Bitcoin lock, custody, destination finality, or one-time mint by itself. |
| The BIP-322 companion has the documented message binding but is not a standard BIP-322 signature. | Companion-format consumers. | `BlindzapBip322MessageHash` and statement `bip322_message_hash` binding. | `protocol_test`: tagged-message and companion binding cases. | An unmodified BIP-322 script verifier must reject/does not understand a BlindZap proof. |

## Normative coverage and review boundaries

The MUST/REJECT requirements in [the v1 specification](blindzap-v1.md) map to
the rows above: sections 1 and 3 to the first four rows, sections 4 through 6
to the circuit-ID/replay/parser/bridge rows, section 7 to the chain and total
rows, and section 8 to the corresponding negative-test corpus. The
implementation intentionally performs host-side validation in addition to
the circuit.  Those validations are defense in depth only; the scalar, point,
canonical SEC, SHA-256, RIPEMD-160, and public-program relation are circuit
constraints.

Before relying on a deployment, an independent reviewer must assess the proof
system, circuit implementation, parameter generation, nonce-store atomicity,
Bitcoin provider/snapshot/finality policy, and any bridge lock and mint
system.  No row in this document turns those external assumptions into a
cryptographic guarantee.
