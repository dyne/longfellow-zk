# Pre-split artifact baseline

The current `src/liblongfellow-zk.a` contains 16 objects.  Four are mdoc
application objects (`mdoc_decompress`, `mdoc_generate_circuit`, `mdoc_zk`,
`zk_spec`) and one (`decode_util`) is test helper code; all five must disappear
from the base archive in the packaging milestone.  The current globally defined
application symbols include `run_mdoc_prover`, `run_mdoc_verifier`, and the
`MdocHash::assert_valid_hash_mdoc` instantiation.  These are negative artifact
checks, not behavior changes.

The qualification baseline remains the current matrix: LFC1/LFC2 vectors and
proof verification, compiler/circuit IDs, ECDSA module/artifact tests, BIP340
vectors, mdoc Bats, and BlindZap protocol/integration/CLI/Sage gates.  Random
proofs are verified and tamper-rejected rather than byte-compared.  The test
ownership manifest names one post-split owner and replacement target for every
first-party test, vector, corpus, and qualification script; Bats runner and
assertion libraries remain shared test infrastructure.
