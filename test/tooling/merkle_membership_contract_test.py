#!/usr/bin/env python3
"""Keep the published V1 membership contract and vector schema complete."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "merkle-membership-contract.md"
SCHEMA = ROOT / "test" / "merkle" / "canonical_merkle_membership_vector.schema.json"


def main() -> None:
    text = DOC.read_text(encoding="utf-8")
    required = (
        "FixedDepthSha256MerkleMembership", "FlatSHA256Circuit", "BitPlucker",
        "direction_bits[level]` is boolean", "left || right",
        "MerkleTree::generate_compressed_proof",
        "MerkleTreeVerifier::verify_compressed_proof", "Compressed multi-open proofs",
        "v256[(31 - b) * 8 + bit]", "depth 0", "non-power-of-two",
        "negative cases independently mutate the leaf",
    )
    assert all(marker in text for marker in required), "contract is incomplete"
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    required_fields = set(schema["required"])
    expected = {"treeSize", "depth", "leaves", "selectedIndex", "leaf",
                "nativeCompressedProof", "nativeCompressedProofBytes",
                "expandedPath", "indexBitsLsbFirst", "levels", "root"}
    assert expected <= required_fields, "canonical vector fields are incomplete"
    assert schema["$defs"]["digest"]["pattern"] == "^[0-9a-f]{64}$"
    assert schema["properties"]["levels"]["items"]["properties"]["leftRightPreimage"]["pattern"] == "^[0-9a-f]{128}$"
    print("merkle membership contract: API, ordering, adapter, and vector schema complete")


if __name__ == "__main__":
    main()
