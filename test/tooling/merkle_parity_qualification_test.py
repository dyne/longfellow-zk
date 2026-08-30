#!/usr/bin/env python3
"""Qualify canonical native-to-circuit Merkle bytes across installed boundaries."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT.parent
CORPUS = ROOT / "test/merkle/canonical_merkle_membership_vectors.json"

NATIVE = r'''
#include <cstdio>
#include <vector>
#include "merkle/merkle_tree.h"
int main() { proofs::MerkleTree tree(4); for (size_t i = 0; i != 4; ++i) { proofs::Digest d{}; for (size_t j = 0; j != 32; ++j) d.data[j] = i * 32 + j; tree.set_leaf(i, d); } const size_t index = 2; const auto root = tree.build_tree(); std::vector<proofs::Digest> proof; tree.generate_compressed_proof(proof, &index, 1); for (auto b : root.data) std::printf("%02x", b); std::printf("\n"); for (const auto& d : proof) for (auto b : d.data) std::printf("%02x", b); std::printf("\n"); }
'''

CIRCUIT = r'''
#include <cstdio>
#include <vector>
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/merkle/fixed_depth_sha256_merkle_membership.h"
#include "ec/p256k1.h"
int main() { proofs::MerkleTree tree(4); std::vector<proofs::Digest> leaves(4); for (size_t i = 0; i != 4; ++i) { for (size_t j = 0; j != 32; ++j) leaves[i].data[j] = i * 32 + j; tree.set_leaf(i, leaves[i]); } const size_t index = 2; const auto root = tree.build_tree(); std::vector<proofs::Digest> proof; tree.generate_compressed_proof(proof, &index, 1); const auto path = proofs::FixedDepthSha256MerklePathAdapter<2>::from_single_leaf(4, root, leaves[index], index, proof); using Logic = proofs::Logic<proofs::Fp256k1Base, proofs::EvaluationBackend<proofs::Fp256k1Base>>; using Relation = proofs::FixedDepthSha256MerkleMembership<Logic, 2>; Relation::Witness<proofs::Fp256k1Base> witness(path); for (size_t level = 0; level != 2; ++level) { const auto& sibling = path.siblings[level]; const auto& current = level ? witness.intermediate_digests()[level - 1] : path.leaf; const auto& left = path.direction_bits[level] ? sibling : current; const auto& right = path.direction_bits[level] ? current : sibling; for (auto b : left.data) std::printf("%02x", b); for (auto b : right.data) std::printf("%02x", b); std::printf("\n"); for (auto b : witness.intermediate_digests()[level].data) std::printf("%02x", b); std::printf("\n"); } }
'''

def run(command: list[str], cwd: Path) -> list[str]:
    return subprocess.check_output(command, cwd=cwd, text=True, stderr=subprocess.STDOUT).splitlines()

def probe(source: str, include: Path, library: Path, name: str) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="merkle-parity-") as directory:
        work = Path(directory); main = work / "main.cc"; binary = work / name
        main.write_text(source, encoding="utf-8")
        run(["ccache", "c++", "-std=c++20", f"-I{include}", str(main), str(library), "-lcrypto", "-o", str(binary)], work)
        return run([str(binary)], work)

def main() -> None:
    assert shutil.which("ccache"), "ccache is required for C++ qualification probes"
    vector = json.loads(CORPUS.read_text(encoding="utf-8"))[0]
    prefix = WORKSPACE / ".longfellow-install"
    european = probe(NATIVE, prefix / "include/longfellow-zk", prefix / "lib/liblongfellow-zk.a", "european")
    google = probe(NATIVE, WORKSPACE / "google-longfellow-zk/lib", WORKSPACE / "google-longfellow-zk/build-l4/liblongfellow-zk.a", "google")
    assert european == google == [vector["root"], vector["nativeCompressedProofBytes"]]
    circuit = probe(CIRCUIT, prefix / "include/longfellow-zk", prefix / "lib/liblongfellow-zk.a", "circuit")
    expected = [value for level in vector["levels"] for value in (level["leftRightPreimage"], level["digest"])]
    assert circuit == expected, "installed path adapter/witness changed a vector byte"
    assert [step["sibling"] for step in vector["expandedPath"]] == vector["nativeCompressedProof"]
    assert [step["siblingIsLeft"] for step in vector["expandedPath"]] == vector["indexBitsLsbFirst"]
    print("merkle parity: native roots/proofs and installed circuit path bytes match corpus")

if __name__ == "__main__":
    main()
