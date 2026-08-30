// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Adapted from lib/merkle/merkle_tree_test.cc without GoogleTest or benchmarks.

#include "merkle/merkle_tree.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace proofs {
namespace {

Digest HexDigest(std::string_view hex) {
  assert(hex.size() == 2 * Digest::kLength);
  Digest digest{};
  for (size_t index = 0; index < Digest::kLength; ++index) {
    const auto nibble = [](char value) -> uint8_t {
      if (value >= '0' && value <= '9') return value - '0';
      if (value >= 'a' && value <= 'f') return value - 'a' + 10;
      assert(false);
      return 0;
    };
    digest.data[index] = static_cast<uint8_t>(
        (nibble(hex[2 * index]) << 4) | nibble(hex[2 * index + 1]));
  }
  return digest;
}

void CheckBuildTree() {
  MerkleTree tree(4);
  const std::array<Digest, 4> leaves = {Digest{100}, Digest{101}, Digest{102},
                                         Digest{103}};
  for (size_t index = 0; index < leaves.size(); ++index) tree.set_leaf(index, leaves[index]);
  const Digest root = tree.build_tree();
  assert(tree.layers_[4] == leaves[0]);
  assert(tree.layers_[2] == Digest::hash2(leaves[0], leaves[1]));
  assert(tree.layers_[3] == Digest::hash2(leaves[2], leaves[3]));
  assert(tree.layers_[1] == Digest::hash2(Digest::hash2(leaves[0], leaves[1]),
                                           Digest::hash2(leaves[2], leaves[3])));
  assert(root == tree.layers_[1]);
}

MerkleTree SetupBatch(size_t count, size_t batch_size, std::vector<Digest>& leaves,
                      std::vector<size_t>& indices) {
  MerkleTree tree(count);
  for (size_t index = 0; index < count; ++index) tree.set_leaf(index, Digest{static_cast<uint8_t>(index + 1)});
  for (size_t request = 0; request < batch_size; ++request) {
    size_t index = (request * 37 + 11) % count;
    while (std::find(indices.begin(), indices.end(), index) != indices.end()) {
      index = (index + 1) % count;
    }
    indices.push_back(index);
    leaves.push_back(tree.layers_[index + count]);
  }
  return tree;
}

void CheckCompressedProofs() {
  for (const size_t batch_size : {size_t{1}, size_t{10}, size_t{80}}) {
    for (size_t count = 200; count <= 300; ++count) {
      std::vector<size_t> indices;
      std::vector<Digest> leaves;
      MerkleTree tree = SetupBatch(count, batch_size, leaves, indices);
      const Digest root = tree.build_tree();
      std::vector<Digest> proof;
      const size_t length = tree.generate_compressed_proof(proof, indices.data(), indices.size());
      assert(length == proof.size());
      assert(MerkleTreeVerifier(count, root).verify_compressed_proof(
          proof.data(), length, leaves.data(), indices.data(), indices.size()));
    }
  }
}

void CheckRejectedProofs() {
  for (size_t count = 200; count <= 300; ++count) {
    std::vector<size_t> indices;
    std::vector<Digest> leaves;
    MerkleTree tree = SetupBatch(count, 80, leaves, indices);
    const Digest root = tree.build_tree();
    std::vector<Digest> proof;
    const size_t length = tree.generate_compressed_proof(proof, indices.data(), indices.size());
    const MerkleTreeVerifier verifier(count, root);
    for (Digest& element : proof) {
      element.data[0] ^= 1;
      assert(!verifier.verify_compressed_proof(proof.data(), length, leaves.data(),
                                                indices.data(), indices.size()));
      element.data[0] ^= 1;
    }
  }

  std::vector<size_t> indices;
  std::vector<Digest> leaves;
  MerkleTree tree = SetupBatch(300, 20, leaves, indices);
  const Digest root = tree.build_tree();
  std::vector<Digest> proof;
  const size_t length = tree.generate_compressed_proof(proof, indices.data(), indices.size());
  assert(!MerkleTreeVerifier(300, root).verify_compressed_proof(
      proof.data(), length - 1, leaves.data(), indices.data(), indices.size()));
}

void CheckZeroLengthProof() {
  const std::array<Digest, 4> leaves = {Digest{100}, Digest{101}, Digest{102},
                                         Digest{103}};
  MerkleTree tree(leaves.size());
  for (size_t index = 0; index < leaves.size(); ++index) tree.set_leaf(index, leaves[index]);
  const Digest root = tree.build_tree();
  const std::array<size_t, 4> indices = {0, 1, 2, 3};
  const std::vector<Digest> empty_proof;
  const MerkleTreeVerifier verifier(leaves.size(), root);
  assert(!verifier.verify_compressed_proof(empty_proof.data(), 0, leaves.data(),
                                            indices.data(), 1));
  assert(verifier.verify_compressed_proof(empty_proof.data(), 0, leaves.data(),
                                           indices.data(), leaves.size()));
}

void CheckVectors() {
  const std::array<Digest, 5> leaves = {
      HexDigest("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
      HexDigest("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986"),
      HexDigest("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
      HexDigest("e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71"),
      HexDigest("e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db")};
  MerkleTree tree(leaves.size());
  for (size_t index = 0; index < leaves.size(); ++index) tree.set_leaf(index, leaves[index]);
  assert(tree.build_tree() == HexDigest("f22f4501ffd3bdffcecc9e4cd6828a4479aeedd6aa484eb7c1f808ccf71c6e76"));

  std::array<size_t, 2> indices = {0, 1};
  std::vector<Digest> proof;
  assert(tree.generate_compressed_proof(proof, indices.data(), indices.size()) == 2);
  assert((proof == std::vector<Digest>{
      HexDigest("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
      HexDigest("f03808f5b8088c61286d505e8e93aa378991d9889ae2d874433ca06acabcd493")}));

  indices = {1, 3};
  proof.clear();
  assert(tree.generate_compressed_proof(proof, indices.data(), indices.size()) == 3);
  assert((proof == std::vector<Digest>{
      HexDigest("e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db"),
      HexDigest("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
      HexDigest("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")}));
}

}  // namespace
}  // namespace proofs

int main() {
  proofs::CheckBuildTree();
  proofs::CheckCompressedProofs();
  proofs::CheckRejectedProofs();
  proofs::CheckZeroLengthProof();
  proofs::CheckVectors();
  return 0;
}
