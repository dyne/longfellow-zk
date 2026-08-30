// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include <cassert>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <vector>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/merkle/fixed_depth_sha256_merkle_membership.h"
#include "ec/p256k1.h"

namespace proofs {
namespace {

Digest Leaf(uint8_t value) {
  Digest digest{};
  digest.data[0] = value;
  return digest;
}

template <size_t Depth>
void CheckPosition(size_t position) {
  constexpr size_t kTreeSize = size_t{1} << Depth;
  MerkleTree tree(kTreeSize);
  for (size_t i = 0; i < kTreeSize; ++i) tree.set_leaf(i, Leaf(static_cast<uint8_t>(i + 1)));
  const Digest root = tree.build_tree();
  std::vector<Digest> proof;
  tree.generate_compressed_proof(proof, &position, 1);

  const auto path = FixedDepthSha256MerklePathAdapter<Depth>::from_single_leaf(
      kTreeSize, root, Leaf(static_cast<uint8_t>(position + 1)), position, proof);
  assert(path.root == root);
  for (size_t level = 0; level < Depth; ++level) {
    assert(path.siblings[level] == proof[level]);
    assert(path.direction_bits[level] == ((position >> level) & 1u));
  }
  typename FixedDepthSha256MerkleMembership<
      Logic<Fp256k1Base, EvaluationBackend<Fp256k1Base>>, Depth>::template Witness<Fp256k1Base>
      witness(path);
  if constexpr (Depth > 0) assert(witness.intermediate_digests()[Depth - 1] == root);
}

using EvalLogic = Logic<Fp256k1Base, EvaluationBackend<Fp256k1Base>>;
using Circuit = FixedDepthSha256MerkleMembership<EvalLogic, 2>;

void AssignDigest(const EvalLogic& logic, EvalLogic::v256& output,
                  const Digest& digest) {
  for (size_t byte = 0; byte < Digest::kLength; ++byte) {
    logic.bits(8, &output[(31 - byte) * 8], digest.data[byte]);
  }
}

void AssignBlock(const EvalLogic& logic, Circuit::ShaBlockWitness& output,
                 const FlatSHA256Witness::BlockWitness& input) {
  BitPluckerEncoder<Fp256k1Base, 4> encoder(p256k1_base);
  for (size_t i = 0; i < 48; ++i) {
    const auto packed = encoder.mkpacked_v32(input.outw[i]);
    for (size_t j = 0; j < packed.size(); ++j) output.outw[i][j] = logic.konst(packed[j]);
  }
  for (size_t i = 0; i < 64; ++i) {
    const auto packed_e = encoder.mkpacked_v32(input.oute[i]);
    const auto packed_a = encoder.mkpacked_v32(input.outa[i]);
    for (size_t j = 0; j < packed_e.size(); ++j) {
      output.oute[i][j] = logic.konst(packed_e[j]);
      output.outa[i][j] = logic.konst(packed_a[j]);
    }
  }
  for (size_t i = 0; i < 8; ++i) {
    const auto packed = encoder.mkpacked_v32(input.h1[i]);
    for (size_t j = 0; j < packed.size(); ++j) output.h1[i][j] = logic.konst(packed[j]);
  }
}

Circuit::Input CircuitInput(const EvalLogic& logic,
                            const FixedDepthSha256MerklePath<2>& path,
                            int mutation) {
  Circuit::Input input{};
  AssignDigest(logic, input.leaf_digest, path.leaf);
  for (size_t level = 0; level < 2; ++level) {
    AssignDigest(logic, input.siblings[level], path.siblings[level]);
    input.direction_bits[level] = logic.bit(path.direction_bits[level]);
    input.index_bits[level] = logic.bit(path.direction_bits[level]);
  }
  Digest expected = path.root;
  if (mutation == 1) expected.data[0] ^= 1;
  AssignDigest(logic, input.expected_root, expected);

  Digest current = path.leaf;
  for (size_t level = 0; level < 2; ++level) {
    const Digest& sibling = path.siblings[level];
    const bool sibling_left = path.direction_bits[level] != 0;
    const Digest& left = sibling_left ? sibling : current;
    const Digest& right = sibling_left ? current : sibling;
    std::array<uint8_t, 64> message{};
    for (size_t i = 0; i < Digest::kLength; ++i) {
      message[i] = left.data[i];
      message[Digest::kLength + i] = right.data[i];
    }
    uint8_t blocks = 0;
    std::array<uint8_t, 128> padded{};
    std::array<FlatSHA256Witness::BlockWitness, 2> witness{};
    FlatSHA256Witness::transform_and_witness_message(message.size(), message.data(),
                                                     2, blocks, padded.data(), witness.data());
    assert(blocks == 2);
    AssignBlock(logic, input.sha_witness[2 * level], witness[0]);
    AssignBlock(logic, input.sha_witness[2 * level + 1], witness[1]);
    current = Digest::hash2(left, right);
  }
  if (mutation == 2) input.leaf_digest[0] = logic.lnot(input.leaf_digest[0]);
  if (mutation == 3) input.siblings[0][0] = logic.lnot(input.siblings[0][0]);
  if (mutation == 4) {
    input.direction_bits[0] = logic.lnot(input.direction_bits[0]);
    input.index_bits[0] = logic.lnot(input.index_bits[0]);
  }
  if (mutation == 5) {
    BitPluckerEncoder<Fp256k1Base, 4> encoder(p256k1_base);
    input.sha_witness[1].h1[0][0] = logic.konst(encoder.mkpacked_v32(0)[0]);
  }
  if (mutation == 6) std::swap(input.siblings[0], input.siblings[1]);
  return input;
}

void CheckCircuit() {
  MerkleTree tree(4);
  for (size_t i = 0; i < 4; ++i) tree.set_leaf(i, Leaf(static_cast<uint8_t>(i + 1)));
  const Digest root = tree.build_tree();
  const size_t position = 3;
  std::vector<Digest> proof;
  tree.generate_compressed_proof(proof, &position, 1);
  const auto path = FixedDepthSha256MerklePathAdapter<2>::from_single_leaf(
      4, root, Leaf(4), position, proof);

  for (int mutation = 0; mutation <= 6; ++mutation) {
    EvaluationBackend<Fp256k1Base> backend(p256k1_base, false);
    EvalLogic logic(&backend, p256k1_base);
    Circuit relation(logic);
    const auto input = CircuitInput(logic, path, mutation);
    relation.assert_member(input);
    assert(backend.assertion_failed() == (mutation != 0));
  }
}

void CheckCompilerBound() {
  QuadCircuit<Fp256k1Base> circuit(p256k1_base);
  using CompileBackend = CompilerBackend<Fp256k1Base>;
  using CompileLogic = Logic<Fp256k1Base, CompileBackend>;
  const CompileBackend backend(&circuit);
  const CompileLogic logic(&backend, p256k1_base);
  FixedDepthSha256MerkleMembership<CompileLogic, 4> relation(logic);
  circuit.private_input();
  const auto input = relation.input();
  relation.assert_member(input);
  const auto compiled = circuit.mkcircuit(1);
  assert(compiled->ninputs > 0);
  std::printf("depth=4 inputs=%zu wires=%zu quads=%zu\n", compiled->ninputs,
              circuit.nwires_, circuit.nquad_terms_);
}

}  // namespace
}  // namespace proofs

int main() {
  proofs::CheckPosition<0>(0);
  proofs::CheckPosition<1>(0);
  proofs::CheckPosition<1>(1);
  proofs::CheckPosition<2>(0);
  proofs::CheckPosition<2>(1);
  proofs::CheckPosition<2>(2);
  proofs::CheckPosition<2>(3);
  proofs::CheckCircuit();
  proofs::CheckCompilerBound();

  for (int malformed = 0; malformed < 3; ++malformed) {
    bool rejected = false;
    try {
      if (malformed == 0) {
        proofs::FixedDepthSha256MerklePathAdapter<2>::from_single_leaf(
            3, proofs::Leaf(0), proofs::Leaf(0), 0, {});
      } else if (malformed == 1) {
        proofs::FixedDepthSha256MerklePathAdapter<2>::from_single_leaf(
            4, proofs::Leaf(0), proofs::Leaf(0), 4, {});
      } else {
        proofs::FixedDepthSha256MerklePathAdapter<2>::from_single_leaf(
            4, proofs::Leaf(0), proofs::Leaf(0), 0, {});
      }
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    assert(rejected);
  }
  return 0;
}
