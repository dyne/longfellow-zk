// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MERKLE_FIXED_DEPTH_SHA256_MERKLE_MEMBERSHIP_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MERKLE_FIXED_DEPTH_SHA256_MERKLE_MEMBERSHIP_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

#include "arrays/dense.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "merkle/merkle_tree.h"

namespace proofs {

// The circuit is deliberately bounded: each level is two complete SHA-256
// compression blocks (a 64-byte message plus SHA padding).  Larger relations
// should compose a reviewed, separately measured instantiation.
inline constexpr size_t kFixedDepthSha256MerkleMembershipMaxDepth = 4;

template <size_t Depth>
struct FixedDepthSha256MerklePath {
  static_assert(Depth <= kFixedDepthSha256MerkleMembershipMaxDepth,
                "Merkle circuit depth exceeds the reviewed fixed maximum");

  Digest leaf{};
  std::array<Digest, Depth> siblings{};  // Bottom-up, native single-leaf order.
  std::array<uint8_t, Depth> direction_bits{};  // 1 iff sibling is left.
  Digest root{};
};

// Adapts exactly one already-generated native compressed proof.  It neither
// hashes nor expands a host tree: native verification establishes the proof;
// for one opened leaf the native emission order is already bottom-up.
template <size_t Depth>
class FixedDepthSha256MerklePathAdapter {
 public:
  static_assert(Depth <= kFixedDepthSha256MerkleMembershipMaxDepth,
                "Merkle circuit depth exceeds the reviewed fixed maximum");

  static FixedDepthSha256MerklePath<Depth> from_single_leaf(
      size_t tree_size, const Digest& root, const Digest& leaf,
      size_t position, const std::vector<Digest>& compressed_proof) {
    const size_t expected_size = expected_tree_size();
    if (tree_size != expected_size || position >= tree_size ||
        compressed_proof.size() != Depth) {
      throw std::invalid_argument("invalid fixed-depth single-leaf Merkle proof");
    }

    // This must happen before copying any proof digest into circuit witness
    // storage.  Passing one leaf/position intentionally rejects V1 multi-open
    // proof representations at this API boundary.
    MerkleTreeVerifier verifier(tree_size, root);
    if (!verifier.verify_compressed_proof(compressed_proof.data(),
                                          compressed_proof.size(), &leaf,
                                          &position, 1)) {
      throw std::invalid_argument("native Merkle proof verification failed");
    }

    FixedDepthSha256MerklePath<Depth> path;
    path.leaf = leaf;
    path.root = root;
    for (size_t level = 0; level < Depth; ++level) {
      path.siblings[level] = compressed_proof[level];
      path.direction_bits[level] = static_cast<uint8_t>((position >> level) & 1u);
    }
    return path;
  }

 private:
  static constexpr size_t expected_tree_size() {
    static_assert(Depth < std::numeric_limits<size_t>::digits,
                  "Merkle tree size would overflow size_t");
    return size_t{1} << Depth;
  }
};

template <class Logic, size_t Depth, size_t PluckerLog = 4>
class FixedDepthSha256MerkleMembership {
 public:
  static_assert(Depth <= kFixedDepthSha256MerkleMembershipMaxDepth,
                "Merkle circuit depth exceeds the reviewed fixed maximum");
  using v8 = typename Logic::v8;
  using v256 = typename Logic::v256;
  using BitW = typename Logic::BitW;
  using ShaCircuit = FlatSHA256Circuit<Logic, BitPlucker<Logic, PluckerLog>>;
  using ShaBlockWitness = typename ShaCircuit::BlockWitness;
  static constexpr size_t kShaBlocksPerNode = 2;

  struct Input {
    v256 leaf_digest;
    std::array<v256, Depth> siblings;
    std::array<BitW, Depth> direction_bits;
    typename Logic::template bitvec<Depth> index_bits;
    v256 expected_root;
    std::array<ShaBlockWitness, kShaBlocksPerNode * Depth> sha_witness;
  };

  explicit FixedDepthSha256MerkleMembership(const Logic& logic) : logic_(logic) {}

  // Allocate all private circuit inputs in the exact order consumed by Witness.
  Input input() const {
    Input result{};
    result.leaf_digest = logic_.template vinput<256>();
    for (auto& sibling : result.siblings) sibling = logic_.template vinput<256>();
    for (auto& direction : result.direction_bits) direction = logic_.input();
    result.index_bits = logic_.template vinput<Depth>();
    result.expected_root = logic_.template vinput<256>();
    for (auto& witness : result.sha_witness) witness.input(logic_);
    return result;
  }

  void assert_member(const Input& input) const {
    v256 current;
    for (size_t bit = 0; bit < 256; ++bit) current[bit] = input.leaf_digest[bit];
    ShaCircuit sha(logic_);
    for (size_t level = 0; level < Depth; ++level) {
      logic_.assert_is_bit(input.direction_bits[level]);
      logic_.assert_eq(input.direction_bits[level], input.index_bits[level]);

      v256 left;
      v256 right;
      logic_.vmux(input.direction_bits[level], left, input.siblings[level], current);
      logic_.vmux(input.direction_bits[level], right, current, input.siblings[level]);

      std::array<v8, 128> padded{};
      digest_to_bytes(left, padded.data());
      digest_to_bytes(right, padded.data() + Digest::kLength);
      logic_.bits(8, padded[64].data(), 0x80);
      for (size_t byte = 65; byte < 127; ++byte) logic_.bits(8, padded[byte].data(), 0);
      logic_.bits(8, padded[127].data(), 0);  // 64-byte message bit length is in bytes 126..127.
      logic_.bits(8, padded[126].data(), 2);  // 512 bits, big-endian low byte.

      auto block_count = logic_.template vbit<8>(kShaBlocksPerNode);
      const size_t witness_offset = kShaBlocksPerNode * level;
      sha.assert_message(kShaBlocksPerNode, block_count, padded.data(),
                         &input.sha_witness[witness_offset]);
      // The output is not advice supplied by the caller.  It is unpacked from
      // the final SHA block state that assert_message just constrained.
      v256 next;
      for (size_t word = 0; word < 8; ++word) {
        const auto hash_word = sha.bp_.unpack_v32(
            input.sha_witness[witness_offset + kShaBlocksPerNode - 1].h1[word]);
        for (size_t bit = 0; bit < 32; ++bit) next[(7 - word) * 32 + bit] = hash_word[bit];
      }
      current = std::move(next);
    }
    logic_.vassert_eq(current, input.expected_root);
  }

  template <class Field>
  class Witness {
   public:
    explicit Witness(const FixedDepthSha256MerklePath<Depth>& path) : path_(path) {
      for (size_t level = 0; level < Depth; ++level) {
        std::array<uint8_t, 64> message{};
        const Digest& sibling = path_.siblings[level];
        const Digest& current = level == 0 ? path_.leaf : intermediate_[level - 1];
        const bool sibling_left = path_.direction_bits[level] != 0;
        const Digest& left = sibling_left ? sibling : current;
        const Digest& right = sibling_left ? current : sibling;
        for (size_t i = 0; i < Digest::kLength; ++i) {
          message[i] = left.data[i];
          message[Digest::kLength + i] = right.data[i];
        }
        uint8_t blocks = 0;
        FlatSHA256Witness::transform_and_witness_message(
            message.size(), message.data(), kShaBlocksPerNode, blocks,
            padded_[level].data(), sha_witness_[level].data());
        if (blocks != kShaBlocksPerNode) throw std::logic_error("unexpected SHA block count");
        intermediate_[level] = Digest::hash2(left, right);
      }
      const Digest& final_digest = Depth == 0 ? path_.leaf : intermediate_[Depth - 1];
      if (!(final_digest == path_.root)) {
        throw std::invalid_argument("Merkle path root does not match witness");
      }
    }

    void fill_witness(DenseFiller<Field>& filler, const Field& field) const {
      fill_digest(filler, path_.leaf, field);
      for (const auto& sibling : path_.siblings) fill_digest(filler, sibling, field);
      for (uint8_t direction : path_.direction_bits) filler.push_back(direction, 1, field);
      for (uint8_t direction : path_.direction_bits) filler.push_back(direction, 1, field);
      fill_digest(filler, path_.root, field);
      BitPluckerEncoder<Field, PluckerLog> encoder(field);
      for (const auto& node_witness : sha_witness_) {
        for (const auto& block : node_witness) fill_sha(filler, encoder, block);
      }
    }

    const std::array<Digest, Depth>& intermediate_digests() const { return intermediate_; }

   private:
    static void fill_digest(DenseFiller<Field>& filler, const Digest& digest,
                            const Field& field) {
      for (size_t byte = 0; byte < Digest::kLength; ++byte) {
        for (size_t bit = 0; bit < 8; ++bit) {
          filler.push_back((digest.data[31 - byte] >> bit) & 1u, 1, field);
        }
      }
    }
    static void fill_sha(DenseFiller<Field>& filler,
                         BitPluckerEncoder<Field, PluckerLog>& encoder,
                         const FlatSHA256Witness::BlockWitness& block) {
      for (uint32_t value : block.outw) filler.push_back(encoder.mkpacked_v32(value));
      for (size_t i = 0; i < 64; ++i) {
        filler.push_back(encoder.mkpacked_v32(block.oute[i]));
        filler.push_back(encoder.mkpacked_v32(block.outa[i]));
      }
      for (uint32_t value : block.h1) filler.push_back(encoder.mkpacked_v32(value));
    }

    FixedDepthSha256MerklePath<Depth> path_;
    std::array<std::array<uint8_t, 128>, Depth> padded_{};
    std::array<std::array<FlatSHA256Witness::BlockWitness, kShaBlocksPerNode>, Depth>
        sha_witness_{};
    std::array<Digest, Depth> intermediate_{};
  };

 private:
  void digest_to_bytes(const v256& digest, v8* bytes) const {
    for (size_t byte = 0; byte < Digest::kLength; ++byte) {
      for (size_t bit = 0; bit < 8; ++bit) {
        bytes[byte][bit] = digest[(31 - byte) * 8 + bit];
      }
    }
  }

  const Logic& logic_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MERKLE_FIXED_DEPTH_SHA256_MERKLE_MEMBERSHIP_H_
