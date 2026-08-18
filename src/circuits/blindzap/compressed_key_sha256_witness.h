// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_COMPRESSED_KEY_SHA256_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_COMPRESSED_KEY_SHA256_WITNESS_H_

#include <array>
#include <cstdint>
#include <stdexcept>

#include "circuits/sha/flatsha256_witness.h"

namespace proofs {

// Native witness for the fixed SEC-length SHA stage.  The size check is
// deliberately fail-closed: this helper cannot accidentally produce a
// multiple-block witness for a different message shape.
struct CompressedKeySha256Witness {
  FlatSHA256Witness::BlockWitness block;
  std::array<uint8_t, 32> digest;

  void compute(const std::array<uint8_t, 33>& sec) {
    uint8_t nb = 0;
    uint8_t padded[64] = {};
    FlatSHA256Witness::transform_and_witness_message(sec.size(), sec.data(), 1,
                                                     nb, padded, &block);
    if (nb != 1 || padded[33] != 0x80 || padded[62] != 1 || padded[63] != 8) {
      throw std::invalid_argument("compressed SEC must hash in one SHA-256 block");
    }
    for (size_t word = 0; word < 8; ++word) {
      for (size_t byte = 0; byte < 4; ++byte) {
        digest[word * 4 + byte] = (block.h1[word] >> (24 - 8 * byte)) & 0xffu;
      }
    }
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_COMPRESSED_KEY_SHA256_WITNESS_H_
