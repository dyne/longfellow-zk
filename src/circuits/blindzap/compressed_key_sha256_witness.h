// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
