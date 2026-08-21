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
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_RIPEMD160_RIPEMD160_FIXED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_RIPEMD160_RIPEMD160_FIXED_H_

#include <array>
#include "circuits/ripemd160/ripemd160_circuit.h"

namespace proofs {

// RIPEMD-160's single block for a 32-byte digest.  FlatSHA256 exposes its
// digest in reversed byte order, hence the explicit 31-byte reversal here.
template <class Logic>
class Ripemd160Fixed32 {
 public:
  using v8 = typename Logic::v8;
  using v256 = typename Logic::v256;
  explicit Ripemd160Fixed32(const Logic& logic) : l_(logic), ripemd_(logic) {}
  std::array<v8, 20> derive(const v256& sha_digest) const {
    std::array<v8, 64> block;
    for (auto& byte : block) byte = l_.template vbit<8>(0);
    for (size_t byte = 0; byte < 32; ++byte)
      for (size_t bit = 0; bit < 8; ++bit) block[byte][bit] = sha_digest[(31-byte)*8+bit];
    block[32] = l_.template vbit<8>(0x80);
    block[56] = l_.template vbit<8>(0);
    block[57] = l_.template vbit<8>(1);  // little-endian uint64(256)
    const auto words = ripemd_.compress(block);
    std::array<v8, 20> out;
    for (size_t byte = 0; byte < 20; ++byte)
      for (size_t bit = 0; bit < 8; ++bit) out[byte][bit] = words[byte/4][(byte%4)*8+bit];
    return out;
  }
 private:
  const Logic& l_;
  Ripemd160Circuit<Logic> ripemd_;
};
}  // namespace proofs
#endif
