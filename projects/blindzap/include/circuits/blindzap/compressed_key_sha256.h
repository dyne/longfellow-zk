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
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_COMPRESSED_KEY_SHA256_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_COMPRESSED_KEY_SHA256_H_

#include <array>

#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {

// SHA-256 for the canonical 33-byte compressed SEC key produced by
// KeyOwnershipCircuit.  The sole block is built here: SEC || 0x80 || zeroes
// || uint64_be(264).  A v8 is least-significant-bit first, although SHA words
// are assembled big endian; the SEC coordinate witness is MSB first and is
// therefore reversed within each v8.  FlatSHA256Circuit packs its v32 round
// witnesses with BitPlucker, then returns the v256 digest in field-integer bit
// order (the displayed SHA byte stream is consequently reversed by bytes).
// assert_message() constrains the block and zero padding; the digest is
// unpacked from that constrained block's H1 witness.  SEC bits are taken
// directly from the already constrained coordinate encoding, so no message,
// padding, length, or digest input is exposed by this stage.
template <class LogicCircuit>
class CompressedKeySha256Circuit {
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using BitW = typename LogicCircuit::BitW;
  using Flatsha = FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, 4>>;

 public:
  struct Witness {
    typename Flatsha::BlockWitness block;
    void input(const LogicCircuit& lc) { block.input(lc); }
  };

  explicit CompressedKeySha256Circuit(const LogicCircuit& lc) : lc_(lc), sha_(lc) {}

  template <class CompressedKey>
  v256 derive(const CompressedKey& key, const Witness& witness) const {
    std::array<v8, 64> block;
    for (auto& byte : block) byte = lc_.template vbit<8>(0);

    // SEC prefix is 0x02 + Y parity.  Bit vectors are least-significant-bit
    // first, while the coordinate witness stores its bits most-significant-bit
    // first.
    block[0][0] = BitW(key.parity, lc_.f_);
    block[0][1] = lc_.bit(1);
    for (size_t byte = 0; byte < 32; ++byte) {
      for (size_t bit = 0; bit < 8; ++bit) {
        block[byte + 1][bit] = BitW(key.x_bits[byte * 8 + (7 - bit)], lc_.f_);
      }
    }
    block[33] = lc_.template vbit<8>(0x80);
    block[62] = lc_.template vbit<8>(1);
    block[63] = lc_.template vbit<8>(8);

    const v8 one_block = lc_.template vbit<8>(1);
    sha_.assert_message(1, one_block, block.data(), &witness.block);

    // FlatSHA256Circuit deliberately exposes its bit plucker so callers can
    // encode and decode packed witnesses.  This message always occupies one
    // block, so H1 is the selected final state without the multi-block mux
    // used by assert_hash().  Keep the same field-integer bit order as that
    // method while leaving the digest private to the surrounding circuit.
    v256 digest;
    for (size_t word = 0; word < 8; ++word) {
      const auto unpacked = sha_.bp_.unpack_v32(witness.block.h1[word]);
      for (size_t bit = 0; bit < 32; ++bit) {
        digest[(7 - word) * 32 + bit] = unpacked[bit];
      }
    }
    return digest;
  }

 private:
  const LogicCircuit& lc_;
  Flatsha sha_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_COMPRESSED_KEY_SHA256_H_
