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
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_BLINDZAP_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_BLINDZAP_WITNESS_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include "arrays/dense.h"
#include "circuits/blindzap/compressed_key_sha256_witness.h"
#include "circuits/blindzap/key_ownership_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/ripemd160/ripemd160.h"

namespace proofs {

// Native witness construction is deliberately validation-first.  It supplies
// advice only; the circuit independently constrains every derived value.
template <class Field, class EC>
class BlindzapWitnessV1 {
 public:
  using Nat = typename Field::N;
  static constexpr size_t kProgramBytes = 20;

  bool compute(const EC& ec, const uint8_t* secret, size_t secret_size) {
    if (secret == nullptr || secret_size != 32) return false;
    uint8_t little_endian[32];
    for (size_t i = 0; i < 32; ++i) little_endian[i] = secret[31 - i];
    const Nat scalar = Nat::of_bytes(little_endian, 256);
    const Nat order("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    if (scalar == Nat(0) || !(scalar < order)) return false;
    field_ = &ec.f_;
    ownership_.compute(ec, scalar);
    std::array<uint8_t, 33> sec{};
    sec[0] = 2 + ec.f_.from_montgomery(ownership_.y_bits[255]).bit(0);
    for (size_t byte = 0; byte < 32; ++byte)
      for (size_t bit = 0; bit < 8; ++bit)
        sec[byte + 1] = static_cast<uint8_t>((sec[byte + 1] << 1) |
            ec.f_.from_montgomery(ownership_.x_bits[byte * 8 + bit]).bit(0));
    sha_.compute(sec);
    program_ = Ripemd160::digest(sha_.digest);
    return true;
  }

  const std::array<uint8_t, kProgramBytes>& program() const { return program_; }

  template <class Filler>
  void fill_witness(Filler& filler) const {
    filler.push_back(ownership_.scalar);
    filler.push_back(ownership_.scalar_inverse);
    for (size_t i = 0; i < EC::kBits; ++i) {
      filler.push_back(ownership_.scalar_mult.bits[i]);
      if (i + 1 < EC::kBits) {
        filler.push_back(ownership_.scalar_mult.int_x[i]);
        filler.push_back(ownership_.scalar_mult.int_y[i]);
        filler.push_back(ownership_.scalar_mult.int_z[i]);
      }
    }
    filler.push_back(ownership_.z_inverse);
    filler.push_back(ownership_.x);
    filler.push_back(ownership_.y);
    for (size_t i = 0; i < EC::kBits; ++i) filler.push_back(ownership_.x_bits[i]);
    for (size_t i = 0; i < EC::kBits; ++i) filler.push_back(ownership_.y_bits[i]);
    if (field_ == nullptr) throw std::logic_error("witness was not computed");
    BitPluckerEncoder<Field, 4> encoder(*field_);
    for (size_t i = 0; i < 48; ++i) for (const auto& value : encoder.mkpacked_v32(sha_.block.outw[i])) filler.push_back(value);
    for (size_t i = 0; i < 64; ++i) {
      for (const auto& value : encoder.mkpacked_v32(sha_.block.oute[i])) filler.push_back(value);
      for (const auto& value : encoder.mkpacked_v32(sha_.block.outa[i])) filler.push_back(value);
    }
    for (size_t i = 0; i < 8; ++i) for (const auto& value : encoder.mkpacked_v32(sha_.block.h1[i])) filler.push_back(value);
  }

 private:
  KeyOwnershipWitness<Field, EC> ownership_;
  CompressedKeySha256Witness sha_;
  std::array<uint8_t, kProgramBytes> program_{};
  const Field* field_ = nullptr;
};

}  // namespace proofs

#endif
