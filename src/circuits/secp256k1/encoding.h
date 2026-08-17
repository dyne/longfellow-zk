// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_ENCODING_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_ENCODING_H_

#include <array>
#include <cstddef>

namespace proofs {

// Canonical (not merely modulo p) 256-bit base-field encoding.  bits[0] is
// the most significant bit; this is the order used by SEC byte serialization.
template <class LogicCircuit, class EC>
class Secp256k1Encoding {
 public:
  using EltW = typename LogicCircuit::EltW;
  static constexpr size_t kBits = EC::kBits;
  struct CoordinateWitness {
    EltW bits[kBits];
    void input(const LogicCircuit& lc) { for (auto& bit : bits) bit = lc.eltw_input(); }
  };
  struct CompressedKey { std::array<EltW, 33> bytes; };

  explicit Secp256k1Encoding(const LogicCircuit& lc) : lc_(lc), modulus_bits_(modulus_bits(lc)) {}

  void assert_canonical(EltW value, const CoordinateWitness& witness) const {
    typename LogicCircuit::v256 lsb_first;
    EltW reconstructed = lc_.konst(lc_.zero());
    for (size_t i = 0; i < kBits; ++i) {
      typename LogicCircuit::BitW bit(witness.bits[i], lc_.f_);
      lc_.assert_is_bit(bit);
      reconstructed = lc_.add(reconstructed, reconstructed);
      reconstructed = lc_.add(reconstructed, witness.bits[i]);
      lsb_first[kBits - 1 - i] = bit;
    }
    lc_.assert_eq(reconstructed, value);
    // Equality in Fp alone admits value+p.  The strict comparison gives one
    // integer and therefore one 32-byte SEC representation.
    lc_.assert1(lc_.vlt(lsb_first, modulus_bits_));
  }

  std::array<EltW, 32> bytes(const CoordinateWitness& witness) const {
    std::array<EltW, 32> result;
    for (size_t byte = 0; byte < result.size(); ++byte) {
      EltW value = lc_.konst(lc_.zero());
      for (size_t bit = 0; bit < 8; ++bit) {
        value = lc_.add(value, value);
        value = lc_.add(value, witness.bits[byte * 8 + bit]);
      }
      result[byte] = value;
    }
    return result;
  }

  CompressedKey compressed(const CoordinateWitness& x,
                           const CoordinateWitness& y) const {
    CompressedKey key;
    // bits[255] is the LSB under the MSB-first convention.
    key.bytes[0] = lc_.add(lc_.konst(2), y.bits[kBits - 1]);
    const auto x_bytes = bytes(x);
    for (size_t i = 0; i < x_bytes.size(); ++i) key.bytes[i + 1] = x_bytes[i];
    return key;
  }

 private:
  const LogicCircuit& lc_;
  typename LogicCircuit::v256 modulus_bits_;
  static typename LogicCircuit::v256 modulus_bits(const LogicCircuit& lc) {
    typename LogicCircuit::v256 result;
    typename EC::N p("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    for (size_t i = 0; i < kBits; ++i) result[i] = lc.bit(p.bit(i));
    return result;
  }
};
}  // namespace proofs
#endif
