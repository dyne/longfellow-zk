// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_EC_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_EC_WITNESS_H_

#include <cstddef>

namespace proofs {

template <class Field, class EC>
struct Secp256k1ScalarMultWitness {
  using Elt = typename Field::Elt;
  static constexpr size_t kBits = EC::kBits;
  Elt bits[kBits];
  Elt int_x[kBits];
  Elt int_y[kBits];
  Elt int_z[kBits];
};

/// Fill the MSB-first bit decomposition and complete-projective trace used by
/// Secp256k1EcGadget.  The final trace entry is retained for native clients;
/// the circuit only receives the first kBits - 1 entries.
template <class Field, class EC>
void compute_secp256k1_scalar_mult_witness(
    Secp256k1ScalarMultWitness<Field, EC>& witness, const EC& ec,
    const typename EC::ECPoint& point, const typename Field::N& scalar) {
  using Elt = typename Field::Elt;
  const Field& field = ec.f_;
  Elt x = field.zero();
  Elt y = field.one();
  Elt z = field.zero();
  for (size_t i = 0; i < EC::kBits; ++i) {
    const size_t bit_index = EC::kBits - 1 - i;
    const int bit = scalar.bit(bit_index);
    witness.bits[i] = field.of_scalar(bit);
    ec.doubleE(x, y, z, x, y, z);
    if (bit == 1) {
      ec.addE(x, y, z, x, y, z, point.x, point.y, point.z);
    } else {
      ec.addE(x, y, z, x, y, z, field.zero(), field.one(), field.zero());
    }
    witness.int_x[i] = x;
    witness.int_y[i] = y;
    witness.int_z[i] = z;
  }
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_EC_WITNESS_H_
