// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_KEY_OWNERSHIP_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_KEY_OWNERSHIP_WITNESS_H_

#include "circuits/secp256k1/ec_witness.h"

namespace proofs {
// Native filling helpers deliberately contain no serialization API.
template <class Field, class EC>
struct KeyOwnershipWitness {
  using Elt = typename Field::Elt; using Nat = typename Field::N;
  Secp256k1ScalarMultWitness<Field, EC> scalar_mult;
  Elt scalar, scalar_inverse, z_inverse, x, y;
  Elt x_bits[EC::kBits], y_bits[EC::kBits];
  void compute(const EC& ec, const Nat& secret) {
    const Field& f = ec.f_; scalar = f.to_montgomery(secret);
    scalar_inverse = f.invertf(scalar);
    compute_secp256k1_scalar_mult_witness(scalar_mult, ec, ec.generator(), secret);
    // The circuit consumes the MSB-first double-and-add trace, whose final
    // projective scale need not equal the native scalar_multf scale.
    const Elt& final_x = scalar_mult.int_x[EC::kBits - 1];
    const Elt& final_y = scalar_mult.int_y[EC::kBits - 1];
    const Elt& final_z = scalar_mult.int_z[EC::kBits - 1];
    z_inverse = f.invertf(final_z); x = f.mulf(final_x, z_inverse); y = f.mulf(final_y, z_inverse);
    const Nat xn = f.from_montgomery(x), yn = f.from_montgomery(y);
    for (size_t i = 0; i < EC::kBits; ++i) { x_bits[i] = f.of_scalar(xn.bit(EC::kBits - 1 - i)); y_bits[i] = f.of_scalar(yn.bit(EC::kBits - 1 - i)); }
  }
};
}  // namespace proofs
#endif
