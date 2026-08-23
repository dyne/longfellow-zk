// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_EVALUATE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_EVALUATE_H_

#include "circuits/ecdsa/verify_types.h"
#include "util/panic.h"

namespace proofs {

// Derives the native intermediates consumed by the ECDSA relation.  It is
// intentionally separate from serialization and circuit construction so tests
// can corrupt a single native intermediate before it is allocated as advice.
template <class EC, class ScalarField>
bool EvaluateVerifyWitness(VerifyWitnessData<EC>& witness,
                           const ScalarField& scalar_field, const EC& ec,
                           const typename EC::Field::Elt& pk_x,
                           const typename EC::Field::Elt& pk_y,
                           const typename EC::Field::N& e,
                           const typename EC::Field::N& r,
                           const typename EC::Field::N& s) {
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  using Point = typename EC::ECPoint;
  using Scalar = typename ScalarField::Elt;
  const Field& field = ec.f_;
  const Scalar s_inverse = scalar_field.invertf(scalar_field.to_montgomery(s));
  const Scalar minus_s = scalar_field.negf(scalar_field.to_montgomery(s));

  const Nat e_over_s = scalar_field.from_montgomery(
      scalar_field.mulf(scalar_field.to_montgomery(e), s_inverse));
  const Nat r_over_s = scalar_field.from_montgomery(
      scalar_field.mulf(scalar_field.to_montgomery(r), s_inverse));
  Point bases[] = {ec.generator(), Point(pk_x, pk_y, field.one())};
  Nat scalars[] = {e_over_s, r_over_s};
  auto point_r = ec.scalar_multf(2, bases, scalars);
  ec.normalize(point_r);

  witness.rx_ = field.to_montgomery(r);
  witness.ry_ = point_r.y;
  if (witness.rx_ != field.zero()) {
    witness.rx_inv_ = field.invertf(witness.rx_);
    check(field.mulf(witness.rx_, witness.rx_inv_) == field.one(), "bad inv");
  }
  witness.s_inv_ = field.to_montgomery(scalar_field.from_montgomery(minus_s));
  if (witness.s_inv_ != field.zero()) field.invert(witness.s_inv_);
  if (pk_x != field.zero()) witness.pk_inv_ = field.invertf(pk_x);

  const Nat native_minus_s = scalar_field.from_montgomery(minus_s);
  const Elt one = field.one(), gx = ec.gx_, gy = ec.gy_;
  const Elt lhs[] = {gx, gy, gx, gy, pk_x, pk_y};
  const Elt rhs[] = {pk_x, pk_y, witness.rx_, witness.ry_, witness.rx_,
                     witness.ry_};
  Elt z;
  for (size_t i = 0; i < 3; ++i) {
    ec.addE(witness.pre_[2 * i], witness.pre_[2 * i + 1], z, lhs[2 * i],
            lhs[2 * i + 1], one, rhs[2 * i], rhs[2 * i + 1], one);
    if (z != field.zero()) field.invert(z);
    field.mul(witness.pre_[2 * i], z);
    field.mul(witness.pre_[2 * i + 1], z);
  }
  ec.addE(witness.pre_[6], witness.pre_[7], z, witness.pre_[2], witness.pre_[3],
          one, pk_x, pk_y, one);
  if (z != field.zero()) field.invert(z);
  field.mul(witness.pre_[6], z);
  field.mul(witness.pre_[7], z);

  Elt ax = field.zero(), ay = one, az = field.zero();
  size_t choices[EC::kBits];
  for (size_t i = 0; i < EC::kBits; ++i) {
    choices[i] = e.bit(EC::kBits - i - 1) + 2 * r.bit(EC::kBits - i - 1) +
                 4 * native_minus_s.bit(EC::kBits - i - 1);
    witness.bi_[i] = field.subf(field.of_scalar(2 * choices[i]), field.of_scalar(7));
    if (i > 0) ec.doubleE(ax, ay, az, ax, ay, az);
    switch (choices[i]) {
      case 0: ec.addE(ax, ay, az, ax, ay, az, field.zero(), field.one(), field.zero()); break;
      case 1: ec.addE(ax, ay, az, ax, ay, az, gx, gy, one); break;
      case 2: ec.addE(ax, ay, az, ax, ay, az, pk_x, pk_y, one); break;
      case 3: ec.addE(ax, ay, az, ax, ay, az, witness.pre_[0], witness.pre_[1], one); break;
      case 4: ec.addE(ax, ay, az, ax, ay, az, witness.rx_, witness.ry_, one); break;
      case 5: ec.addE(ax, ay, az, ax, ay, az, witness.pre_[2], witness.pre_[3], one); break;
      case 6: ec.addE(ax, ay, az, ax, ay, az, witness.pre_[4], witness.pre_[5], one); break;
      case 7: ec.addE(ax, ay, az, ax, ay, az, witness.pre_[6], witness.pre_[7], one); break;
    }
    witness.int_x_[i] = ax;
    witness.int_y_[i] = ay;
    witness.int_z_[i] = az;
  }
  return ax == field.zero() && az == field.zero();
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_EVALUATE_H_
