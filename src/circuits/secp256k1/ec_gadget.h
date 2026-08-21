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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_EC_GADGET_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_EC_GADGET_H_

#include <cstddef>

namespace proofs {

/// Complete projective secp256k1 formulas and their witnessed scalar trace.
/// Scalar bits and trace entries are deliberately MSB-first to match the
/// BIP-340 witness layout.
template <class LogicCircuit, class EC>
class Secp256k1EcGadget {
  using EltW = typename LogicCircuit::EltW;
  static constexpr size_t kBits = EC::kBits;

 public:
  struct ProjectivePointW {
    EltW x;
    EltW y;
    EltW z;
  };

  struct ScalarMultWitness {
    EltW bits[kBits];
    EltW int_x[kBits];
    EltW int_y[kBits];
    EltW int_z[kBits];

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kBits; ++i) {
        bits[i] = lc.eltw_input();
        if (i < kBits - 1) {
          int_x[i] = lc.eltw_input();
          int_y[i] = lc.eltw_input();
          int_z[i] = lc.eltw_input();
        }
      }
    }
  };

  Secp256k1EcGadget(const LogicCircuit& lc, const EC& ec)
      : lc_(lc), ec_(ec), scalar_order_bits_(scalar_order_bits(lc)) {}

  /// Constrain an MSB-first scalar decomposition, its field reconstruction,
  /// and canonical secp256k1 order.  BIP-340 keeps its historic allow-zero
  /// relation; private-key clients call assert_nonzero_scalar separately.
  void assert_canonical_scalar(const ScalarMultWitness& witness) const {
    typename LogicCircuit::v256 lsb_first;
    for (size_t i = 0; i < kBits; ++i) {
      typename LogicCircuit::BitW bit(witness.bits[i], lc_.f_);
      lc_.assert_is_bit(bit);
      lsb_first[kBits - 1 - i] = bit;
    }
    lc_.assert1(lc_.vlt(lsb_first, scalar_order_bits_));
  }

  void assert_nonzero_scalar(EltW value, EltW inverse) const {
    lc_.assert_eq(lc_.mul(value, inverse), lc_.konst(lc_.one()));
  }

  void assert_scalar_matches(EltW value,
                             const ScalarMultWitness& witness) const {
    EltW reconstructed = lc_.konst(lc_.zero());
    for (size_t i = 0; i < kBits; ++i) {
      reconstructed = lc_.add(reconstructed, reconstructed);
      reconstructed = lc_.add(reconstructed, witness.bits[i]);
    }
    lc_.assert_eq(reconstructed, value);
  }

  void assert_point_on_curve(EltW x, EltW y) const {
    auto y2 = lc_.mul(y, y);
    auto x2 = lc_.mul(x, x);
    auto x3 = lc_.mul(x, x2);
    auto ax = lc_.mul(lc_.konst(ec_.a_), x);
    auto b = lc_.konst(ec_.b_);
    lc_.assert_eq(y2, lc_.add(lc_.add(x3, ax), b));
  }

  void scalar_mult(ProjectivePointW& result, ProjectivePointW point,
                   const ScalarMultWitness& witness,
                   bool assert_bits = true) const {
    EltW zero = lc_.konst(lc_.zero());
    EltW one = lc_.konst(lc_.one());
    ProjectivePointW accumulator{zero, one, zero};
    for (size_t i = 0; i < kBits; ++i) {
      typename LogicCircuit::BitW bit(witness.bits[i], lc_.f_);
      if (assert_bits) lc_.assert_is_bit(bit);
      ProjectivePointW selected{lc_.mux(bit, point.x, zero),
                                 lc_.mux(bit, point.y, one),
                                 lc_.mux(bit, point.z, zero)};
      doubleE(accumulator, accumulator);
      addE(accumulator, accumulator, selected);
      if (i < kBits - 1) {
        lc_.assert_eq(accumulator.x, witness.int_x[i]);
        lc_.assert_eq(accumulator.y, witness.int_y[i]);
        lc_.assert_eq(accumulator.z, witness.int_z[i]);
        accumulator = {witness.int_x[i], witness.int_y[i], witness.int_z[i]};
      }
    }
    result = accumulator;
  }

  void addE(ProjectivePointW& result, ProjectivePointW left,
            ProjectivePointW right) const {
    EltW t0 = lc_.mul(left.x, right.x);
    EltW t1 = lc_.mul(left.y, right.y);
    EltW t2 = lc_.mul(left.z, right.z);
    EltW t3 = lc_.mul(lc_.add(left.x, left.y), lc_.add(right.x, right.y));
    t3 = lc_.sub(t3, lc_.add(t0, t1));
    EltW t4 = lc_.mul(lc_.add(left.x, left.z), lc_.add(right.x, right.z));
    t4 = lc_.sub(t4, lc_.add(t0, t2));
    EltW t5 = lc_.mul(lc_.add(left.y, left.z), lc_.add(right.y, right.z));
    t5 = lc_.sub(t5, lc_.add(t1, t2));
    auto a = lc_.konst(ec_.a_);
    auto k3b = lc_.konst(ec_.k3b);
    EltW x3 = lc_.mul(k3b, t2);
    EltW z3 = lc_.add(x3, lc_.mul(a, t4));
    x3 = lc_.sub(t1, z3);
    z3 = lc_.add(t1, z3);
    EltW y3 = lc_.mul(x3, z3);
    t1 = lc_.add(lc_.add(t0, t0), t0);
    t2 = lc_.mul(a, t2);
    t4 = lc_.mul(k3b, t4);
    t1 = lc_.add(t1, t2);
    t2 = lc_.mul(a, lc_.sub(t0, t2));
    t4 = lc_.add(t4, t2);
    t0 = lc_.mul(t1, t4);
    y3 = lc_.add(y3, t0);
    x3 = lc_.sub(lc_.mul(t3, x3), lc_.mul(t5, t4));
    z3 = lc_.add(lc_.mul(t5, z3), lc_.mul(t3, t1));
    result = {x3, y3, z3};
  }

  void doubleE(ProjectivePointW& result, ProjectivePointW point) const {
    EltW t0 = lc_.mul(point.x, point.x);
    EltW t1 = lc_.mul(point.y, point.y);
    EltW t2 = lc_.mul(point.z, point.z);
    EltW t3 = lc_.add(lc_.mul(point.x, point.y), lc_.mul(point.x, point.y));
    EltW z3 = lc_.add(lc_.mul(point.x, point.z), lc_.mul(point.x, point.z));
    auto a = lc_.konst(ec_.a_);
    auto k3b = lc_.konst(ec_.k3b);
    EltW x3 = lc_.mul(a, z3);
    EltW y3 = lc_.add(x3, lc_.mul(k3b, t2));
    x3 = lc_.sub(t1, y3);
    y3 = lc_.mul(x3, lc_.add(t1, y3));
    x3 = lc_.mul(t3, x3);
    z3 = lc_.mul(k3b, z3);
    t2 = lc_.mul(a, t2);
    t3 = lc_.add(lc_.mul(a, lc_.sub(t0, t2)), z3);
    z3 = lc_.add(t0, t0);
    t0 = lc_.mul(lc_.add(lc_.add(z3, t0), t2), t3);
    y3 = lc_.add(y3, t0);
    t2 = lc_.add(lc_.mul(point.y, point.z), lc_.mul(point.y, point.z));
    x3 = lc_.sub(x3, lc_.mul(t2, t3));
    z3 = lc_.mul(t2, t1);
    z3 = lc_.add(z3, z3);
    z3 = lc_.add(z3, z3);
    result = {x3, y3, z3};
  }

 private:
  const LogicCircuit& lc_;
  const EC& ec_;
  typename LogicCircuit::v256 scalar_order_bits_;

  static typename LogicCircuit::v256 scalar_order_bits(const LogicCircuit& lc) {
    typename LogicCircuit::v256 result;
    typename EC::N order(
        "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    for (size_t i = 0; i < kBits; ++i) result[i] = lc.bit(order.bit(i));
    return result;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_EC_GADGET_H_
