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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BIP340_BIP340_VERIFY_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BIP340_BIP340_VERIFY_H_

#include <stddef.h>

#include "circuits/secp256k1/ec_gadget.h"

namespace proofs {

/// Production BIP-340 / Schnorr signature verification over secp256k1.
///
///   s*G = R + e*P
///
/// --- In-circuit (proven) ---
///
/// Public field inputs, in order: rx, px, e.
///   rx : R.x (x-only, 32 bytes after BIP-340 parse).
///   px : P.x (x-only public key).
///   e  : Fiat-Shamir challenge scalar (field element).
///
/// Private witness: bits_s[256], int_s_{x,y,z}[255] for s*G;
///   bits_e[256], int_e_{x,y,z}[255] for e*P;
///   py (P.y, the even square root);
///   ry (affine R.y); rz_inv (R.z inverse); ry_bits[256].
///
/// Circuit constraints:
///   - e is reconstructed from bits_e[256] (MSB-first).
///   - s is range-checked as a scalar: 0 <= s < n.
///   - py^2 = px^3 + 7  (P is on the secp256k1 curve).
///   - ry^2 = rx^3 + 7  (R is on the secp256k1 curve).
///   - Double-and-add trace for s*G with intermediate witnesses.
///   - Double-and-add trace for e*P with intermediate witnesses.
///   - R = s*G - e*P computed in projective coordinates.
///   - R.z * rz_inv = 1  (R is not the point at infinity).
///   - R.x = rx  (projective equality: R.x * 1 == rx * R.z).
///   - R.y = ry  (projective equality; ry is the affine y).
///   - ry is canonically even: ry_bits[255] (LSB) = 0, and
///     ry reconstructed from ry_bits[256] matches ry.
///   - Each ry_bits[i] in {0,1}.
///
/// --- Outside the circuit (witness/verifier validation) ---
///
/// Witness generation checks before building the circuit:
///   - Byte-length validation: sig 64 bytes, pk 32 bytes.
///   - rx < p, s < n, px < p.
///   - px is liftable (curve point exists with even y).
///   - e is computed from BIP-340 tagged SHA-256 hash.
///
/// Tagged SHA-256 is deliberately NOT proven in this circuit.
/// The circuit proves the algebraic BIP-340 relation given a
/// public challenge value e.  The binding between e and the
/// message / public key is established by the verifier's own
/// hash computation outside the proof system.
template <class LogicCircuit, class Field, class EC>
class Bip340Verify {
  using EltW = typename LogicCircuit::EltW;
  using Elt = typename LogicCircuit::Elt;
  using EcGadget = Secp256k1EcGadget<LogicCircuit, EC>;
  static constexpr size_t kBits = EC::kBits;

 public:
  struct Witness {
    typename EcGadget::ScalarMultWitness s_mult;
    typename EcGadget::ScalarMultWitness e_mult;

    EltW py;          // affine P.y (the even square root)
    EltW ry;          // affine R.y (witnessed even value)
    EltW rz_inv;      // inverse of R.z (proves R finite)
    EltW bits_ry[kBits];  // affine ry bits, MSB-first

    void input(const LogicCircuit& lc) {
      s_mult.input(lc);
      e_mult.input(lc);
      py = lc.eltw_input();
      ry = lc.eltw_input();
      rz_inv = lc.eltw_input();
      for (size_t i = 0; i < kBits; ++i) {
        bits_ry[i] = lc.eltw_input();
      }
    }
  };

  Bip340Verify(const LogicCircuit& lc, const EC& ec) : lc_(lc), ec_(ec) {}

  /// Verify the BIP-340 relation: s*G - e*P = R, with R.x == rx.
  ///
  /// rx: x-coordinate of R (public, x-only)
  /// px: x-coordinate of P (public, x-only public key)
  /// e:  Fiat-Shamir challenge (public scalar, field element)
  /// w:  witness containing bits of s and e, intermediate points, and py
  void assert_verify(EltW rx, EltW px, EltW e, const Witness& w) const {
    EcGadget gadget(lc_, ec_);
    EltW zero = lc_.konst(lc_.zero());
    EltW one = lc_.konst(lc_.one());

    // -- 0. Verify e matches bits_e decomposition ------------------------
    // e must equal sum_i bits_e[i] * 2^(kBits-1-i), i.e., the scalar
    // represented by the bits in MSB-first order.
    {
      EltW check = lc_.konst(lc_.zero());
      EltW pow = lc_.konst(lc_.one());  // 2^0
      for (int i = static_cast<int>(kBits) - 1; i >= 0; --i) {
        check = lc_.add(check, lc_.mul(w.e_mult.bits[i], pow));
        pow = lc_.add(pow, pow);  // pow *= 2
      }
      lc_.assert_eq(check, e);
    }

    // -- 1. Verify s is a canonical secp256k1 scalar ---------------------
    // The shared gadget converts this MSB-first multiplication trace to the
    // LSB-first convention required by Logic::vlt.
    gadget.assert_canonical_scalar(w.s_mult);

    // -- 2. Lift P: verify py^2 = px^3 + b (secp256k1: b = 7) --------------
    gadget.assert_point_on_curve(px, w.py);

    // -- 3. Compute s*G ---------------------------------------------------
    EltW gx = lc_.konst(ec_.gx_);
    EltW gy = lc_.konst(ec_.gy_);
    typename EcGadget::ProjectivePointW sG{zero, one, zero};
    gadget.scalar_mult(sG, {gx, gy, one}, w.s_mult, false);

    // -- 4. Compute e*P  (P = (px, py, 1)) -------------------------------
    typename EcGadget::ProjectivePointW eP{zero, one, zero};
    gadget.scalar_mult(eP, {px, w.py, one}, w.e_mult);

    // -- 5. Compute R = sG - eP = sG + (-eP) ------------------------------
    typename EcGadget::ProjectivePointW R;
    eP.y = lc_.sub(zero, eP.y);
    gadget.addE(R, sG, eP);

    // -- 6. Verify R is on the curve and finite --------------------------
    gadget.assert_point_on_curve(rx, w.ry);

    // R.z * rz_inv = 1  <=>  R is not the point at infinity.
    lc_.assert_eq(lc_.mul(R.z, w.rz_inv), one);

    // -- 7. Check R.x == rx (projective) ---------------------------------
    lc_.assert_eq(R.x, lc_.mul(rx, R.z));   // R.x * 1 == rx * R.z

    // -- 8. Check R.y == ry (projective) ---------------------------------
    lc_.assert_eq(R.y, lc_.mul(w.ry, R.z));  // R.y * 1 == ry * R.z

    // -- 9. Verify ry bitness and even parity ----------------------------
    // bits_ry[0] is MSB, bits_ry[kBits-1] is LSB.
    EltW ry_check = lc_.konst(lc_.zero());
    for (size_t i = 0; i < kBits; ++i) {
      typename LogicCircuit::BitW b_bit(w.bits_ry[i], lc_.f_);
      lc_.assert_is_bit(b_bit);
      ry_check = lc_.add(ry_check, ry_check);  // ry_check *= 2
      ry_check = lc_.add(ry_check, w.bits_ry[i]);
    }
    lc_.assert_eq(ry_check, w.ry);

    // Assert LSB is zero (bits_ry[255] in MSB-first order).
    lc_.assert_eq(w.bits_ry[kBits - 1], zero);
  }

 private:
  const LogicCircuit& lc_;
  const EC& ec_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BIP340_BIP340_VERIFY_H_
