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
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_AFFINE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SECP256K1_AFFINE_H_

namespace proofs {

// An explicitly witnessed affine representative of a complete-projective
// point.  The equations below use the repository convention x=X/Z, y=Y/Z.
template <class LogicCircuit, class EcGadget>
class Secp256k1Affine {
 public:
  using EltW = typename LogicCircuit::EltW;
  struct Witness {
    EltW z_inv;
    EltW x;
    EltW y;
    void input(const LogicCircuit& lc) { z_inv = lc.eltw_input(); x = lc.eltw_input(); y = lc.eltw_input(); }
  };

  Secp256k1Affine(const LogicCircuit& lc, const EcGadget& ec) : lc_(lc), ec_(ec) {}

  void assert_normalized(const typename EcGadget::ProjectivePointW& point,
                         const Witness& witness) const {
    const EltW one = lc_.konst(lc_.one());
    // This proves finiteness, then binds both affine coordinates to the
    // scalar-multiplication result rather than to an independently chosen point.
    lc_.assert_eq(lc_.mul(point.z, witness.z_inv), one);
    lc_.assert_eq(point.x, lc_.mul(witness.x, point.z));
    lc_.assert_eq(point.y, lc_.mul(witness.y, point.z));
    ec_.assert_point_on_curve(witness.x, witness.y);
  }

 private:
  const LogicCircuit& lc_;
  const EcGadget& ec_;
};
}  // namespace proofs
#endif
