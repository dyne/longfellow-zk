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
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_RIPEMD160_RIPEMD160_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_RIPEMD160_RIPEMD160_CIRCUIT_H_

#include <array>
#include <cstdint>

namespace proofs {

// A direct Boolean circuit for one RIPEMD-160 compression block.  Unlike the
// SHA gadget this deliberately derives all rounds, so no native trace is a
// soundness input.  The caller is responsible for fixing the 64 input bytes.
template <class Logic>
class Ripemd160Circuit {
 public:
  using v8 = typename Logic::v8;
  using v32 = typename Logic::v32;
  explicit Ripemd160Circuit(const Logic& logic) : l_(logic) {}

  std::array<v32, 5> compress(const std::array<v8, 64>& bytes) const {
    static constexpr uint8_t r[80] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
    static constexpr uint8_t rr[80] = {5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
    static constexpr uint8_t s[80] = {11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
    static constexpr uint8_t ss[80] = {8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
    std::array<v32, 16> x;
    for (size_t i = 0; i < 16; ++i) x[i] = l_.vappend(l_.vappend(bytes[4*i], bytes[4*i+1]), l_.vappend(bytes[4*i+2], bytes[4*i+3]));
    v32 al=l_.template vbit<32>(0x67452301u), bl=l_.template vbit<32>(0xefcdab89u), cl=l_.template vbit<32>(0x98badcfeu), dl=l_.template vbit<32>(0x10325476u), el=l_.template vbit<32>(0xc3d2e1f0u);
    v32 ar=l_.template vbit<32>(0x67452301u), br=l_.template vbit<32>(0xefcdab89u), cr=l_.template vbit<32>(0x98badcfeu), dr=l_.template vbit<32>(0x10325476u), er=l_.template vbit<32>(0xc3d2e1f0u);
    for (unsigned j = 0; j < 80; ++j) {
      const v32 t = l_.vadd(l_.vrotr(sum(al, f(j, bl, cl, dl), x[r[j]], k(j)), 32-s[j]), el);
      al=el; el=dl; dl=l_.vrotr(cl,22); cl=bl; bl=t;
      const v32 tt = l_.vadd(l_.vrotr(sum(ar, f(79-j, br, cr, dr), x[rr[j]], kk(j)), 32-ss[j]), er);
      ar=er; er=dr; dr=l_.vrotr(cr,22); cr=br; br=tt;
    }
    return {l_.vadd(l_.vadd(l_.template vbit<32>(0xefcdab89u), cl), dr),
            l_.vadd(l_.vadd(l_.template vbit<32>(0x98badcfeu), dl), er),
            l_.vadd(l_.vadd(l_.template vbit<32>(0x10325476u), el), ar),
            l_.vadd(l_.vadd(l_.template vbit<32>(0xc3d2e1f0u), al), br),
            l_.vadd(l_.vadd(l_.template vbit<32>(0x67452301u), bl), cr)};
  }
 private:
  v32 sum(const v32& a, const v32& b, const v32& c, uint32_t d) const { return l_.vadd(l_.vadd(l_.vadd(a,b),c),d); }
  v32 f(unsigned round, const v32& x, const v32& y, const v32& z) const {
    if (round < 16) return l_.vxor3(x,y,z);
    if (round < 32) return l_.vCh(x,y,z);
    if (round < 48) return l_.vxor(l_.vor(x,l_.vnot(y)),z);
    if (round < 64) return l_.vCh(z,x,y);
    return l_.vxor(x,l_.vor(y,l_.vnot(z)));
  }
  static uint32_t k(unsigned r) { static constexpr uint32_t v[] = {0,0x5a827999u,0x6ed9eba1u,0x8f1bbcdcu,0xa953fd4eu}; return v[r/16]; }
  static uint32_t kk(unsigned r) { static constexpr uint32_t v[] = {0x50a28be6u,0x5c4dd124u,0x6d703ef3u,0x7a6d76e9u,0}; return v[r/16]; }
  const Logic& l_;
};
}  // namespace proofs
#endif
