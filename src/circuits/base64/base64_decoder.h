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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_BASE64_DECODE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_BASE64_DECODE_H_

#include <cstddef>
#include <vector>

#include "util/ceildiv.h"
#include "util/panic.h"

namespace proofs {

// This class implements a circuit to assert a base64 url decoding.
// A string in base64 consists of the characters A-Z a-z 0-9 - _ and =.
// 0--25 are mapped to A-Z, 26--51 are mapped to a-z, 52--61 are mapped to 0-9,
// and 62--63 are mapped to - and _ respectively.
// The base64 encoding is padded with = to a multiple of 4.
template <class LogicCircuit>
class Base64Decoder {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using v6 = typename LogicCircuit::template bitvec<6>;

 public:
  explicit Base64Decoder(const LogicCircuit& lc) : lc_(lc) {}

  void base64_rawurl_decode(const v8 inputs[/*n*/],
                            v8 output[/* ceil(n*6/8) */], size_t n) const {
    check(n < (1 << 28), "input too large");  // avoid overflows
    v6 zero = lc_.template vbit<6>(0);

    size_t max = ceildiv<size_t>(n * 6, 8);
    size_t oc = 0;

    for (size_t i = 0; i < n; i += 4, oc += 3) {
      v6 quad[4]{v6(zero), v6(zero), v6(zero), v6(zero)};
      for (size_t j = 0; j < 4 && i + j < n; ++j) {
        decode(inputs[i + j], quad[j]);
      }
      // repack
      for (size_t j = 0; j < 24 && (oc + j / 8) < max; ++j) {
        output[oc + j / 8][7 - (j % 8)] = quad[j / 6][5 - (j % 6)];
      }
    }
  }

  template <size_t N>
  void base64_rawurl_decode_len(
      const v8 inputs[/*n*/], v8 output[/* ceil(n*6/8) */], size_t n,
      typename LogicCircuit::template bitvec<N>& len) const {
    check(n < (1 << 28), "input too large");  // avoid overflows
    v6 zero = lc_.template vbit<6>(0);

    size_t max = ceildiv<size_t>(n * 6, 8);
    size_t oc = 0;

    for (size_t i = 0; i < n; i += 4, oc += 3) {
      v6 quad[4]{v6(zero), v6(zero), v6(zero), v6(zero)};
      BitW invalid;
      for (size_t j = 0; j < 4 && i + j < n; ++j) {
        decode(inputs[i + j], quad[j], invalid);
        auto range = lc_.vlt(i + j, len);
        lc_.assert_implies(range, lc_.lnot(invalid));
      }
      // repack
      for (size_t j = 0; j < 24 && (oc + j / 8) < max; ++j) {
        output[oc + j / 8][7 - (j % 8)] = quad[j / 6][5 - (j % 6)];
      }
    }
  }

  void decode(const v8& in, v6& out) const {
    BitW invalid;
    decode(in, out, invalid);
    lc_.assert0(invalid);
  }

  void decode(const v8& in, v6& out, BitW& invalid) const {
    v8 ni;
    for (size_t i = 0; i < 8; ++i) {
      ni[i] = lc_.lnot(in[i]);
    }
    std::vector<std::vector<BitW> > exp[] = {
        {
            //  ['!v4', '!v3', '!v2', '!v1', '!v0']
            {
                ni[4],
                ni[3],
                ni[2],
                ni[1],
                ni[0],
            },
            //  ['v4', 'v3', '!v2', 'v1', 'v0']
            {
                in[4],
                in[3],
                ni[2],
                in[1],
                in[0],
            },
            //  ['v5', 'v4', 'v3', 'v1', 'v0']
            {
                in[5],
                in[4],
                in[3],
                in[1],
                in[0],
            },
            //  ['!v6', 'v3', 'v2', '!v0']
            {
                ni[6],
                in[3],
                in[2],
                ni[0],
            },
            //  ['v4', 'v3', 'v2', '!v1']
            {
                in[4],
                in[3],
                in[2],
                ni[1],
            },
            //  ['v4', 'v3', 'v2', '!v0']
            {
                in[4],
                in[3],
                in[2],
                ni[0],
            },
            //  ['!v6', '!v4', '!v3']
            {
                ni[6],
                ni[4],
                ni[3],
            },
            //  ['!v6', '!v4', '!v2']
            {
                ni[6],
                ni[4],
                ni[2],
            },
            //  ['!v6', 'v3', 'v1']
            {
                ni[6],
                in[3],
                in[1],
            },
            //  ['!v6', '!v5']
            {
                ni[6],
                ni[5],
            },
            //  ['v7']
            {
                in[7],
            },
        },
        {
            //  ['v6', 'v5', 'v4', '!v3', '!v2']
            {
                in[6],
                in[5],
                in[4],
                ni[3],
                ni[2],
            },
            //  ['v6', 'v5', 'v4', '!v3', '!v0']
            {
                in[6],
                in[5],
                in[4],
                ni[3],
                ni[0],
            },
            //  ['v6', 'v5', 'v4', 'v2', '!v1']
            {
                in[6],
                in[5],
                in[4],
                in[2],
                ni[1],
            },
            //  ['v5', 'v2', 'v1', 'v0']
            {
                in[5],
                in[2],
                in[1],
                in[0],
            },
            //  ['v4', 'v3', 'v1', 'v0']
            {
                in[4],
                in[3],
                in[1],
                in[0],
            },
            //  ['v5', 'v3']
            {
                in[5],
                in[3],
            },
            //  ['!v6', '!v2']
            {
                ni[6],
                ni[2],
            },
            //  ['!v6', 'v2']
            {
                ni[6],
                in[2],
            },
        },
        {
            //  ['v5', '!v4', '!v3', '!v1']
            {
                in[5],
                ni[4],
                ni[3],
                ni[1],
            },
            //  ['v5', '!v4', '!v3', '!v2']
            {
                in[5],
                ni[4],
                ni[3],
                ni[2],
            },
            //  ['!v5', 'v4', 'v1']
            {
                ni[5],
                in[4],
                in[1],
            },
            //  ['v5', '!v4', '!v3', '!v0']
            {
                in[5],
                ni[4],
                ni[3],
                ni[0],
            },
            //  ['v4', 'v2', 'v1', 'v0']
            {
                in[4],
                in[2],
                in[1],
                in[0],
            },
            //  ['!v5', 'v4', 'v0']
            {
                ni[5],
                in[4],
                in[0],
            },
            //  ['!v5', 'v4', 'v2']
            {
                ni[5],
                in[4],
                in[2],
            },
            //  ['v4', 'v3']
            {
                in[4],
                in[3],
            },
            //  ['!v6', '!v2']
            {
                ni[6],
                ni[2],
            },
            //  ['!v6', 'v2']
            {
                ni[6],
                in[2],
            },
        },
        {
            //  ['v6', '!v3', '!v2', '!v1', '!v0']
            {
                in[6],
                ni[3],
                ni[2],
                ni[1],
                ni[0],
            },
            //  ['v6', 'v5', 'v4', '!v3', '!v2']
            {
                in[6],
                in[5],
                in[4],
                ni[3],
                ni[2],
            },
            //  ['v6', 'v5', 'v4', '!v3', '!v0']
            {
                in[6],
                in[5],
                in[4],
                ni[3],
                ni[0],
            },
            //  ['v6', 'v5', 'v4', 'v2', '!v1']
            {
                in[6],
                in[5],
                in[4],
                in[2],
                ni[1],
            },
            //  ['v5', '!v4', '!v3', '!v1']
            {
                in[5],
                ni[4],
                ni[3],
                ni[1],
            },
            //  ['v5', '!v4', '!v3', '!v2']
            {
                in[5],
                ni[4],
                ni[3],
                ni[2],
            },
            //  ['v5', '!v4', '!v3', '!v0']
            {
                in[5],
                ni[4],
                ni[3],
                ni[0],
            },
            //  ['!v5', 'v3', 'v1']
            {
                ni[5],
                in[3],
                in[1],
            },
            //  ['v3', 'v2', 'v1', 'v0']
            {
                in[3],
                in[2],
                in[1],
                in[0],
            },
            //  ['!v5', 'v3', 'v0']
            {
                ni[5],
                in[3],
                in[0],
            },
            //  ['!v5', 'v3', 'v2']
            {
                ni[5],
                in[3],
                in[2],
            },
            //  ['!v6', 'v3']
            {
                ni[6],
                in[3],
            },
            //  ['!v6', 'v2']
            {
                ni[6],
                in[2],
            },
        },
        {
            //  ['v5', '!v4', 'v2', '!v1', 'v0']
            {
                in[5],
                ni[4],
                in[2],
                ni[1],
                in[0],
            },
            //  ['v6', 'v5', 'v4', 'v2', '!v1']
            {
                in[6],
                in[5],
                in[4],
                in[2],
                ni[1],
            },
            //  ['!v5', '!v2', '!v1', '!v0']
            {
                ni[5],
                ni[2],
                ni[1],
                ni[0],
            },
            //  ['v6', 'v5', 'v2', '!v0']
            {
                in[6],
                in[5],
                in[2],
                ni[0],
            },
            //  ['v5', '!v2', 'v1', 'v0']
            {
                in[5],
                ni[2],
                in[1],
                in[0],
            },
            //  ['!v5', 'v2', 'v0']
            {
                ni[5],
                in[2],
                in[0],
            },
            //  ['!v5', 'v2', 'v1']
            {
                ni[5],
                in[2],
                in[1],
            },
            //  ['!v6', '!v2']
            {
                ni[6],
                ni[2],
            },
        },
        {
            //  ['v5', '!v4', 'v2', '!v1', 'v0']
            {
                in[5],
                ni[4],
                in[2],
                ni[1],
                in[0],
            },
            //  ['v6', 'v5', '!v1', 'v0']
            {
                in[6],
                in[5],
                ni[1],
                in[0],
            },
            //  ['!v5', '!v1', '!v0']
            {
                ni[5],
                ni[1],
                ni[0],
            },
            //  ['!v5', 'v1', 'v0']
            {
                ni[5],
                in[1],
                in[0],
            },
            //  ['v5', 'v1', '!v0']
            {
                in[5],
                in[1],
                ni[0],
            },
            //  ['!v6', 'v1']
            {
                ni[6],
                in[1],
            },
        },
        {
            //  ['v4', 'v3', 'v1', 'v0']
            {
                in[4],
                in[3],
                in[1],
                in[0],
            },
            //  ['!v6', 'v4', 'v0']
            {
                ni[6],
                in[4],
                in[0],
            },
            //  ['v6', '!v0']
            {
                in[6],
                ni[0],
            },
        },
    };
    invalid = lc_.or_of_and(exp[0]);
    for (size_t i = 0; i < 6; ++i) {
      out[5 - i] = lc_.or_of_and(exp[i + 1]);
    }
  }

 private:
  const LogicCircuit& lc_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_BASE64_DECODE_H_
