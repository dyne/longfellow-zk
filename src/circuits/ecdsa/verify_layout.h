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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_LAYOUT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_LAYOUT_H_

#include "arrays/dense.h"
#include "circuits/ecdsa/verify_types.h"

namespace proofs {

// This is the compatibility boundary for ECDSA advice.  Keep these loops in
// lockstep with the historical order: protocol witness bytes depend on it.
template <class EC>
constexpr size_t kVerifyWitnessLayoutElements =
    5 + 8 + EC::kBits + 3 * (EC::kBits - 1);

template <class Field, class EC>
void FillVerifyWitnessLayout(const VerifyWitnessData<EC>& witness,
                             DenseFiller<Field>& filler) {
  filler.push_back(witness.rx_);
  filler.push_back(witness.ry_);
  filler.push_back(witness.rx_inv_);
  filler.push_back(witness.s_inv_);
  filler.push_back(witness.pk_inv_);
  for (size_t i = 0; i < 8; ++i) filler.push_back(witness.pre_[i]);
  for (size_t i = 0; i < EC::kBits; ++i) {
    filler.push_back(witness.bi_[i]);
    if (i < EC::kBits - 1) {
      filler.push_back(witness.int_x_[i]);
      filler.push_back(witness.int_y_[i]);
      filler.push_back(witness.int_z_[i]);
    }
  }
}

template <class LogicCircuit, class EC>
void VerifyCircuitWitness<LogicCircuit, EC>::input(const LogicCircuit& lc) {
  rx = lc.eltw_input();
  ry = lc.eltw_input();
  rx_inv = lc.eltw_input();
  s_inv = lc.eltw_input();
  pk_inv = lc.eltw_input();
  for (size_t i = 0; i < 8; ++i) pre[i] = lc.eltw_input();
  for (size_t i = 0; i < kBits; ++i) {
    bi[i] = lc.eltw_input();
    if (i < kBits - 1) {
      int_x[i] = lc.eltw_input();
      int_y[i] = lc.eltw_input();
      int_z[i] = lc.eltw_input();
    }
  }
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_LAYOUT_H_
