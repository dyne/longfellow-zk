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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_TYPES_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_TYPES_H_

#include <cstddef>

namespace proofs {

// Native advice for the triple-scalar ECDSA relation.  This is deliberately a
// data-only type: verify_layout.h owns its wire order and verify_evaluate.h
// owns how each intermediate value is derived.
template <class EC>
struct VerifyWitnessData {
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  static constexpr size_t kBits = EC::kBits;

  Elt rx_, ry_;
  Elt rx_inv_;
  Elt s_inv_;
  Elt pk_inv_;
  Elt pre_[8];
  Elt bi_[kBits];
  Elt int_x_[kBits];
  Elt int_y_[kBits];
  Elt int_z_[kBits];
};

// Circuit-side counterpart of VerifyWitnessData.  Its input order is kept in
// verify_layout.h so relation code cannot silently change witness allocation.
template <class LogicCircuit, class EC>
struct VerifyCircuitWitness {
  using EltW = typename LogicCircuit::EltW;
  static constexpr size_t kBits = EC::kBits;

  EltW rx, ry;
  EltW pre[8];
  EltW rx_inv, s_inv, pk_inv;
  EltW bi[kBits];
  EltW int_x[kBits - 1];
  EltW int_y[kBits - 1];
  EltW int_z[kBits - 1];

  void input(const LogicCircuit& lc);
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_TYPES_H_
