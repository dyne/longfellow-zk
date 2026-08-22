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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_WITNESS_H_

#include "circuits/ecdsa/verify_evaluate.h"
#include "circuits/ecdsa/verify_layout.h"

namespace proofs {

// Compatibility facade for ECDSA's native advice. Storage, wire layout, and
// native evaluation each have an explicit, independently testable boundary.
template <class EC, class ScalarField>
class VerifyWitness3 : public VerifyWitnessData<EC> {
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;

 public:
  constexpr static size_t kBits = EC::kBits;
  const ScalarField& fn_;
  const EC& ec_;

  VerifyWitness3(const ScalarField& scalar_field, const EC& ec)
      : fn_(scalar_field), ec_(ec) {}

  void fill_witness(DenseFiller<Field>& filler) const {
    FillVerifyWitnessLayout<Field>(*this, filler);
  }

  // Produces advice for id = g*e + pk*r + (rx,ry)*-s. Existing mdoc callers
  // retain this facade while the derivation remains isolated in evaluate.h.
  bool compute_witness(const Elt pk_x, const Elt pk_y, const Nat e,
                       const Nat r, const Nat s) {
    return EvaluateVerifyWitness(*this, fn_, ec_, pk_x, pk_y, e, r, s);
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_ECDSA_VERIFY_WITNESS_H_
