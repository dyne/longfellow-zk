// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_KEY_OWNERSHIP_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_KEY_OWNERSHIP_H_

#include "circuits/secp256k1/affine.h"
#include "circuits/secp256k1/encoding.h"
#include "circuits/secp256k1/ec_gadget.h"

namespace proofs {
// Private-key relation only.  It intentionally has no public-key getter and
// does not serialize keys or proofs; later BlindZap layers own those APIs.
template <class LogicCircuit, class Field, class EC>
class KeyOwnershipCircuit {
  using EltW = typename LogicCircuit::EltW;
  using EcGadget = Secp256k1EcGadget<LogicCircuit, EC>;
  using Affine = Secp256k1Affine<LogicCircuit, EcGadget>;
  using Encoding = Secp256k1Encoding<LogicCircuit, EC>;
 public:
  struct Witness {
    EltW scalar;
    EltW scalar_inverse;
    typename EcGadget::ScalarMultWitness scalar_mult;
    typename Affine::Witness affine;
    typename Encoding::CoordinateWitness x;
    typename Encoding::CoordinateWitness y;
    void input(const LogicCircuit& lc) {
      scalar = lc.eltw_input(); scalar_inverse = lc.eltw_input();
      scalar_mult.input(lc); affine.input(lc); x.input(lc); y.input(lc);
    }
  };
  using CompressedKey = typename Encoding::CompressedKey;
  KeyOwnershipCircuit(const LogicCircuit& lc, const EC& ec) : lc_(lc), ec_(ec) {}
  CompressedKey derive(const Witness& witness) const {
    EcGadget gadget(lc_, ec_); Affine affine(lc_, gadget); Encoding encoding(lc_);
    gadget.assert_canonical_scalar(witness.scalar_mult);
    gadget.assert_scalar_matches(witness.scalar, witness.scalar_mult);
    gadget.assert_nonzero_scalar(witness.scalar, witness.scalar_inverse);
    typename EcGadget::ProjectivePointW result;
    const EltW one = lc_.konst(lc_.one());
    gadget.scalar_mult(result, {lc_.konst(ec_.gx_), lc_.konst(ec_.gy_), one}, witness.scalar_mult, false);
    affine.assert_normalized(result, witness.affine);
    encoding.assert_canonical(witness.affine.x, witness.x);
    encoding.assert_canonical(witness.affine.y, witness.y);
    return encoding.compressed(witness.x, witness.y);
  }
 private:
  const LogicCircuit& lc_; const EC& ec_;
};
}  // namespace proofs
#endif
