// Copyright 2026 Google LLC.

#include <cstddef>

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"

namespace {

using Field = proofs::Fp256Base;
using EC = proofs::P256;
using Backend = proofs::EvaluationBackend<Field>;
using LogicCircuit = proofs::Logic<Field, Backend>;
using Relation = proofs::VerifyCircuit<LogicCircuit, Field, EC>;
using NativeWitness = proofs::VerifyWitness3<EC, proofs::Fp256Scalar>;

struct Fixture {
  Field::N e{7};
  Field::N r;
  Field::N s;
  Field::Elt pk_x;
  Field::Elt pk_y;
};

Fixture MakeFixture() {
  auto public_key = proofs::p256.scalar_multf(proofs::p256.generator(), Field::N(3));
  proofs::p256.normalize(public_key);
  auto nonce_point = proofs::p256.scalar_multf(proofs::p256.generator(), Field::N(5));
  proofs::p256.normalize(nonce_point);
  const Field::N r = proofs::p256_base.from_montgomery(nonce_point.x);
  const auto scalar_r = proofs::p256_scalar.to_montgomery(r);
  const auto numerator = proofs::p256_scalar.addf(
      proofs::p256_scalar.to_montgomery(Field::N(7)),
      proofs::p256_scalar.mulf(
          scalar_r, proofs::p256_scalar.to_montgomery(Field::N(3))));
  const auto s = proofs::p256_scalar.from_montgomery(
      proofs::p256_scalar.mulf(
          numerator,
          proofs::p256_scalar.invertf(
              proofs::p256_scalar.to_montgomery(Field::N(5)))));
  return {Field::N(7), r, s, public_key.x, public_key.y};
}

Relation::Witness ToCircuitWitness(const LogicCircuit& circuit,
                                   const NativeWitness& native) {
  Relation::Witness witness;
  witness.rx = circuit.konst(native.rx_);
  witness.ry = circuit.konst(native.ry_);
  witness.rx_inv = circuit.konst(native.rx_inv_);
  witness.s_inv = circuit.konst(native.s_inv_);
  witness.pk_inv = circuit.konst(native.pk_inv_);
  for (size_t i = 0; i < 8; ++i) witness.pre[i] = circuit.konst(native.pre_[i]);
  for (size_t i = 0; i < EC::kBits; ++i) {
    witness.bi[i] = circuit.konst(native.bi_[i]);
    if (i < EC::kBits - 1) {
      witness.int_x[i] = circuit.konst(native.int_x_[i]);
      witness.int_y[i] = circuit.konst(native.int_y_[i]);
      witness.int_z[i] = circuit.konst(native.int_z_[i]);
    }
  }
  return witness;
}

bool CheckRelation(bool corrupt) {
  const Fixture fixture = MakeFixture();
  NativeWitness native(proofs::p256_scalar, proofs::p256);
  if (!native.compute_witness(fixture.pk_x, fixture.pk_y, fixture.e,
                              fixture.r, fixture.s)) {
    return false;
  }
  if (corrupt) {
    native.int_x_[17] =
        proofs::p256_base.addf(native.int_x_[17], proofs::p256_base.one());
  }

  const Backend backend(proofs::p256_base, false);
  const LogicCircuit logic(&backend, proofs::p256_base);
  const Relation relation(logic, proofs::p256, proofs::n256_order);
  const auto witness = ToCircuitWitness(logic, native);
  relation.verify_signature3(
      logic.konst(fixture.pk_x), logic.konst(fixture.pk_y),
      logic.konst(proofs::p256_base.to_montgomery(fixture.e)), witness);
  return backend.assertion_failed() == corrupt;
}

}  // namespace

extern "C" int longfellow_zk_ecdsa_wasi_verify() {
  if (!CheckRelation(false)) return 1;
  if (!CheckRelation(true)) return 2;
  return 0;
}
