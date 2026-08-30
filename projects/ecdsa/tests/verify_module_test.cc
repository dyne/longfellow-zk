// Copyright 2026 Google LLC.

#include <iostream>
#include <stdexcept>
#include <vector>

#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "proto/circuit_io.h"
#include "proto/circuit_writer.h"

namespace proofs {
namespace {
using Field = Fp256Base;
using EC = P256;
using Backend = EvaluationBackend<Field>;
using LogicCircuit = Logic<Field, Backend>;
using Relation = VerifyCircuit<LogicCircuit, Field, EC>;
using NativeWitness = VerifyWitness3<EC, Fp256Scalar>;
using CompileBackend = CompilerBackend<Field>;
using CompileLogic = Logic<Field, CompileBackend>;
using CompileRelation = VerifyCircuit<CompileLogic, Field, EC>;

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

struct Fixture {
  Field::N e{7};
  Field::N r;
  Field::N s;
  Field::Elt pk_x;
  Field::Elt pk_y;
};

Fixture MakeFixture() {
  auto public_key = p256.scalar_multf(p256.generator(), Field::N(3));
  p256.normalize(public_key);
  auto nonce_point = p256.scalar_multf(p256.generator(), Field::N(5));
  p256.normalize(nonce_point);
  const Field::N r = p256_base.from_montgomery(nonce_point.x);
  const auto scalar_r = p256_scalar.to_montgomery(r);
  const auto numerator = p256_scalar.addf(
      p256_scalar.to_montgomery(Field::N(7)),
      p256_scalar.mulf(scalar_r, p256_scalar.to_montgomery(Field::N(3))));
  const auto s = p256_scalar.from_montgomery(
      p256_scalar.mulf(numerator,
                        p256_scalar.invertf(p256_scalar.to_montgomery(Field::N(5)))));
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

void CheckRelation(bool corrupt) {
  const Fixture fixture = MakeFixture();
  NativeWitness native(p256_scalar, p256);
  Require(native.compute_witness(fixture.pk_x, fixture.pk_y, fixture.e,
                                 fixture.r, fixture.s),
          "native ECDSA evaluation rejected a valid signature");
  Dense<Field> serialized(1, kVerifyWitnessLayoutElements<EC>);
  DenseFiller<Field> filler(serialized);
  native.fill_witness(filler);
  Require(filler.size() == kVerifyWitnessLayoutElements<EC>,
          "native ECDSA witness layout length changed");
  Require(serialized.at(0) == native.rx_ && serialized.at(1) == native.ry_ &&
              serialized.at(5) == native.pre_[0] &&
              serialized.at(13) == native.bi_[0] &&
              serialized.at(14) == native.int_x_[0],
          "native ECDSA witness layout order changed");
  uint64_t witness_hash = 1469598103934665603ULL;
  uint8_t field_bytes[Field::kBytes];
  for (size_t i = 0; i < filler.size(); ++i) {
    p256_base.to_bytes_field(field_bytes, serialized.at(i));
    for (uint8_t byte : field_bytes) { witness_hash ^= byte; witness_hash *= 1099511628211ULL; }
  }
  Require(filler.size() * Field::kBytes == 33088 &&
              witness_hash == 12644743857867008985ULL,
          "ECDSA serialized witness bytes changed");
  if (corrupt) native.int_x_[17] = p256_base.addf(native.int_x_[17], p256_base.one());

  const Backend backend(p256_base, false);
  const LogicCircuit logic(&backend, p256_base);
  const Relation relation(logic, p256, n256_order);
  const auto witness = ToCircuitWitness(logic, native);
  relation.verify_signature3(logic.konst(fixture.pk_x), logic.konst(fixture.pk_y),
                             logic.konst(p256_base.to_montgomery(fixture.e)), witness);
  Require(backend.assertion_failed() == corrupt,
          corrupt ? "corrupt intermediate was accepted" : "valid relation failed");
}

void CheckCompactScalarBinding(bool splice_r, bool splice_negative_s) {
  const Fixture fixture = MakeFixture();
  NativeWitness native(p256_scalar, p256);
  Require(native.compute_witness(fixture.pk_x, fixture.pk_y, fixture.e,
                                 fixture.r, fixture.s),
          "native ECDSA evaluation rejected a valid signature");

  const Backend backend(p256_base, false);
  const LogicCircuit logic(&backend, p256_base);
  const Relation relation(logic, p256, n256_order);
  const auto witness = ToCircuitWitness(logic, native);

  auto expected_r = p256_base.to_montgomery(fixture.r);
  if (splice_r) expected_r = p256_base.addf(expected_r, p256_base.one());
  const auto negative_s = p256_scalar.from_montgomery(
      p256_scalar.negf(p256_scalar.to_montgomery(fixture.s)));
  auto expected_negative_s = p256_base.to_montgomery(negative_s);
  if (splice_negative_s) {
    expected_negative_s =
        p256_base.addf(expected_negative_s, p256_base.one());
  }
  relation.verify_signature3_bound(
      logic.konst(fixture.pk_x), logic.konst(fixture.pk_y),
      logic.konst(p256_base.to_montgomery(fixture.e)),
      logic.konst(expected_r), logic.konst(expected_negative_s), witness);
  const bool spliced = splice_r || splice_negative_s;
  Require(backend.assertion_failed() == spliced,
          spliced ? "spliced compact ECDSA scalar was accepted"
                  : "valid compact ECDSA scalar binding failed");
}

void TestContract() {
  static_assert(kVerifyWitnessLayoutElements<EC> == 1034,
                "ECDSA witness allocation layout changed");
  CheckRelation(false);
  CheckRelation(true);
  CheckCompactScalarBinding(false, false);
  CheckCompactScalarBinding(true, false);
  CheckCompactScalarBinding(false, true);
}

uint64_t Fnv1a(const std::vector<uint8_t>& bytes) {
  uint64_t hash = 1469598103934665603ULL;
  for (uint8_t byte : bytes) { hash ^= byte; hash *= 1099511628211ULL; }
  return hash;
}

void TestCompiledArtifactBaseline() {
  QuadCircuit<Field> quad(p256_base);
  const CompileBackend backend(&quad);
  const CompileLogic logic(&backend, p256_base);
  const CompileRelation relation(logic, p256, n256_order);
  const auto pk_x = logic.eltw_input();
  const auto pk_y = logic.eltw_input();
  const auto e = logic.eltw_input();
  quad.private_input();
  CompileRelation::Witness witness;
  witness.input(logic);
  relation.verify_signature3(pk_x, pk_y, e, witness);
  const auto circuit = quad.mkcircuit(1);
  std::vector<uint8_t> bytes;
  CircuitWriter<Field> writer(p256_base, P256_ID);
  writer.to_bytes(*circuit, bytes);
  // Historical ECDSA relation characterization. These fail on any input
  // allocation, relation-construction, or serialized-circuit byte drift.
  Require(quad.depth_ == 12 && quad.nwires_ == 24477 && quad.ninput_ == 1038 &&
              quad.noutput_ == 2 && quad.nquad_terms_ == 49646,
          "ECDSA circuit metrics changed");
  Require(bytes.size() == 647908 && Fnv1a(bytes) == 8491313162921805174ULL,
          "ECDSA serialized circuit bytes changed");
}
}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::TestContract();
    proofs::TestCompiledArtifactBaseline();
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "ecdsa module tests passed\n";
}
