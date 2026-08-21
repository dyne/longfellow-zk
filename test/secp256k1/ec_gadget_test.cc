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

#include <functional>
#include <iostream>
#include <stdexcept>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/secp256k1/ec_gadget.h"
#include "circuits/secp256k1/ec_witness.h"
#include "ec/p256k1.h"

namespace proofs {
namespace {
using Field = Fp256k1Base;
using EC = P256k1;
using Backend = EvaluationBackend<Field>;
using Circuit = Logic<Field, Backend>;
using Gadget = Secp256k1EcGadget<Circuit, EC>;
using Trace = Secp256k1ScalarMultWitness<Field, EC>;

void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}

void CheckScalar(const typename Field::N& value, int mutation = -1) {
  const Field& field = p256k1_base;
  Trace trace;
  const auto generator = p256k1.generator();
  compute_secp256k1_scalar_mult_witness(trace, p256k1, generator, value);
  // Mutated witnesses are deliberately invalid external values, so evaluate
  // them through the recoverable assertion path.  Valid fixtures retain the
  // fail-fast invariant mode.
  const Backend backend(field, mutation < 0);
  const Circuit circuit(&backend, field);
  const Gadget gadget(circuit, p256k1);
  typename Gadget::ScalarMultWitness witness;
  for (size_t i = 0; i < EC::kBits; ++i) {
    witness.bits[i] = circuit.konst(trace.bits[i]);
    if (i < EC::kBits - 1) {
      witness.int_x[i] = circuit.konst(trace.int_x[i]);
      witness.int_y[i] = circuit.konst(trace.int_y[i]);
      witness.int_z[i] = circuit.konst(trace.int_z[i]);
      if (mutation == 0 && i == 17) witness.int_x[i] = circuit.konst(field.addf(trace.int_x[i], field.one()));
      if (mutation == 1 && i == 89) witness.int_y[i] = circuit.konst(field.addf(trace.int_y[i], field.one()));
      if (mutation == 2 && i == 201) witness.int_z[i] = circuit.konst(field.addf(trace.int_z[i], field.one()));
    }
  }
  typename Gadget::ProjectivePointW result;
  gadget.scalar_mult(result, {circuit.konst(generator.x), circuit.konst(generator.y),
                              circuit.konst(generator.z)}, witness);
  circuit.assert_eq(result.x, circuit.konst(mutation == 3 ? field.zero() : trace.int_x[255]));
  circuit.assert_eq(result.y, circuit.konst(trace.int_y[255]));
  circuit.assert_eq(result.z, circuit.konst(trace.int_z[255]));
  Require(mutation < 0 ? !backend.assertion_failed() : backend.assertion_failed(),
          mutation < 0 ? "native/circuit scalar mismatch" : "trace mutation accepted");
}

void TestIdentityAndTraceMutations() {
  const Field& field = p256k1_base;
  const Backend backend(field, false);
  const Circuit circuit(&backend, field);
  const Gadget gadget(circuit, p256k1);
  typename Gadget::ProjectivePointW infinity{circuit.konst(field.zero()),
      circuit.konst(field.one()), circuit.konst(field.zero())};
  const auto native_generator = p256k1.generator();
  typename Gadget::ProjectivePointW generator{circuit.konst(native_generator.x),
      circuit.konst(native_generator.y), circuit.konst(native_generator.z)};
  typename Gadget::ProjectivePointW result;
  gadget.addE(result, infinity, generator);
  // Complete formulas may choose an equivalent projective scale.
  circuit.assert_eq(circuit.mul(result.x, generator.z),
                    circuit.mul(generator.x, result.z));
  circuit.assert_eq(circuit.mul(result.y, generator.z),
                    circuit.mul(generator.y, result.z));
  Require(!backend.assertion_failed(), "infinity identity rejected");
}
}  // namespace
}  // namespace proofs

int main() {
  try {
    // Exercises zero/one bits, low/mid/high positions and independent native
    // generator multiples through the shared circuit trace.
    proofs::CheckScalar(proofs::Field::N(1));
    proofs::CheckScalar(proofs::Field::N(2));
    proofs::CheckScalar(proofs::Field::N(3));
    proofs::CheckScalar(proofs::Field::N(153));
    proofs::CheckScalar(proofs::Field::N(382));
    proofs::CheckScalar(proofs::Field::N(
        "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"));
    proofs::CheckScalar(proofs::Field::N("0x100000000000000000000000000000000"));
    proofs::CheckScalar(proofs::Field::N("0x8000000000000000000000000000000000000000000000000000000000000000"));
    proofs::CheckScalar(proofs::Field::N(3), 0);
    proofs::CheckScalar(proofs::Field::N(3), 1);
    proofs::CheckScalar(proofs::Field::N(3), 2);
    proofs::CheckScalar(proofs::Field::N(3), 3);
    proofs::TestIdentityAndTraceMutations();
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "ec gadget tests passed\n";
}
