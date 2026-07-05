// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "circuits/bip340/bip340_verify.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#include "algebra/crt.h"
#include "circuits/bip340/bip340_guard.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"
#include "util/log.h"

namespace proofs {
namespace {

using Field = Fp256k1Base;
using EC = P256k1;

void Require(bool ok, const std::string& msg) {
  if (!ok) {
    throw std::runtime_error(msg);
  }
}

std::unique_ptr<Circuit<Field>> BuildBip340Circuit(QuadCircuit<Field>& Q) {
  using Backend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, Backend>;
  using Verify = Bip340Verify<LogicCircuit, Field, EC>;

  const Backend backend(&Q);
  const LogicCircuit logic(&backend, p256k1_base);
  Verify circuit(logic, p256k1);

  auto rx = logic.eltw_input();
  auto px = logic.eltw_input();
  auto e = logic.eltw_input();

  typename Verify::Witness witness;
  Q.private_input();
  witness.input(logic);
  circuit.assert_verify(rx, px, e, witness);
  return Q.mkcircuit(1);
}

void TestImportedCircuitCompiles() {
  QuadCircuit<Field> Q(p256k1_base);
  auto circuit = BuildBip340Circuit(Q);

  Require(circuit->npub_in > 0, "BIP340 circuit has no public inputs");
  Require(circuit->ninputs > circuit->npub_in,
          "BIP340 circuit has no private witness inputs");

  using Crt = CRT256<Field>;
  size_t block_enc = circuit->ninputs - circuit->npub_in + Q.nquad_terms_ + 1;
  auto err = check_crt_block_enc<Crt>(block_enc);
  Require(err.empty(), err);
}

}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::set_log_level(proofs::ERROR);
    proofs::TestImportedCircuitCompiles();
  } catch (const std::exception& e) {
    std::cerr << "not ok - " << e.what() << '\n';
    return 1;
  }

  std::cout << "bip340 tests passed\n";
  return 0;
}
