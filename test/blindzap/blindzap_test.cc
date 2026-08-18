// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0.

#include <array>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>

#include "circuits/blindzap/blindzap_circuit.h"
#include "circuits/blindzap/blindzap_witness.h"
#include "blindzap/proof.h"
#include "circuits/bip340/bip340_guard.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"
#include "proto/circuit_writer.h"
#include "util/crypto.h"
#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace {
using Field = Fp256k1Base;
using EC = P256k1;
using CompileBackend = CompilerBackend<Field>;
using CompileLogic = Logic<Field, CompileBackend>;
using Relation = BlindzapCircuitV1<CompileLogic, Field, EC>;

void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}

std::unique_ptr<Circuit<Field>> BuildCircuit(QuadCircuit<Field>& q) {
  const CompileBackend backend(&q);
  const CompileLogic logic(&backend, p256k1_base);
  Relation relation(logic, p256k1);
  std::array<CompileLogic::EltW, Relation::kProgramBytes> program;
  for (auto& byte : program) byte = logic.eltw_input();
  q.private_input();
  Relation::Witness witness;
  witness.input(logic);
  relation.assert_program(program, witness);
  return q.mkcircuit(1);
}

void TestStableLayoutAndDigest() {
  QuadCircuit<Field> q1(p256k1_base);
  auto c1 = BuildCircuit(q1);
  const auto identity = BlindzapCircuitDigest(*c1, p256k1_base, SECP_ID);
  BlindzapProofV1 envelope; envelope.circuit_digest = identity;
  Require(BlindzapProofIdentityMatches(envelope, identity), "circuit identity rejected");
  envelope.rate++;
  Require(!BlindzapProofIdentityMatches(envelope, identity), "parameter mismatch accepted");
  Require(c1->npub_in == 21, "BlindZap public layout must be one plus 20 bytes");
  Require(c1->ninputs > c1->npub_in, "BlindZap private witness missing");

  std::vector<uint8_t> one;
  CircuitWriter<Field>(p256k1_base, SECP_ID).to_bytes(*c1, one);
  uint8_t digest_one[32];
  SHA256 sha_one;
  sha_one.Update(one.data(), one.size());
  sha_one.DigestData(digest_one);

  QuadCircuit<Field> q2(p256k1_base);
  auto c2 = BuildCircuit(q2);
  std::vector<uint8_t> two;
  CircuitWriter<Field>(p256k1_base, SECP_ID).to_bytes(*c2, two);
  uint8_t digest_two[32];
  SHA256 sha_two;
  sha_two.Update(two.data(), two.size());
  sha_two.DigestData(digest_two);
  Require(one == two, "BlindZap circuit serialization is not deterministic");
  for (size_t i = 0; i < sizeof(digest_one); ++i)
    Require(digest_one[i] == digest_two[i], "BlindZap circuit digest is not deterministic");
}

void TestWitnessInputValidation() {
  BlindzapWitnessV1<Field, EC> witness;
  std::array<uint8_t, 32> one{};
  one[31] = 1;
  std::array<uint8_t, 32> zero{};
  std::array<uint8_t, 32> order = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
  Require(!witness.compute(p256k1, one.data(), 31), "31-byte secret accepted");
  Require(!witness.compute(p256k1, one.data(), 33), "33-byte secret accepted");
  Require(!witness.compute(p256k1, zero.data(), zero.size()), "zero secret accepted");
  Require(!witness.compute(p256k1, order.data(), order.size()), "order secret accepted");
  Require(witness.compute(p256k1, one.data(), one.size()), "valid secret rejected");
  const auto first_program = witness.program();
  std::array<uint8_t, 32> two{}; two[31] = 2;
  Require(witness.compute(p256k1, two.data(), two.size()), "reused witness rejected valid secret");
  Require(witness.program() != first_program, "reused witness retained stale program advice");
  Require(witness.compute(p256k1, one.data(), one.size()), "reused witness could not restore first secret");
  Require(witness.program() == first_program, "reused witness retained stale second-secret advice");
}

void TestProofRoundTrip(const std::array<uint8_t, 32>& secret) {
  BlindzapWitnessV1<Field, EC> witness;
  Require(witness.compute(p256k1, secret.data(), secret.size()), "witness compute failed");
  QuadCircuit<Field> q(p256k1_base); auto circuit = BuildCircuit(q);
  auto inputs = std::make_unique<Dense<Field>>(1, circuit->ninputs);
  { DenseFiller<Field> fill(*inputs); fill.push_back(p256k1_base.one()); BitPluckerEncoder<Field,8> enc(p256k1_base); for (auto b : witness.program()) fill.push_back(enc.encode(b)); witness.fill_witness(fill); }
  using Crt = CRT256<Field>; using CF = CrtConvolutionFactory<Crt, Field>; using RS = ReedSolomonFactory<Field, CF>;
  const size_t block = circuit->ninputs - circuit->npub_in + q.nquad_terms_ + 1; Require(check_crt_block_enc<Crt>(block).empty(), "CRT guard rejected circuit"); Require(!check_crt_block_enc<Crt>((1ull << 22) + 1).empty(), "CRT guard accepted oversized value"); CF cf(p256k1_base); RS rs(cf, p256k1_base);
  ZkProof<Field> proof(*circuit, 4, 128, block); ZkProver<Field, RS> prover(*circuit, p256k1_base, rs); SecureRandomEngine rng; uint8_t tag[] = {'B','Z','P','1'}; Transcript tp(tag, sizeof(tag)); prover.commit(proof, *inputs, tp, rng); Require(prover.prove(proof, *inputs, tp), "prove failed");
  std::vector<uint8_t> bytes; proof.write(bytes, p256k1_base); ReadBuffer rb(bytes.data(), bytes.size()); ZkProof<Field> parsed(*circuit, 4, 128, block); Require(parsed.read(rb, p256k1_base), "parse failed");
  Dense<Field> pub(1, circuit->npub_in); { DenseFiller<Field> fill(pub); fill.push_back(p256k1_base.one()); BitPluckerEncoder<Field,8> enc(p256k1_base); for (auto b : witness.program()) fill.push_back(enc.encode(b)); }
  Transcript tv(tag, sizeof(tag)); ZkVerifier<Field, RS> verifier(*circuit, rs, 4, 128, block, p256k1_base); verifier.recv_commitment(parsed, tv); std::cerr << "positive verify begin\n"; Require(verifier.verify(parsed, pub, tv), "verify failed"); std::cerr << "positive verify done\n";
  auto changed = pub.clone(); changed->v_[1] = p256k1_base.addf(changed->v_[1], p256k1_base.one()); Transcript changed_tv(tag, sizeof(tag)); ZkVerifier<Field, RS> changed_verifier(*circuit, rs, 4, 128, block, p256k1_base); changed_verifier.recv_commitment(parsed, changed_tv); Require(!changed_verifier.verify(parsed, *changed, changed_tv), "public-byte mutation accepted");
  auto swapped = pub.clone(); std::swap(swapped->v_[1], swapped->v_[2]); Transcript swapped_tv(tag, sizeof(tag)); ZkVerifier<Field, RS> swapped_verifier(*circuit, rs, 4, 128, block, p256k1_base); swapped_verifier.recv_commitment(parsed, swapped_tv); Require(!swapped_verifier.verify(parsed, *swapped, swapped_tv), "swapped public bytes accepted");
  bytes[10] ^= 1; ReadBuffer bad_rb(bytes.data(), bytes.size()); ZkProof<Field> bad(*circuit, 4, 128, block); Require(bad.read(bad_rb, p256k1_base), "tampered proof parse failed"); Transcript bad_tv(tag, sizeof(tag)); ZkVerifier<Field, RS> bad_verifier(*circuit, rs, 4, 128, block, p256k1_base); bad_verifier.recv_commitment(bad, bad_tv); Require(!bad_verifier.verify(bad, pub, bad_tv), "tampered proof accepted");
  std::ofstream metrics("test/results/native_blindzap_metrics.csv"); Require(metrics.good(), "metrics output unavailable"); metrics << "target,circuit,proof_bytes,public_inputs,total_inputs,quad_terms,crt_block_enc\n" << "native,blindzap," << bytes.size() << ',' << circuit->npub_in << ',' << circuit->ninputs << ',' << q.nquad_terms_ << ',' << block << '\n';
}
}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::TestStableLayoutAndDigest();
    proofs::TestWitnessInputValidation();
    std::array<uint8_t, 32> one{}; one[31] = 1;
    proofs::TestProofRoundTrip(one);
    for (uint8_t scalar : {uint8_t{2}, uint8_t{3}, uint8_t{153}}) {
      std::array<uint8_t, 32> value{}; value[31] = scalar;
      proofs::TestProofRoundTrip(value);
    }
    std::array<uint8_t, 32> three_eighty_two{}; three_eighty_two[30] = 1; three_eighty_two[31] = 126;
    proofs::TestProofRoundTrip(three_eighty_two);
    std::array<uint8_t, 32> n_minus_one = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x40};
    proofs::TestProofRoundTrip(n_minus_one);
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "BlindZap layout tests passed\n";
}
