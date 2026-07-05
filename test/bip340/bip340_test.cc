// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "circuits/bip340/bip340_verify.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/bip340/bip340_guard.h"
#include "circuits/bip340/bip340_witness.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace {

constexpr size_t kRate = 4;
constexpr size_t kQueries = 128;

using Field = Fp256k1Base;
using Nat = typename Field::N;
using Elt = typename Field::Elt;
using EC = P256k1;

struct TestFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void Require(bool ok, const std::string& msg) {
  if (!ok) {
    throw TestFailure(msg);
  }
}

template <typename T>
void RequireEq(const T& got, const T& want, const std::string& msg) {
  if (!(got == want)) {
    throw TestFailure(msg);
  }
}

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

std::optional<std::vector<uint8_t>> ParseHexVec(const char* hex) {
  size_t len = std::strlen(hex);
  if (len % 2 != 0) return std::nullopt;
  std::vector<uint8_t> out(len / 2);
  for (size_t i = 0; i < len; i += 2) {
    int hi = HexValue(hex[i]);
    int lo = HexValue(hex[i + 1]);
    if (hi == -1 || lo == -1) return std::nullopt;
    out[i / 2] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return out;
}

std::vector<uint8_t> HexVec(const char* hex) {
  auto result = ParseHexVec(hex);
  Require(result.has_value(), std::string("malformed hex: ") + hex);
  return *result;
}

template <class FieldT>
void PushBip340PublicInputs(DenseFiller<FieldT>& filler, const FieldT& F,
                            typename FieldT::Elt rx,
                            typename FieldT::Elt px,
                            typename FieldT::Elt e) {
  filler.push_back(F.one());
  filler.push_back(rx);
  filler.push_back(px);
  filler.push_back(e);
}

template <class LogicType, class VerifyC>
typename VerifyC::Witness MakeEvalWitness(const LogicType& l,
                                          const Bip340Witness& wit) {
  typename VerifyC::Witness w;
  for (size_t i = 0; i < Bip340Witness::kBits; ++i) {
    w.bits_s[i] = l.konst(wit.bits_s_[i]);
    w.bits_e[i] = l.konst(wit.bits_e_[i]);
    w.bits_ry[i] = l.konst(wit.bits_ry_[i]);
    if (i < Bip340Witness::kBits - 1) {
      w.int_sx[i] = l.konst(wit.int_sx_[i]);
      w.int_sy[i] = l.konst(wit.int_sy_[i]);
      w.int_sz[i] = l.konst(wit.int_sz_[i]);
      w.int_ex[i] = l.konst(wit.int_ex_[i]);
      w.int_ey[i] = l.konst(wit.int_ey_[i]);
      w.int_ez[i] = l.konst(wit.int_ez_[i]);
    }
  }
  w.py = l.konst(wit.py_);
  w.ry = l.konst(wit.ry_);
  w.rz_inv = l.konst(wit.rz_inv_);
  return w;
}

Elt SqrtEven(const Field& F, const Elt& a) {
  Nat exp("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c");
  Elt root = F.one();
  Elt base = a;
  for (int i = 255; i >= 0; --i) {
    root = F.mulf(root, root);
    if (exp.bit(i)) {
      root = F.mulf(root, base);
    }
  }
  return F.from_montgomery(root).bit(0) == 0 ? root : F.negf(root);
}

Elt ComputeRx(const Field& F, const EC& ec, const Nat& s_nat,
              const Nat& e_nat, const Elt& px, Elt& py_out) {
  Elt x2 = F.mulf(px, px);
  Elt x3 = F.mulf(x2, px);
  py_out = SqrtEven(F, F.addf(x3, ec.b_));

  auto sG = ec.scalar_multf(ec.generator(), s_nat);
  typename EC::ECPoint P = {px, py_out, F.one()};
  auto eP = ec.scalar_multf(P, e_nat);
  typename EC::ECPoint neg_eP = {eP.x, F.negf(eP.y), eP.z};
  ec.addE(sG, neg_eP);
  ec.normalize(sG);
  return sG.x;
}

void CheckVerify(const Nat& s_nat, const Nat& e_nat, const Elt& px,
                 const Elt& py, const Elt& rx, bool expected) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  Bip340Witness wit(p256k1);
  Require(wit.compute_from_scalars(s_nat, e_nat, px, py),
          "compute_from_scalars failed");

  const EvalBackend ebk(p256k1_base, expected);
  const LogicType l(&ebk, p256k1_base);
  VerifyC circuit(l, p256k1);

  auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
  circuit.assert_verify(l.konst(rx), l.konst(px), l.konst(wit.e_), w);
  RequireEq(ebk.assertion_failed(), !expected,
            expected ? "valid witness failed" : "invalid witness passed");
}

struct Bip340RealVector {
  const char* pk_hex;
  const char* msg_hex;
  const char* sig_hex;
  bool valid;
};

struct Bip340GoldenFact {
  size_t index;
  bool valid;
  bool compute_success;
  const char* rx_hex;
  const char* px_hex;
  const char* e_hex;
  const char* py_hex;
  const char* ry_hex;
};

enum class RejectBy {
  kAccept = 0,
  kInputValidation,
  kCircuit,
};

constexpr RejectBy kRejectLayer[] = {
    RejectBy::kAccept,          RejectBy::kAccept,
    RejectBy::kAccept,          RejectBy::kAccept,
    RejectBy::kAccept,          RejectBy::kInputValidation,
    RejectBy::kCircuit,         RejectBy::kCircuit,
    RejectBy::kCircuit,         RejectBy::kCircuit,
    RejectBy::kCircuit,         RejectBy::kCircuit,
    RejectBy::kInputValidation, RejectBy::kInputValidation,
    RejectBy::kInputValidation, RejectBy::kAccept,
    RejectBy::kAccept,          RejectBy::kAccept,
    RejectBy::kAccept,
};
static_assert(sizeof(kRejectLayer) / sizeof(kRejectLayer[0]) == 19);

const Bip340RealVector kRealVectors[] = {
#include "testdata/bip340_vectors.inc"
};
static_assert(sizeof(kRealVectors) / sizeof(kRealVectors[0]) == 19);

const Bip340GoldenFact kGoldenFacts[] = {
#include "testdata/bip340_golden.inc"
};
static_assert(sizeof(kGoldenFacts) / sizeof(kGoldenFacts[0]) == 19);

Elt EltFromHex(const Field& F, const char* hex) {
  auto be = HexVec(hex);
  uint8_t le[32] = {0};
  for (size_t i = 0; i < be.size(); ++i) {
    le[i] = be[be.size() - 1 - i];
  }
  return F.to_montgomery(Nat::of_bytes(le, 256));
}

void TestHexParser() {
  RequireEq(HexValue('0'), 0, "hex 0");
  RequireEq(HexValue('F'), 15, "hex F");
  RequireEq(HexValue('f'), 15, "hex f");
  RequireEq(HexValue('g'), -1, "hex rejects g");
  auto v = ParseHexVec("0A1b");
  Require(v.has_value(), "valid hex rejected");
  RequireEq(v->size(), static_cast<size_t>(2), "hex length");
  RequireEq((*v)[0], static_cast<uint8_t>(0x0a), "hex byte 0");
  RequireEq((*v)[1], static_cast<uint8_t>(0x1b), "hex byte 1");
  Require(!ParseHexVec("0A1").has_value(), "odd hex accepted");
  Require(!ParseHexVec("0g").has_value(), "invalid hex accepted");
}

void TestScalarEvaluation() {
  const Field& F = p256k1_base;
  const EC& ec = p256k1;
  auto G = ec.generator();

  Nat s_nat(2ull);
  Nat e_nat(1ull);
  auto P = ec.scalar_multf(G, Nat(1ull));
  ec.normalize(P);

  Elt py;
  Elt rx = ComputeRx(F, ec, s_nat, e_nat, P.x, py);
  CheckVerify(s_nat, e_nat, P.x, py, rx, true);

  Elt wrong_rx = F.negf(rx);
  CheckVerify(s_nat, e_nat, P.x, py, wrong_rx, false);

  auto wrongP = ec.scalar_multf(G, Nat(5ull));
  ec.normalize(wrongP);
  Elt wrong_py;
  Elt wrong_point_rx = ComputeRx(F, ec, s_nat, e_nat, wrongP.x, wrong_py);
  CheckVerify(s_nat, e_nat, P.x, wrong_py, wrong_point_rx, false);
}

void TestVectorsEvaluate() {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  for (size_t vi = 0; vi < sizeof(kRealVectors) / sizeof(kRealVectors[0]);
       ++vi) {
    const auto& tv = kRealVectors[vi];
    auto pk = HexVec(tv.pk_hex);
    auto msg = HexVec(tv.msg_hex);
    auto sig = HexVec(tv.sig_hex);
    RejectBy expected = kRejectLayer[vi];

    Bip340Witness wit(ec);
    bool computed = wit.compute(sig.data(), pk.data(), msg.data(), msg.size());

    if (expected == RejectBy::kAccept) {
      Require(computed, "valid vector compute failed: " + std::to_string(vi));
      const EvalBackend ebk(F, false);
      const LogicType l(&ebk, F);
      VerifyC circuit(l, ec);
      auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
      circuit.assert_verify(
          l.konst(F.to_montgomery(Bip340Witness::nat_from_be_bytes(sig.data()))),
          l.konst(F.to_montgomery(Bip340Witness::nat_from_be_bytes(pk.data()))),
          l.konst(wit.e_), w);
      Require(!ebk.assertion_failed(),
              "valid vector circuit failed: " + std::to_string(vi));
      continue;
    }

    if (expected == RejectBy::kInputValidation) {
      Require(!computed,
              "invalid vector passed input validation: " + std::to_string(vi));
      continue;
    }

    if (!computed) {
      continue;
    }

    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);
    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
    circuit.assert_verify(
        l.konst(F.to_montgomery(Bip340Witness::nat_from_be_bytes(sig.data()))),
        l.konst(F.to_montgomery(Bip340Witness::nat_from_be_bytes(pk.data()))),
        l.konst(wit.e_), w);
    Require(ebk.assertion_failed(),
            "invalid vector circuit passed: " + std::to_string(vi));
  }
}

void TestGoldenFacts() {
  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  for (size_t vi = 0; vi < sizeof(kRealVectors) / sizeof(kRealVectors[0]);
       ++vi) {
    const auto& tv = kRealVectors[vi];
    const auto& fact = kGoldenFacts[vi];
    auto pk = HexVec(tv.pk_hex);
    auto msg = HexVec(tv.msg_hex);
    auto sig = HexVec(tv.sig_hex);

    RequireEq(fact.index, vi, "golden index mismatch");
    RequireEq(fact.valid, tv.valid, "golden validity mismatch");

    Bip340Witness wit(ec);
    bool computed = wit.compute(sig.data(), pk.data(), msg.data(), msg.size());
    if (!computed || !fact.compute_success) {
      Require(!tv.valid, "valid vector failed golden compute");
      continue;
    }

    RequireEq(wit.e_, EltFromHex(F, fact.e_hex), "challenge mismatch");
    RequireEq(wit.py_, EltFromHex(F, fact.py_hex), "py mismatch");
    RequireEq(wit.ry_, EltFromHex(F, fact.ry_hex), "ry mismatch");
  }
}

std::unique_ptr<Circuit<Field>> BuildCircuit(QuadCircuit<Field>& Q) {
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using VerifyC = Bip340Verify<LogicCircuit, Field, EC>;

  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, p256k1_base);
  VerifyC circuit(lc, p256k1);

  auto rx = lc.eltw_input();
  auto px = lc.eltw_input();
  auto e = lc.eltw_input();

  typename VerifyC::Witness w;
  Q.private_input();
  w.input(lc);
  circuit.assert_verify(rx, px, e, w);
  return Q.mkcircuit(1);
}

void TestCircuitSize() {
  QuadCircuit<Field> Q(p256k1_base);
  auto C = BuildCircuit(Q);
  Require(C->npub_in > 0, "circuit has no public inputs");
  Require(C->ninputs > C->npub_in, "circuit has no private witness");

  using Crt = CRT256<Field>;
  size_t block_enc = C->ninputs - C->npub_in + Q.nquad_terms_ + 1;
  auto err = check_crt_block_enc<Crt>(block_enc);
  Require(err.empty(), err);
}

void TestZkProverVerifierVector0() {
  const Field& F = p256k1_base;
  const EC& ec = p256k1;
  const auto& tv = kRealVectors[0];
  auto pk = HexVec(tv.pk_hex);
  auto msg = HexVec(tv.msg_hex);
  auto sig = HexVec(tv.sig_hex);

  Bip340Witness wit(ec);
  Require(wit.compute(sig.data(), pk.data(), msg.data(), msg.size()),
          "vector 0 witness compute failed");

  QuadCircuit<Field> Q(F);
  auto CIRCUIT = BuildCircuit(Q);

  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  {
    DenseFiller<Field> filler(*W);
    PushBip340PublicInputs(
        filler, F,
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(sig.data())),
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(pk.data())),
        wit.e_);
    wit.fill_witness(filler);
  }

  using Crt = CRT256<Field>;
  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  ConvolutionFactory factory(F);
  RSFactory rsf(factory, F);

  Transcript tp(reinterpret_cast<uint8_t*>(const_cast<char*>("bip340 vec0")),
                11);
  SecureRandomEngine rng;

  ZkProof<Field> zkpr(*CIRCUIT, kRate, kQueries);
  ZkProver<Field, RSFactory> prover(*CIRCUIT, F, rsf);
  prover.commit(zkpr, *W, tp, rng);
  Require(prover.prove(zkpr, *W, tp), "prover failed");

  Transcript trv(reinterpret_cast<uint8_t*>(const_cast<char*>("bip340 vec0")),
                 11);
  Dense<Field> pub(1, CIRCUIT->npub_in);
  {
    DenseFiller<Field> filler(pub);
    PushBip340PublicInputs(
        filler, F,
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(sig.data())),
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(pk.data())),
        wit.e_);
  }

  ZkVerifier<Field, RSFactory> verifier(*CIRCUIT, rsf, kRate, kQueries, F);
  verifier.recv_commitment(zkpr, trv);
  Require(verifier.verify(zkpr, pub, trv), "verifier rejected proof");
}

void Run(const char* name, const std::function<void()>& fn) {
  fn();
  std::cout << "ok - " << name << '\n';
}

}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::set_log_level(proofs::ERROR);
    proofs::Run("hex parser rejects malformed input", proofs::TestHexParser);
    proofs::Run("scalar evaluation accepts and rejects witnesses",
                proofs::TestScalarEvaluation);
    proofs::Run("bitcoin vectors evaluate through circuit",
                proofs::TestVectorsEvaluate);
    proofs::Run("witness semantic facts match golden vectors",
                proofs::TestGoldenFacts);
    proofs::Run("compiled circuit has expected shape", proofs::TestCircuitSize);
    proofs::Run("zk prover/verifier accepts bitcoin vector 0",
                proofs::TestZkProverVerifierVector0);
  } catch (const std::exception& e) {
    std::cerr << "not ok - " << e.what() << '\n';
    return 1;
  }
  std::cout << "bip340 tests passed\n";
  return 0;
}
