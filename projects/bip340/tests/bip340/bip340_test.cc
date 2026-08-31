// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "circuits/bip340/bip340_verify.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
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
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "util/readbuffer.h"
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
using Clock = std::chrono::steady_clock;

using Field = Fp256k1Base;
using Nat = typename Field::N;
using Elt = typename Field::Elt;
using EC = P256k1;

struct TestFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

struct MetricRow {
  const char* phase;
  long ms;
  size_t compressed_bytes;
  size_t public_inputs;
  size_t total_inputs;
  size_t quad_terms;
  size_t crt_block_enc;
};

void Require(bool ok, const std::string& msg) {
  if (!ok) {
    throw TestFailure(msg);
  }
}

long ElapsedMs(Clock::time_point start, Clock::time_point finish) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(finish - start)
      .count();
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
    w.s_mult.bits[i] = l.konst(wit.s_mult_.bits[i]);
    w.e_mult.bits[i] = l.konst(wit.e_mult_.bits[i]);
    w.bits_ry[i] = l.konst(wit.bits_ry_[i]);
    if (i < Bip340Witness::kBits - 1) {
      w.s_mult.int_x[i] = l.konst(wit.s_mult_.int_x[i]);
      w.s_mult.int_y[i] = l.konst(wit.s_mult_.int_y[i]);
      w.s_mult.int_z[i] = l.konst(wit.s_mult_.int_z[i]);
      w.e_mult.int_x[i] = l.konst(wit.e_mult_.int_x[i]);
      w.e_mult.int_y[i] = l.konst(wit.e_mult_.int_y[i]);
      w.e_mult.int_z[i] = l.konst(wit.e_mult_.int_z[i]);
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

void TestSoundnessRegressions() {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;
  auto P = ec.scalar_multf(ec.generator(), Nat(1ull));
  ec.normalize(P);

  const Nat s_nat(2ull);
  const Nat e_nat(1ull);
  Elt py;
  Elt rx = ComputeRx(F, ec, s_nat, e_nat, P.x, py);

  Bip340Witness wit(ec);
  Require(wit.compute_from_scalars(s_nat, e_nat, P.x, py),
          "soundness witness compute failed");

  auto expect_rejected = [&](const char* name, Elt public_rx, Elt public_px,
                             Elt public_e,
                             const std::function<void(
                                 typename VerifyC::Witness&,
                                 const LogicType&)>& mutate) {
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);
    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
    mutate(w, l);
    circuit.assert_verify(l.konst(public_rx), l.konst(public_px),
                          l.konst(public_e), w);
    Require(ebk.assertion_failed(),
            std::string("soundness mutation accepted: ") + name);
  };

  auto no_mutation = [](typename VerifyC::Witness&, const LogicType&) {};
  expect_rejected("wrong public rx", F.negf(rx), P.x, wit.e_, no_mutation);
  expect_rejected("wrong public px", rx, F.negf(P.x), wit.e_, no_mutation);
  expect_rejected("wrong public challenge", rx, P.x,
                  F.addf(wit.e_, F.one()), no_mutation);

  expect_rejected("odd R.y with even decomposition", rx, P.x, wit.e_,
                  [&](auto& w, const auto& l) {
                    w.ry = l.konst(F.negf(wit.ry_));
                  });
  expect_rejected("odd R.y with matching decomposition", rx, P.x, wit.e_,
                  [&](auto& w, const auto& l) {
                    Elt odd_ry = F.negf(wit.ry_);
                    w.ry = l.konst(odd_ry);
                    Nat odd_ry_nat = F.from_montgomery(odd_ry);
                    for (size_t i = 0; i < Bip340Witness::kBits; ++i) {
                      w.bits_ry[i] =
                          l.konst(F.of_scalar(odd_ry_nat.bit(255 - i)));
                    }
                  });

  expect_rejected("flipped s bit", rx, P.x, wit.e_,
                  [&](auto& w, const auto& l) {
                    w.s_mult.bits[10] =
                        l.konst(F.subf(F.one(), wit.s_mult_.bits[10]));
                  });
  expect_rejected("flipped e bit", rx, P.x, wit.e_,
                  [&](auto& w, const auto& l) {
                    w.e_mult.bits[20] =
                        l.konst(F.subf(F.one(), wit.e_mult_.bits[20]));
                  });
  expect_rejected("corrupt s trace", rx, P.x, wit.e_,
                  [&](auto& w, const auto& l) {
                    w.s_mult.int_x[254] = l.konst(F.zero());
                  });
  expect_rejected("corrupt e trace", rx, P.x, wit.e_,
                  [&](auto& w, const auto& l) {
                    w.e_mult.int_y[254] = l.konst(F.zero());
                  });
  expect_rejected("zero R.z inverse", rx, P.x, wit.e_,
                  [&](auto& w, const auto& l) {
                    w.rz_inv = l.konst(F.zero());
                  });

  // n + 2 has the same group action as 2, but is not a canonical BIP-340
  // response scalar.  This specifically exercises the in-circuit s < n
  // constraint added by the accepted implementation.
  Nat s_plus_n(
      "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143");
  Bip340Witness noncanonical(ec);
  Require(noncanonical.compute_from_scalars(s_plus_n, e_nat, P.x, py),
          "non-canonical scalar witness compute failed");
  {
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);
    auto w = MakeEvalWitness<LogicType, VerifyC>(l, noncanonical);
    circuit.assert_verify(l.konst(rx), l.konst(P.x),
                          l.konst(noncanonical.e_), w);
    Require(ebk.assertion_failed(), "scalar s >= n was accepted");
  }
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

void TestCrtGuardBoundaries() {
  using Crt = CRT256<Field>;
  Require(check_crt_block_enc<Crt>(1024).empty(),
          "CRT guard rejected a small transform");
  Require(check_crt_block_enc<Crt>(1ull << 22).empty(),
          "CRT guard rejected its documented maximum transform");
  auto err = check_crt_block_enc<Crt>((1ull << 22) + 1);
  Require(!err.empty(), "CRT guard accepted an oversized transform");
  Require(err.find("exceeds") != std::string::npos,
          "CRT guard returned an unexpected oversized-transform error");
}

std::string ResultDir(const char* argv0) {
  std::string path = argv0 ? argv0 : "";
  auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    return "test/results";
  }
  return path.substr(0, slash) + "/results";
}

void WriteMetricsCsv(const char* argv0, const std::vector<MetricRow>& rows) {
  auto dir = ResultDir(argv0);
  (void)mkdir(dir.c_str(), 0777);
  std::ofstream out(dir + "/native_bip340_metrics.csv");
  Require(out.good(), "failed to open native metrics CSV");
  out << "target,circuit,phase,ms,compressed_bytes,public_inputs,total_inputs,"
         "quad_terms,crt_block_enc\n";
  for (const auto& row : rows) {
    out << "native,bip340," << row.phase << ',' << row.ms << ','
        << row.compressed_bytes << ',' << row.public_inputs << ','
        << row.total_inputs << ',' << row.quad_terms << ','
        << row.crt_block_enc << '\n';
  }
}

void TestZkProverVerifierVector0(const char* argv0) {
  const Field& F = p256k1_base;
  const EC& ec = p256k1;
  const auto& tv = kRealVectors[0];
  auto pk = HexVec(tv.pk_hex);
  auto msg = HexVec(tv.msg_hex);
  auto sig = HexVec(tv.sig_hex);
  std::vector<MetricRow> metrics;

  auto phase_start = Clock::now();
  QuadCircuit<Field> Q(F);
  auto CIRCUIT = BuildCircuit(Q);
  std::vector<uint8_t> circuit_bytes;
  CircuitWriter<Field> circuit_writer(F, SECP_ID);
  circuit_writer.to_bytes(*CIRCUIT, circuit_bytes);

  ReadBuffer circuit_rb(circuit_bytes);
  CircuitReader<Field> circuit_reader(F, SECP_ID);
  auto parsed_circuit = circuit_reader.from_bytes(circuit_rb, true);
  Require(parsed_circuit != nullptr, "valid circuit parse failed");
  Require(circuit_reader.last_error().code == CircuitReadErrorCode::kNone,
          "valid circuit retained a parse error");
  for (size_t n = 0; n < std::min<size_t>(circuit_bytes.size(), 25); ++n) {
    ReadBuffer truncated_circuit(circuit_bytes.data(), n);
    CircuitReader<Field> truncated_reader(F, SECP_ID);
    Require(truncated_reader.from_bytes(truncated_circuit, true) == nullptr,
            "truncated circuit header accepted");
    Require(truncated_reader.last_error().code ==
                CircuitReadErrorCode::kTruncated,
            "truncated circuit header lacks structured error");
  }

  using Crt = CRT256<Field>;
  size_t block_enc = CIRCUIT->ninputs - CIRCUIT->npub_in + Q.nquad_terms_ + 1;
  auto err = check_crt_block_enc<Crt>(block_enc);
  Require(err.empty(), err);
  auto phase_finish = Clock::now();
  metrics.push_back({"build_serialize_circuit",
                     ElapsedMs(phase_start, phase_finish),
                     circuit_bytes.size(), CIRCUIT->npub_in, CIRCUIT->ninputs,
                     Q.nquad_terms_, block_enc});

  phase_start = Clock::now();
  Bip340Witness wit(ec);
  Require(wit.compute(sig.data(), pk.data(), msg.data(), msg.size()),
          "vector 0 witness compute failed");
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

  std::vector<uint8_t> proof_bytes;
  zkpr.write(proof_bytes, F);
  phase_finish = Clock::now();
  metrics.push_back({"witness_prove_serialize",
                     ElapsedMs(phase_start, phase_finish),
                     proof_bytes.size(), CIRCUIT->npub_in, CIRCUIT->ninputs,
                     Q.nquad_terms_, block_enc});

  phase_start = Clock::now();
  ReadBuffer proof_rb(proof_bytes.data(), proof_bytes.size());
  ZkProof<Field> parsed_proof(*CIRCUIT, kRate, kQueries);
  Require(parsed_proof.read(proof_rb, F), "proof parse failed");
  const std::vector<size_t> truncation_points = {
      0,
      1,
      Digest::kLength - 1,
      Digest::kLength,
      std::min(proof_bytes.size() / 2, proof_bytes.size() - 1),
      proof_bytes.size() - 1,
  };
  for (size_t n : truncation_points) {
    ReadBuffer truncated_rb(proof_bytes.data(), n);
    ZkProof<Field> truncated_proof(*CIRCUIT, kRate, kQueries);
    Require(!truncated_proof.read(truncated_rb, F),
            "truncated proof was accepted");
    Require(truncated_proof.last_read_error().code !=
                ProofReadErrorCode::kNone,
            "truncated proof lacks structured error");
  }

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
  verifier.recv_commitment(parsed_proof, trv);
  Require(verifier.verify(parsed_proof, pub, trv), "verifier rejected proof");

  // The accepted suite also checks that serialized proof corruption cannot
  // survive verification.  Keep that regression in the portable harness.
  auto tampered_bytes = proof_bytes;
  Require(tampered_bytes.size() >= 20, "proof too small to tamper");
  tampered_bytes[10] ^= 0xff;
  ReadBuffer tampered_rb(tampered_bytes.data(), tampered_bytes.size());
  ZkProof<Field> tampered_proof(*CIRCUIT, kRate, kQueries);
  Require(tampered_proof.read(tampered_rb, F),
          "failed to parse structurally valid tampered proof");
  Transcript tampered_transcript(
      reinterpret_cast<uint8_t*>(const_cast<char*>("bip340 vec0")), 11);
  ZkVerifier<Field, RSFactory> tampered_verifier(*CIRCUIT, rsf, kRate,
                                                 kQueries, F);
  tampered_verifier.recv_commitment(tampered_proof, tampered_transcript);
  Require(!tampered_verifier.verify(tampered_proof, pub,
                                    tampered_transcript),
          "verifier accepted a tampered proof");
  phase_finish = Clock::now();
  metrics.push_back({"deserialize_verify_proof",
                     ElapsedMs(phase_start, phase_finish),
                     proof_bytes.size(), CIRCUIT->npub_in, CIRCUIT->ninputs,
                     Q.nquad_terms_, block_enc});
  WriteMetricsCsv(argv0, metrics);
}

void Run(const char* name, const std::function<void()>& fn) {
  fn();
  std::cout << "ok - " << name << '\n';
}

}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  try {
    const char* argv0 = argc > 0 ? argv[0] : "test/bip340_test";
    proofs::set_log_level(proofs::ERROR);
    if (argc > 1) {
      if (argc != 3 || std::strcmp(argv[1], "--profile") != 0) {
        throw std::runtime_error("usage: bip340-test [--profile ITERATIONS]");
      }
      char* end = nullptr;
      const unsigned long iterations = std::strtoul(argv[2], &end, 10);
      if (end == argv[2] || *end != '\0' || iterations == 0) {
        throw std::runtime_error("profile iterations must be a positive integer");
      }
      for (unsigned long i = 0; i < iterations; ++i) {
        proofs::TestZkProverVerifierVector0(argv0);
      }
      std::cout << "profile workload completed " << iterations << " iterations\n";
      return 0;
    }
    proofs::Run("hex parser rejects malformed input", proofs::TestHexParser);
    proofs::Run("scalar evaluation accepts and rejects witnesses",
                proofs::TestScalarEvaluation);
    proofs::Run("accepted circuit soundness regressions",
                proofs::TestSoundnessRegressions);
    proofs::Run("bitcoin vectors evaluate through circuit",
                proofs::TestVectorsEvaluate);
    proofs::Run("witness semantic facts match golden vectors",
                proofs::TestGoldenFacts);
    proofs::Run("compiled circuit has expected shape", proofs::TestCircuitSize);
    proofs::Run("CRT guard accepts and rejects boundary sizes",
                proofs::TestCrtGuardBoundaries);
    proofs::Run("zk prover/verifier accepts bitcoin vector 0",
                [&]() { proofs::TestZkProverVerifierVector0(argv0); });
  } catch (const std::exception& e) {
    std::cerr << "not ok - " << e.what() << '\n';
    return 1;
  }
  std::cout << "bip340 tests passed\n";
  return 0;
}
