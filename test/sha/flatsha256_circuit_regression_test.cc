// Portable adaptations of Google Longfellow's flatsha256_circuit_test.
// The Google-only proof harness and benchmarks are intentionally excluded.
#include <array>
#include <cassert>
#include <cstdint>
#include <memory>
#include <string_view>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"

namespace proofs {
namespace {
using Field = Fp256Base;
using EvalBackend = EvaluationBackend<Field>;
using EvalLogic = Logic<Field, EvalBackend>;
using EvalSha = FlatSHA256Circuit<EvalLogic, BitPlucker<EvalLogic, 4>>;

template <class LogicT>
void AssignBlock(const LogicT& logic, typename FlatSHA256Circuit<
                     LogicT, BitPlucker<LogicT, 4>>::BlockWitness& output,
                 const FlatSHA256Witness::BlockWitness& input) {
  BitPluckerEncoder<Field, 4> encoder(p256_base);
  for (size_t i = 0; i < 48; ++i) output.outw[i] = logic.konst(encoder.mkpacked_v32(input.outw[i]));
  for (size_t i = 0; i < 64; ++i) {
    output.oute[i] = logic.konst(encoder.mkpacked_v32(input.oute[i]));
    output.outa[i] = logic.konst(encoder.mkpacked_v32(input.outa[i]));
  }
  for (size_t i = 0; i < 8; ++i) output.h1[i] = logic.konst(encoder.mkpacked_v32(input.h1[i]));
}

void EvaluateMessage(std::string_view message, const std::array<uint8_t, 32>& digest,
                     bool mutate_digest) {
  constexpr size_t kMaxBlocks = 2;
  std::array<uint8_t, 64 * kMaxBlocks> padded{};
  std::array<FlatSHA256Witness::BlockWitness, kMaxBlocks> witness{};
  uint8_t blocks = 0;
  FlatSHA256Witness::transform_and_witness_message(
      message.size(), reinterpret_cast<const uint8_t*>(message.data()),
      kMaxBlocks, blocks, padded.data(), witness.data());
  assert(blocks > 0);
  EvalBackend backend(p256_base, false);
  EvalLogic logic(&backend, p256_base);
  EvalSha sha(logic);
  std::array<EvalLogic::v8, 64 * kMaxBlocks> input{};
  for (size_t i = 0; i < input.size(); ++i) input[i] = logic.vbit8(padded[i]);
  std::array<EvalSha::BlockWitness, kMaxBlocks> circuit_witness{};
  for (size_t i = 0; i < kMaxBlocks; ++i) AssignBlock(logic, circuit_witness[i], witness[i]);
  EvalLogic::v256 target{};
  for (size_t byte = 0; byte < digest.size(); ++byte)
    logic.bits(8, &target[(31 - byte) * 8], digest[byte]);
  if (mutate_digest) target[0] = logic.lnot(target[0]);
  sha.assert_message_hash(kMaxBlocks, logic.vbit8(blocks), input.data(), target,
                          circuit_witness.data());
  assert(backend.assertion_failed() == mutate_digest);
}

void EvaluationVectors() {
  constexpr std::array<uint8_t, 32> empty = {0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
  constexpr std::array<uint8_t, 32> abc = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
  constexpr std::array<uint8_t, 32> boundary = {0xb3,0x54,0x39,0xa4,0xac,0x6f,0x09,0x48,0xb6,0xd6,0xf9,0xe3,0xc6,0xaf,0x0f,0x5f,0x59,0x0c,0xe2,0x0f,0x1b,0xde,0x70,0x90,0xef,0x79,0x70,0x68,0x6e,0xc6,0x73,0x8a};
  EvaluateMessage("", empty, false);
  EvaluateMessage("abc", abc, false);
  EvaluateMessage(std::string(56, 'a'), boundary, false);
  EvaluateMessage("abc", abc, true);
}

void CompilerPath() {
  QuadCircuit<Field> circuit(p256_base);
  using CompileBackend = CompilerBackend<Field>;
  using CompileLogic = Logic<Field, CompileBackend>;
  using CompileSha = FlatSHA256Circuit<CompileLogic, BitPlucker<CompileLogic, 4>>;
  CompileBackend backend(&circuit);
  CompileLogic logic(&backend, p256_base);
  CompileSha sha(logic);
  circuit.private_input();
  const auto blocks = logic.vinput<8>();
  std::array<CompileLogic::v8, 64> input{};
  for (auto& byte : input) byte = logic.vinput<8>();
  auto target = logic.vinput<256>();
  std::array<CompileSha::BlockWitness, 1> witness{};
  witness[0].input(logic);
  sha.assert_message_hash(1, blocks, input.data(), target, witness.data());
  const auto compiled = circuit.mkcircuit(1);
  assert(compiled->ninputs > 0);
  assert(circuit.nquad_terms_ > 0);
}
}  // namespace
}  // namespace proofs

int main() {
  proofs::EvaluationVectors();
  proofs::CompilerPath();
  return 0;
}
