// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include <cassert>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "circuits/base64/base64_decoder.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "sumcheck/prover_layers.h"

namespace proofs {
namespace {

constexpr char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

template <class Field>
void CheckEverySymbol(const Field& field) {
  using Backend = EvaluationBackend<Field>;
  using CircuitLogic = Logic<Field, Backend>;
  using V6 = typename CircuitLogic::template bitvec<6>;

  const Backend backend(field, false);
  const CircuitLogic logic(&backend, field);
  Base64Decoder<CircuitLogic> decoder(logic);
  V6 output;

  for (size_t byte = 0; byte < 256; ++byte) {
    const auto input = logic.template vbit<8>(byte);
    const size_t expected = std::string(kBase64UrlAlphabet).find(byte);
    decoder.decode(input, output);
    if (expected == std::string::npos) {
      assert(backend.assertion_failed());
    } else {
      assert(logic.eval(logic.veq(output, logic.template vbit<6>(expected))) ==
             logic.konst(1));
      assert(!backend.assertion_failed());
    }
  }
}

template <class Field>
void CheckDecodingVectors(const Field& field) {
  using Backend = EvaluationBackend<Field>;
  using CircuitLogic = Logic<Field, Backend>;
  using V8 = typename CircuitLogic::v8;

  const Backend backend(field, false);
  const CircuitLogic logic(&backend, field);
  Base64Decoder<CircuitLogic> decoder(logic);

  struct Vector {
    const char* decoded;
    const char* encoded;
  };
  constexpr Vector kVectors[] = {
      {"hello", "aGVsbG8"},
      {"s", "cw"},
      {"ab", "YWI"},
      {"333", "MzMz"},
      {"4444", "NDQ0NA"},
      {"55555", "NTU1NTU"},
      {"{\"json\":\"woohoo\"}", "eyJqc29uIjoid29vaG9vIn0"},
      {"{\"g\":{\"foo\":\"hh\"}}", "eyJnIjp7ImZvbyI6ImhoIn19"},
  };

  for (const auto& vector : kVectors) {
    const size_t encoded_size = std::strlen(vector.encoded);
    const size_t decoded_size = encoded_size * 6 / 8;
    assert(std::strlen(vector.decoded) == decoded_size);
    std::vector<V8> input(encoded_size);
    // The raw decoder allocates ceil(n * 6 / 8) output slots; the final,
    // partial Base64URL quantum leaves the extra slot unspecified.
    std::vector<V8> output((encoded_size * 6 + 7) / 8);
    for (size_t i = 0; i < encoded_size; ++i) {
      input[i] = logic.template vbit<8>(vector.encoded[i]);
    }
    decoder.base64_rawurl_decode(input.data(), output.data(), encoded_size);
    for (size_t i = 0; i < decoded_size; ++i) {
      assert(logic.eval(logic.veq(output[i],
                                  logic.template vbit<8>(vector.decoded[i]))) ==
             logic.konst(1));
    }
    assert(!backend.assertion_failed());
  }
}

void CheckCompiledCircuit() {
  using Field = GF2_128<>;
  using CompileBackend = CompilerBackend<Field>;
  using CompileLogic = Logic<Field, CompileBackend>;
  using EvalBackend = EvaluationBackend<Field>;
  using EvalLogic = Logic<Field, EvalBackend>;

  const Field field;
  QuadCircuit<Field> circuit(field);
  const CompileBackend compile_backend(&circuit);
  const CompileLogic compile_logic(&compile_backend, field);
  Base64Decoder<CompileLogic> decoder(compile_logic);
  const auto input = compile_logic.template vinput<8>();
  typename CompileLogic::template bitvec<6> output;
  decoder.decode(input, output);
  compile_logic.voutput(output, 0);
  const auto compiled = circuit.mkcircuit(1);

  const EvalBackend eval_backend(field, false);
  const EvalLogic eval_logic(&eval_backend, field);
  ProverLayers<Field> prover(field);
  for (size_t byte = 0; byte < 256; ++byte) {
    const auto witness_input = eval_logic.template vbit<8>(byte);
    auto witness = std::make_unique<Dense<Field>>(1, 1 + 8);
    witness->v_[0] = field.one();
    for (size_t bit = 0; bit < 8; ++bit) {
      witness->v_[1 + bit] = eval_logic.eval(witness_input[bit]).elt();
    }
    ProverLayers<Field>::inputs prover_inputs;
    const auto evaluated =
        prover.eval_circuit(&prover_inputs, compiled.get(), std::move(witness), field);
    const size_t expected = std::string(kBase64UrlAlphabet).find(byte);
    if (expected == std::string::npos) {
      assert(evaluated == nullptr);
    } else {
      assert(evaluated != nullptr);
      const auto wanted = eval_logic.template vbit<6>(expected);
      for (size_t bit = 0; bit < 6; ++bit) {
        assert(evaluated->v_[bit] == eval_logic.eval(wanted[bit]).elt());
      }
    }
  }
}

}  // namespace
}  // namespace proofs

int main() {
  proofs::CheckEverySymbol(proofs::p256_base);
  proofs::CheckDecodingVectors(proofs::p256_base);
  proofs::CheckCompiledCircuit();
  return 0;
}
