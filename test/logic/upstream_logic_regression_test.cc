// Portable adaptations of Google Longfellow logic primitive tests.
#include <array>
#include <cassert>
#include <cstddef>

#include "algebra/fp.h"
#include "algebra/poly.h"
#include "circuits/logic/bit_adder.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/counter.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/memcmp.h"
#include "circuits/logic/polynomial.h"
#include "circuits/logic/routing.h"

namespace proofs {
namespace {
using Field = Fp<1>;
const Field kField("18446744073709551557");
using Backend = EvaluationBackend<Field>;
using Circuit = Logic<Field, Backend>;

void BitAdderAndLogic() {
  constexpr size_t kWidth = 4;
  const Backend backend(kField, false);
  const Circuit logic(&backend, kField);
  BitAdder<Circuit, kWidth> adder(logic);
  // Full upstream-width vector space, including a deliberately wrong sum.
  for (size_t a = 0; a < 16; ++a) {
    for (size_t b = 0; b < 16; ++b) {
      for (size_t c = 0; c < 16; ++c) {
        const auto sum = (a + b + c) & 15u;
        adder.assert_eqmod(logic.vbit<kWidth>(sum),
                           adder.add({logic.vbit<kWidth>(a), logic.vbit<kWidth>(b), logic.vbit<kWidth>(c)}), 3);
        assert(!backend.assertion_failed());
        adder.assert_eqmod(logic.vbit<kWidth>((sum + 1) & 15u),
                           adder.add({logic.vbit<kWidth>(a), logic.vbit<kWidth>(b), logic.vbit<kWidth>(c)}), 3);
        assert(backend.assertion_failed());
      }
    }
  }
  assert(logic.eval(logic.lxor(logic.bit(1), logic.bit(1))).elt() == kField.zero());
  assert(logic.eval(logic.lor(logic.bit(1), logic.bit(0))).elt() == kField.one());
}

void BitPluckerAndCounter() {
  const Backend backend(kField, false);
  const Circuit logic(&backend, kField);
  BitPlucker<Circuit, 3> plucker(logic);
  for (size_t value = 0; value < 8; ++value) {
    const auto packed = logic.konst(bit_plucker_point<Field, 8>()(value, kField));
    const auto bits = plucker.pluck(packed);
    for (size_t bit = 0; bit < 3; ++bit) assert(logic.eval(bits[bit]).elt() == kField.of_scalar((value >> bit) & 1));
  }
  std::array<Circuit::EltW, 4> mux_input{logic.konst(11), logic.konst(22), logic.konst(33), logic.konst(44)};
  EltMuxer<Circuit, 4> mux(logic, mux_input.data());
  for (size_t index = 0; index < 4; ++index) {
    const auto encoded = bit_plucker_point<Field, 4>()(index, kField);
    assert(mux.mux(logic.konst(encoded)).elt() == kField.of_scalar(11 * (index + 1)));
  }
  Counter<Circuit> counter(logic);
  for (size_t value : {size_t{0}, size_t{1}, size_t{7}, size_t{31}}) {
    const auto actual = counter.add(counter.as_counter(value), counter.mone());
    counter.assert0(actual);
    assert(backend.assertion_failed() == (value != 1));
  }
}

void MemcmpPolynomialAndRouting() {
  const Backend backend(kField, false);
  const Circuit logic(&backend, kField);
  Memcmp<Circuit> memcmp(logic);
  std::array<Circuit::v8, 3> a{logic.vbit<8>(1), logic.vbit<8>(2), logic.vbit<8>(3)};
  std::array<Circuit::v8, 3> b{logic.vbit<8>(1), logic.vbit<8>(2), logic.vbit<8>(4)};
  assert(logic.eval(memcmp.lt(a.size(), a.data(), b.data())).elt() == kField.one());
  assert(logic.eval(memcmp.leq(a.size(), b.data(), a.data())).elt() == kField.zero());

  Poly<5, Field> polynomial;
  for (size_t i = 0; i < 5; ++i) polynomial[i] = kField.of_scalar(i * i + 3);
  Polynomial<Circuit> evaluator(logic);
  for (size_t x : {size_t{0}, size_t{1}, size_t{17}, size_t{101}}) {
    const auto expected = polynomial.eval_monomial(kField.of_scalar(x), kField);
    assert(evaluator.eval(polynomial, logic.konst(kField.of_scalar(x))).elt() == expected);
    assert(evaluator.eval_horner(polynomial, logic.konst(kField.of_scalar(x))).elt() == expected);
  }

  Routing<Circuit> routing(logic);
  std::array<Circuit::BitW, 2> shift{};
  logic.bits(2, shift.data(), 1);
  std::array<Circuit::EltW, 4> input{logic.konst(10), logic.konst(20), logic.konst(30), logic.konst(40)};
  std::array<Circuit::EltW, 4> output{};
  routing.shift(2, shift.data(), output.size(), output.data(), input.size(), input.data(), logic.konst(99), 1);
  assert(output[0].elt() == kField.of_scalar(20));
  assert(output[2].elt() == kField.of_scalar(40));
  assert(output[3].elt() == kField.of_scalar(99));
}

void CompiledPrimitivePath() {
  QuadCircuit<Field> circuit(kField);
  using CompileBackend = CompilerBackend<Field>;
  using CompileLogic = Logic<Field, CompileBackend>;
  const CompileBackend backend(&circuit);
  const CompileLogic logic(&backend, kField);
  BitPlucker<CompileLogic, 2> plucker(logic);
  const auto bits = plucker.pluck(logic.eltw_input());
  logic.vassert_is_bit(bits);
  Memcmp<CompileLogic> memcmp(logic);
  std::array<CompileLogic::v8, 2> left{logic.vinput<8>(), logic.vinput<8>()};
  std::array<CompileLogic::v8, 2> right{logic.vinput<8>(), logic.vinput<8>()};
  logic.assert1(memcmp.leq(left.size(), left.data(), right.data()));
  const auto compiled = circuit.mkcircuit(1);
  assert(compiled->ninputs > 0);
  assert(circuit.nquad_terms_ > 0);
}
}  // namespace
}  // namespace proofs

int main() {
  proofs::BitAdderAndLogic();
  proofs::BitPluckerAndCounter();
  proofs::MemcmpPolynomialAndRouting();
  proofs::CompiledPrimitivePath();
  return 0;
}
