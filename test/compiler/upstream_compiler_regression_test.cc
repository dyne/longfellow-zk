// Portable adaptations of Google Longfellow compiler_test and
// canonicalization_test; intentionally standalone (no GoogleTest dependency).
#include <cassert>
#include <cstddef>
#include <memory>

#include "algebra/fp.h"
#include "circuits/compiler/compiler.h"

namespace proofs {
namespace {
using Field = Fp<1>;
const Field kField("18446744073709551557");

// Google compiler_test's prover/verifier execution case is intentionally not
// imported: it requires Google-only sumcheck/testing.h, absent from the
// European public source closure.  Its portable circuit-construction coverage
// is retained below together with all canonicalization cases.

void OutputAndAssertionScheduling() {
  QuadCircuit<Field> q(kField);
  const size_t a = q.input_wire();
  const size_t b = q.input_wire();
  const size_t c = q.input_wire();
  q.output_wire(a, 0);
  q.output_wire(q.mul(b, c), 1);
  q.assert0(q.sub(q.add(a, b), c));
  const auto circuit = q.mkcircuit(1);
  assert(circuit->ninputs == 4);  // The compiler reserves its constant-one input.
  assert(q.nwires_ >= 5);  // one, three inputs, multiply, and copied output.
  assert(q.nquad_terms_ > 0);
}

std::unique_ptr<Circuit<Field>> CanonicalProduct(bool reordered) {
  QuadCircuit<Field> q(kField);
  const size_t a = q.input_wire();
  const size_t b = q.input_wire();
  const size_t c = q.input_wire();
  const size_t d = q.input_wire();
  const size_t ab = reordered ? q.mul(b, a) : q.mul(a, b);
  const size_t cd = q.mul(c, d);
  if (reordered) {
    (void)q.add(a, b);  // Deliberately unused canonicalization noise.
    (void)q.sub(d, ab);
  }
  q.output_wire(q.mul(ab, cd), 0);
  return q.mkcircuit(1);
}

void CanonicalizationIsOrderIndependent() {
  const auto direct = CanonicalProduct(false);
  const auto reordered = CanonicalProduct(true);
  for (size_t i = 0; i < sizeof(direct->id); ++i) {
    assert(direct->id[i] == reordered->id[i]);
  }
}
}  // namespace
}  // namespace proofs

int main() {
  proofs::OutputAndAssertionScheduling();
  proofs::CanonicalizationIsOrderIndependent();
  return 0;
}
