// Portable adaptations of Google Longfellow's quad_test and sumcheck_test.
// The upstream execution cases require sumcheck/prover.h and sumcheck/verifier.h
// (and their Google-only proof harness), which are not in this source tree.
// Retained cases exercise the complete local EQuad -> Quad construction path.
#include <cassert>
#include <cstddef>
#include <memory>
#include <vector>

#include "algebra/fp.h"
#include "sumcheck/equad.h"
#include "sumcheck/quad.h"
#include "sumcheck/quad_builder.h"

namespace proofs {
namespace {
using Field = Fp<1>;
using Elt = Field::Elt;
const Field kField("18446744073709551557");

void CompressionPreservesCanonicalTerms() {
  using EQuadT = EQuad<Field>;
  auto expanded = std::make_unique<EQuadT>(4);
  expanded->ec_[0] = {.g = 2, .h = {3, 1}, .v = kField.of_scalar(7)};
  expanded->ec_[1] = {.g = 1, .h = {0, 2}, .v = kField.of_scalar(5)};
  expanded->ec_[2] = {.g = 2, .h = {1, 3}, .v = kField.of_scalar(11)};
  expanded->ec_[3] = {.g = 0, .h = {1, 1}, .v = kField.of_scalar(13)};
  expanded->canonicalize(kField);

  const auto compressed = QuadBuilder<Field>::compress(expanded.get(), kField);
  assert(compressed->size() == 3);
  std::vector<typename EQuadT::ecorner> terms;
  for (const auto& term : *compressed) terms.push_back(term);
  assert(terms.size() == 3);
  assert(terms[0].g == 0 && terms[0].h[0] == 1 && terms[0].h[1] == 1);
  assert(terms[1].g == 1 && terms[1].h[0] == 0 && terms[1].h[1] == 2);
  assert(terms[2].g == 2 && terms[2].h[0] == 1 && terms[2].h[1] == 3);
  assert(terms[2].v == kField.of_scalar(18));
}

void DeltaTableDeduplicatesStableRows() {
  ApproximateDeltaTableBuilder<Field> builder(8);
  builder.dedup(1, 2, 3, 4);
  builder.dedup(5, 6, 7, 8);
  builder.dedup(1, 2, 3, 4);
  const auto table = builder.delta_table();
  assert(table->size() >= 2);
  assert(table->size() <= 3);
}
}  // namespace
}  // namespace proofs

int main() {
  proofs::CompressionPreservesCanonicalTerms();
  proofs::DeltaTableDeduplicatesStableRows();
  return 0;
}
