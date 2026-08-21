// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "random/transcript.h"

namespace proofs {
namespace {

constexpr std::array<uint8_t, 7> kLabel = {'c', 'l', 'o', 'n', 'e', '-', '1'};

void require(bool condition, const char* why) {
  if (!condition) {
    std::cerr << "not ok - " << why << '\n';
    std::exit(1);
  }
}

Transcript new_transcript() { return Transcript(kLabel.data(), kLabel.size()); }

template <size_t N>
std::array<uint8_t, N> draw(Transcript& transcript) {
  std::array<uint8_t, N> out{};
  transcript.bytes(out.data(), out.size());
  return out;
}

template <size_t N>
void require_equal(const std::array<uint8_t, N>& left,
                   const std::array<uint8_t, N>& right, const char* why) {
  require(std::memcmp(left.data(), right.data(), left.size()) == 0, why);
}

std::array<uint8_t, kPRFKeySize> proof_bytes(Transcript& transcript) {
  std::array<uint8_t, kPRFKeySize> out{};
  transcript.get(out.data());
  return out;
}

void test_before_first_draw() {
  auto original = new_transcript();
  auto clone = original.clone();
  require_equal(draw<31>(original), draw<31>(clone),
                "clone before first draw changed PRF output");
  require_equal(proof_bytes(original), proof_bytes(clone),
                "drawing changed transcript proof bytes");
}

void test_block_boundary() {
  auto original = new_transcript();
  (void)draw<kPRFOutputSize>(original);
  auto clone = original.clone();
  require_equal(draw<29>(original), draw<29>(clone),
                "clone at PRF block boundary changed output");
}

void test_mid_block() {
  auto original = new_transcript();
  (void)draw<5>(original);
  auto clone = original.clone();
  require_equal(draw<29>(original), draw<29>(clone),
                "clone in a PRF block lost read position");
}

void test_multiple_blocks() {
  auto original = new_transcript();
  (void)draw<kPRFOutputSize + 7>(original);
  auto clone = original.clone();
  require_equal(draw<kPRFOutputSize + 9>(original),
                draw<kPRFOutputSize + 9>(clone),
                "clone after multiple PRF blocks lost state");
}

void test_write_invalidates_only_the_written_clone() {
  auto original = new_transcript();
  (void)draw<5>(original);
  auto original_control = original.clone();
  auto changed = original.clone();
  const std::array<uint8_t, 3> data = {1, 2, 3};
  changed.write(data.data(), data.size());

  require_equal(draw<33>(original), draw<33>(original_control),
                "writing a clone changed the original PRF state");

  auto expected = new_transcript();
  expected.write(data.data(), data.size());
  require_equal(draw<33>(changed), draw<33>(expected),
                "writing a clone did not invalidate its PRF state");
}

void test_independent_advance() {
  auto original = new_transcript();
  (void)draw<6>(original);
  auto clone = original.clone();
  auto original_reference = original.clone();
  auto clone_reference = clone.clone();

  require_equal(draw<41>(original), draw<41>(original_reference),
                "original changed while clone remained idle");
  require_equal(draw<7>(clone), draw<7>(clone_reference),
                "clone changed while original advanced");
  require_equal(draw<19>(original), draw<19>(original_reference),
                "original did not advance independently");
  require_equal(draw<53>(clone), draw<53>(clone_reference),
                "clone did not advance independently");
}

}  // namespace
}  // namespace proofs

int main() {
  proofs::test_before_first_draw();
  proofs::test_block_boundary();
  proofs::test_mid_block();
  proofs::test_multiple_blocks();
  proofs::test_write_invalidates_only_the_written_clone();
  proofs::test_independent_advance();
  return 0;
}
