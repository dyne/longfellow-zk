// Portable adaptations of Google Longfellow's gf2_128_test, lch14_test, and
// lch14_reed_solomon_test.  GoogleTest, benchmark, and Bogorng dependencies
// are deliberately replaced with deterministic standalone assertions.
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "gf2k/gf2_128.h"
#include "gf2k/lch14.h"
#include "gf2k/lch14_reed_solomon.h"

namespace proofs {
namespace {
// Google's Reed-Solomon regression uses the 32-element subfield so a
// 16-symbol codeword remains inside the source-compatible evaluation domain.
using Field = GF2_128<5>;
using Elt = Field::Elt;

Elt EvalMonomial(const Field& field, const std::vector<Elt>& coefficients,
                 const Elt& x) {
  Elt result = field.zero();
  for (size_t index = coefficients.size(); index-- > 0;)
    result = field.addf(coefficients[index], field.mulf(result, x));
  return result;
}

void FieldConstantsAndSerialization() {
  const Field field;
  assert(field.zero() == field.of_scalar_field(0));
  assert(field.one() == field.of_scalar_field(1));
  assert(field.x() == field.of_scalar_field(2));
  assert(field.mulf(field.x(), field.invx()) == field.one());

  for (uint64_t value = 1; value != 128; ++value) {
    const Elt element = field.of_scalar(value);
    assert(field.in_subfield(element));
    assert(field.mulf(element, field.invertf(element)) == field.one());
    std::array<uint8_t, Field::kSubFieldBytes> encoded{};
    field.to_bytes_subfield(encoded.data(), element);
    assert(field.of_bytes_subfield(encoded.data()).value() == element);
  }
}

void Lch14RoundTrip() {
  const Field field;
  LCH14<Field> fft(field);
  constexpr size_t kLogSize = 4;
  std::array<Elt, size_t{1} << kLogSize> values{};
  const auto original = values;
  for (size_t index = 0; index != values.size(); ++index)
    values[index] = field.of_scalar((index * index + 42) & 0x1fu);
  const auto expected = values;
  fft.FFT(kLogSize, 0, values.data());
  fft.IFFT(kLogSize, 0, values.data());
  assert(values == expected);
  (void)original;
}

void ReedSolomonInterpolation() {
  const Field field;
  LCH14ReedSolomonFactory<Field> factory(field);
  for (const size_t codeword_size : {size_t{7}, size_t{8}, size_t{9}, size_t{64}}) {
    for (size_t message_size = 1; message_size < codeword_size; ++message_size) {
      auto code = factory.make(message_size, codeword_size);
      std::vector<Elt> coefficients(message_size);
      std::vector<Elt> evaluations(codeword_size);
      for (size_t index = 0; index != message_size; ++index)
        coefficients[index] = field.of_scalar(
            index * index + 42 + (codeword_size + 11) * (message_size + 22));
      for (size_t index = 0; index != message_size; ++index)
        evaluations[index] = EvalMonomial(field, coefficients, field.of_scalar(index));
      code->interpolate(evaluations.data());
      for (size_t index = 0; index != evaluations.size(); ++index)
        assert(evaluations[index] == EvalMonomial(field, coefficients, field.of_scalar(index)));
    }
  }
}
}  // namespace
}  // namespace proofs

int main() {
  proofs::FieldConstantsAndSerialization();
  proofs::Lch14RoundTrip();
  proofs::ReedSolomonInterpolation();
  return 0;
}
