#include <array>
#include <cstdint>
#include <fstream>
#include <vector>

#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14.h"
#include "gf2k/lch14_reed_solomon.h"
#include "random/transcript.h"

namespace {
void u32(std::ofstream& out, uint32_t value) {
  for (unsigned i = 0; i != 4; ++i) out.put(static_cast<char>(value >> (8 * i)));
}
void record(std::ofstream& out, uint32_t key, const std::vector<uint8_t>& value) {
  out.write("LFP2", 4); out.put(1); out.put(1); u32(out, 5 + value.size());
  u32(out, key); out.put(1);
  out.write(reinterpret_cast<const char*>(value.data()), value.size());
}
std::vector<uint8_t> draw(proofs::Transcript& t, size_t n) {
  std::vector<uint8_t> out(n); t.bytes(out.data(), out.size()); return out;
}
void append(std::vector<uint8_t>& to, const std::vector<uint8_t>& from) {
  to.insert(to.end(), from.begin(), from.end());
}
template <class Field>
void append_field(std::vector<uint8_t>& out, const Field& field,
                  const typename Field::Elt& value) {
  std::array<uint8_t, Field::kBytes> bytes{};
  field.to_bytes_field(bytes.data(), value);
  out.insert(out.end(), bytes.begin(), bytes.end());
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) return 64;
  std::ifstream input(argv[1], std::ios::binary);
  std::ofstream output(argv[2], std::ios::binary);
  if (!input || !output) return 65;
  const std::array<uint8_t, 3> binary = {1, 2, 3};
  proofs::Transcript empty(nullptr, 0); record(output, 1, draw(empty, 31));
  proofs::Transcript boundaries(binary.data(), binary.size());
  boundaries.write0(0); boundaries.write0(31); boundaries.write0(32); boundaries.write0(33);
  record(output, 2, draw(boundaries, 33));
  proofs::Transcript typed(binary.data(), binary.size());
  const auto one = proofs::p256_base.one();
  const std::array<proofs::Fp256Base::Elt, 2> values = {one, proofs::p256_base.of_scalar(7)};
  typed.write(one, proofs::p256_base); typed.write(values.data(), 1, values.size(), proofs::p256_base);
  record(output, 3, draw(typed, 32));
  proofs::Transcript cloned(binary.data(), binary.size()); (void)draw(cloned, 5); auto clone = cloned.clone();
  auto clone_bytes = draw(cloned, 29); append(clone_bytes, draw(clone, 29)); record(output, 4, clone_bytes);
  proofs::Transcript changed(binary.data(), binary.size()); (void)draw(changed, proofs::kPRFOutputSize);
  auto changed_clone = changed.clone(); changed_clone.write(binary.data(), binary.size());
  auto changed_bytes = draw(changed, 33); append(changed_bytes, draw(changed_clone, 33)); record(output, 5, changed_bytes);
  proofs::Transcript compatibility(binary.data(), binary.size()); record(output, 6, draw(compatibility, 25600));
  proofs::GF2_128<> gf;
  const auto ga = gf.of_scalar_field(0x8000000000000043ULL), gb = gf.of_scalar_field(0x123456789abcdef0ULL);
  std::vector<uint8_t> gf_values; append_field(gf_values, gf, gf.addf(ga, gb)); append_field(gf_values, gf, gf.mulf(ga, gb)); append_field(gf_values, gf, gf.invertf(ga));
  record(output, 10, gf_values);
  const auto pa = proofs::p256_base.of_scalar(7), pb = proofs::p256_base.of_scalar(19);
  std::vector<uint8_t> p_values; append_field(p_values, proofs::p256_base, proofs::p256_base.addf(pa, pb)); append_field(p_values, proofs::p256_base, proofs::p256_base.mulf(pa, pb)); append_field(p_values, proofs::p256_base, proofs::p256_base.invertf(pa));
  record(output, 11, p_values);
  const auto qa = proofs::p256_scalar.of_scalar(7), qb = proofs::p256_scalar.of_scalar(19);
  std::vector<uint8_t> q_values; append_field(q_values, proofs::p256_scalar, proofs::p256_scalar.addf(qa, qb)); append_field(q_values, proofs::p256_scalar, proofs::p256_scalar.mulf(qa, qb)); append_field(q_values, proofs::p256_scalar, proofs::p256_scalar.invertf(qa));
  record(output, 12, q_values);
  std::array<uint8_t, proofs::Fp256Base::kBytes> noncanonical{}; noncanonical.fill(0xff);
  record(output, 13, {static_cast<uint8_t>(proofs::p256_base.of_bytes_field(noncanonical.data()).has_value())});
  std::vector<uint8_t> boundary_values;
  for (const auto& value : {gf.zero(), gf.one(), gf.of_scalar(0xa55a)}) { std::array<uint8_t, 2> bytes{}; gf.to_bytes_subfield(bytes.data(), value); boundary_values.insert(boundary_values.end(), bytes.begin(), bytes.end()); }
  for (const auto& value : {proofs::p256_base.zero(), proofs::p256_base.one(), proofs::p256_base.of_scalar(0x80000000)}) append_field(boundary_values, proofs::p256_base, value);
  for (const auto& value : {proofs::p256_scalar.zero(), proofs::p256_scalar.one(), proofs::p256_scalar.of_scalar(0x80000000)}) append_field(boundary_values, proofs::p256_scalar, value);
  record(output, 14, boundary_values);
  // C++ decoding accepts a fixed-width pointer, so wrong-length input is not a
  // recoverable comparable API; record canonical decode outcomes only.
  std::vector<uint8_t> extended_fields;
  auto extend_field = [&]<class Field>(const Field& field) {
    auto a = field.of_scalar(23), b = field.of_scalar(7); append_field(extended_fields, field, field.subf(a, b)); append_field(extended_fields, field, field.mulf(a, a)); append_field(extended_fields, field, field.addf(a, a));
    std::array<uint8_t, 32> encoded{}; field.to_bytes_field(encoded.data(), a); extended_fields.push_back(static_cast<uint8_t>(field.zero() == field.zero())); extended_fields.push_back(static_cast<uint8_t>(field.one() == field.one())); extended_fields.push_back(static_cast<uint8_t>(a == field.of_scalar(23))); extended_fields.push_back(static_cast<uint8_t>(field.of_bytes_field(encoded.data()).has_value()));
  }; extend_field(proofs::p256_base); extend_field(proofs::p256_scalar);
  record(output, 15, extended_fields);
  proofs::LCH14<proofs::GF2_128<>> lch(gf);
  std::array<proofs::GF2_128<>::Elt, 8> fft_values{};
  for (size_t i = 0; i != fft_values.size(); ++i) fft_values[i] = gf.of_scalar_field(i + 1);
  lch.FFT(3, 1, fft_values.data()); std::vector<uint8_t> coding_values;
  for (const auto& value : fft_values) append_field(coding_values, gf, value);
  lch.IFFT(3, 1, fft_values.data()); for (const auto& value : fft_values) append_field(coding_values, gf, value);
  record(output, 20, coding_values);
  std::array<proofs::GF2_128<>::Elt, 13> rs_values{};
  for (size_t i = 0; i != 5; ++i) rs_values[i] = gf.of_scalar_field(i + 1);
  proofs::LCH14ReedSolomon<proofs::GF2_128<>> rs(5, rs_values.size(), gf); rs.interpolate(rs_values.data());
  std::vector<uint8_t> rs_output; for (const auto& value : rs_values) append_field(rs_output, gf, value); record(output, 21, rs_output);
  std::array<proofs::GF2_128<>::Elt, 8> rs_boundary{}; for (size_t i = 0; i != rs_boundary.size(); ++i) rs_boundary[i] = gf.of_scalar_field(i + 1); proofs::LCH14ReedSolomon<proofs::GF2_128<>> rs_identity(8, 8, gf); rs_identity.interpolate(rs_boundary.data()); std::vector<uint8_t> rs_boundary_output; for (const auto& value : rs_boundary) append_field(rs_boundary_output, gf, value); record(output, 24, rs_boundary_output);
  std::array<proofs::GF2_128<>::Elt, 8> rs_three{}; for (size_t i = 0; i != 3; ++i) rs_three[i] = gf.of_scalar_field((i + 1) * 17); proofs::LCH14ReedSolomon<proofs::GF2_128<>> rs_three_to_eight(3, 8, gf); rs_three_to_eight.interpolate(rs_three.data()); std::vector<uint8_t> rs_three_output; for (const auto& value : rs_three) append_field(rs_three_output, gf, value); record(output, 25, rs_three_output);
  std::vector<uint8_t> basis_values; for (size_t i = 0; i != gf.kSubFieldBits; ++i) append_field(basis_values, gf, gf.beta(i)); record(output, 22, basis_values);
  std::array<proofs::GF2_128<>::Elt, 4> short_fft{}; short_fft[0] = gf.one(); lch.FFT(2, 0, short_fft.data()); std::vector<uint8_t> extra_coding; for (const auto& value : short_fft) append_field(extra_coding, gf, value); lch.IFFT(2, 0, short_fft.data()); for (const auto& value : short_fft) append_field(extra_coding, gf, value); record(output, 23, extra_coding);
  auto generator = proofs::p256.generator(); auto doubled = proofs::p256.doubleEf(generator); auto tripled = proofs::p256.scalar_multf(generator, proofs::P256::N(3));
  proofs::p256.normalize(generator); proofs::p256.normalize(doubled); proofs::p256.normalize(tripled);
  std::vector<uint8_t> curve_values; for (const auto* point : {&generator, &doubled, &tripled}) { append_field(curve_values, proofs::p256_base, point->x); append_field(curve_values, proofs::p256_base, point->y); } record(output, 30, curve_values);
  auto scalar_two = proofs::p256.scalar_multf(proofs::p256.generator(), proofs::P256::N(2)); auto order_minus_one = proofs::n256_order; order_minus_one.sub(proofs::P256::N(1)); auto scalar_boundary = proofs::p256.scalar_multf(proofs::p256.generator(), order_minus_one); proofs::p256.normalize(scalar_two); proofs::p256.normalize(scalar_boundary); std::vector<uint8_t> curve_scalars; for (const auto* point : {&scalar_two, &scalar_boundary}) { append_field(curve_scalars, proofs::p256_base, point->x); append_field(curve_scalars, proofs::p256_base, point->y); } record(output, 32, curve_scalars);
  auto added = proofs::p256.addEf(proofs::p256.generator(), scalar_two); proofs::p256.normalize(added); std::vector<uint8_t> curve_add; append_field(curve_add, proofs::p256_base, added.x); append_field(curve_add, proofs::p256_base, added.y); record(output, 35, curve_add);
  auto seeded = proofs::p256.scalar_multf(proofs::p256.generator(), proofs::P256::N("0x123456789abcdef00112233445566778899aabbccddeeff0011223344556677")); proofs::p256.normalize(seeded); std::vector<uint8_t> seeded_curve; append_field(seeded_curve, proofs::p256_base, seeded.x); append_field(seeded_curve, proofs::p256_base, seeded.y); record(output, 33, seeded_curve);
  auto negative = proofs::p256.generator(); proofs::p256_base.neg(negative.y); std::vector<uint8_t> curve_law; proofs::p256.normalize(negative); append_field(curve_law, proofs::p256_base, negative.x); append_field(curve_law, proofs::p256_base, negative.y); record(output, 31, curve_law);
  const auto identity = proofs::p256.zero(); record(output, 34, {static_cast<uint8_t>(proofs::p256.zerop(identity))});
  return output ? 0 : 66;
}
