#include <array>
#include <cstdint>
#include <fstream>
#include <vector>

#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14.h"
#include "gf2k/lch14_reed_solomon.h"
#include "merkle/merkle_commitment.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_prover.h"
#include "ligero/ligero_verifier.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "random/transcript.h"
#include "sumcheck/quad_builder.h"

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
void append_digest(std::vector<uint8_t>& out, const proofs::Digest& digest) {
  out.insert(out.end(), digest.data, digest.data + proofs::Digest::kLength);
}
class CounterRng final : public proofs::RandomEngine {
 public:
  void bytes(uint8_t* out, size_t count) override {
    for (size_t index = 0; index != count; ++index) out[index] = next_++;
  }
 private:
  uint8_t next_ = 0;
};
proofs::Circuit<proofs::Fp256Base> CircuitFixture() {
  proofs::EQuad<proofs::Fp256Base> terms(2);
  terms.ec_[0] = {0, {0, 1}, proofs::p256_base.one()};
  terms.ec_[1] = {1, {1, 1}, proofs::p256_base.zero()};
  terms.canonicalize(proofs::p256_base);
  proofs::Circuit<proofs::Fp256Base> circuit{};
  circuit.nv = 2; circuit.logv = 1; circuit.nc = 1; circuit.logc = 0;
  circuit.nl = 1; circuit.npub_in = 1; circuit.subfield_boundary = 1; circuit.ninputs = 2;
  circuit.l.push_back({2, 1, proofs::QuadBuilder<proofs::Fp256Base>::compress(&terms, proofs::p256_base)});
  proofs::circuit_id(circuit.id, circuit, proofs::p256_base);
  return circuit;
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
  for (const auto count : {size_t{4}, size_t{5}}) {
    proofs::MerkleTree tree(count);
    std::vector<proofs::Digest> leaves(count);
    for (size_t index = 0; index != count; ++index) {
      leaves[index].data[0] = static_cast<uint8_t>(index + 1);
      tree.set_leaf(index, leaves[index]);
    }
    const auto root = tree.build_tree();
    const std::array<size_t, 2> positions = {1, count - 1};
    std::array<proofs::Digest, 2> opened = {leaves[positions[0]], leaves[positions[1]]};
    std::vector<proofs::Digest> proof;
    tree.generate_compressed_proof(proof, positions.data(), positions.size());
    std::vector<uint8_t> value; append_digest(value, root);
    for (const auto& node : proof) append_digest(value, node);
    const proofs::MerkleTreeVerifier verifier(count, root);
    value.push_back(static_cast<uint8_t>(verifier.verify_compressed_proof(proof.data(), proof.size(), opened.data(), positions.data(), positions.size())));
    proof.push_back(proofs::Digest{});
    value.push_back(static_cast<uint8_t>(verifier.verify_compressed_proof(proof.data(), proof.size(), opened.data(), positions.data(), positions.size())));
    record(output, count == 4 ? 40 : 41, value);
  }
  CounterRng merkle_rng;
  proofs::MerkleCommitment commitment(4);
  const auto commitment_root = commitment.commit([](size_t, proofs::SHA256& sha) {
    const std::array<uint8_t, 2> leaf = {0xa5, 0x5a};
    sha.Update(leaf.data(), leaf.size());
  }, merkle_rng);
  const std::array<size_t, 2> commitment_positions = {1, 3};
  proofs::MerkleProof commitment_proof(commitment_positions.size());
  commitment.open(commitment_proof, commitment_positions.data(), commitment_positions.size());
  std::vector<uint8_t> commitment_value; append_digest(commitment_value, commitment_root);
  for (const auto& nonce : commitment_proof.nonce) commitment_value.insert(commitment_value.end(), nonce.bytes, nonce.bytes + proofs::MerkleNonce::kLength);
  for (const auto& node : commitment_proof.path) append_digest(commitment_value, node);
  const auto update_commitment = [](size_t, proofs::SHA256& sha) { const std::array<uint8_t, 2> leaf = {0xa5, 0x5a}; sha.Update(leaf.data(), leaf.size()); };
  commitment_value.push_back(static_cast<uint8_t>(proofs::MerkleCommitmentVerifier::verify(4, commitment_root, commitment_proof, commitment_positions.data(), commitment_positions.size(), update_commitment)));
  commitment_proof.path.push_back(proofs::Digest{});
  commitment_value.push_back(static_cast<uint8_t>(proofs::MerkleCommitmentVerifier::verify(4, commitment_root, commitment_proof, commitment_positions.data(), commitment_positions.size(), update_commitment)));
  record(output, 42, commitment_value);
  const auto circuit = CircuitFixture();
  proofs::CircuitWriter<proofs::Fp256Base> circuit_writer(proofs::p256_base, proofs::P256_ID);
  std::vector<uint8_t> lfc1, lfc2; circuit_writer.to_bytes(circuit, lfc1); circuit_writer.to_bytes(circuit, lfc2, proofs::CircuitFormat::kLfc2);
  std::vector<uint8_t> circuit_value = lfc1; append(circuit_value, lfc2); circuit_value.insert(circuit_value.end(), circuit.id, circuit.id + proofs::CircuitIO::kIdSize);
  proofs::ByteCursor lfc1_cursor(lfc1.data(), lfc1.size()), lfc2_cursor(lfc2.data(), lfc2.size()); proofs::CircuitReader<proofs::Fp256Base> circuit_reader(proofs::p256_base, proofs::P256_ID);
  circuit_value.push_back(static_cast<uint8_t>(circuit_reader.from_bytes(lfc1_cursor, true) != nullptr)); circuit_value.push_back(static_cast<uint8_t>(circuit_reader.from_bytes(lfc2_cursor, true) != nullptr));
  lfc2.push_back(0); proofs::ByteCursor trailing(lfc2.data(), lfc2.size()); circuit_value.push_back(static_cast<uint8_t>(circuit_reader.from_bytes(trailing, true) != nullptr));
  lfc2.pop_back(); lfc2.insert(lfc2.begin() + 4, 0x80); proofs::ByteCursor nonminimal(lfc2.data(), lfc2.size()); circuit_value.push_back(static_cast<uint8_t>(circuit_reader.from_bytes(nonminimal, true) != nullptr));
  auto truncated_lfc1 = lfc1; truncated_lfc1.pop_back(); proofs::ByteCursor truncated_lfc1_cursor(truncated_lfc1.data(), truncated_lfc1.size()); circuit_value.push_back(static_cast<uint8_t>(circuit_reader.from_bytes(truncated_lfc1_cursor, true) != nullptr));
  auto trailing_lfc1 = lfc1; trailing_lfc1.push_back(0); proofs::ByteCursor trailing_lfc1_cursor(trailing_lfc1.data(), trailing_lfc1.size()); circuit_value.push_back(static_cast<uint8_t>(circuit_reader.from_bytes(trailing_lfc1_cursor, true) != nullptr));
  record(output, 50, circuit_value);
  proofs::LigeroParam<proofs::GF2_128<>> ligero_geometry(8, 2, 4, 2, 64);
  std::vector<uint8_t> ligero_value;
  for (const size_t value : {ligero_geometry.block, ligero_geometry.dblock, ligero_geometry.block_enc,
                             ligero_geometry.w, ligero_geometry.nrow, ligero_geometry.nreq,
                             ligero_geometry.mc_pathlen}) ligero_value.push_back(static_cast<uint8_t>(value));
  record(output, 60, ligero_value);
  proofs::LCH14ReedSolomonFactory<proofs::GF2_128<>> ligero_rs(gf);
  std::vector<proofs::GF2_128<>::Elt> ligero_w(ligero_geometry.nw);
  for (auto& value : ligero_w) value = gf.sample([&](size_t count, uint8_t* bytes) { merkle_rng.bytes(bytes, count); });
  std::vector<proofs::LigeroQuadraticConstraint> ligero_lqc(ligero_geometry.nq);
  for (size_t index = 0; index != ligero_lqc.size(); ++index) ligero_lqc[index] = {0, 0, 2 * index + 1};
  for (const auto& constraint : ligero_lqc) ligero_w[constraint.z] = gf.mulf(ligero_w[constraint.x], ligero_w[constraint.y]);
  const std::array<uint8_t, 4> ligero_seed = {'t', 'e', 's', 't'};
  proofs::Transcript ligero_transcript(ligero_seed.data(), ligero_seed.size());
  proofs::LigeroProver<proofs::GF2_128<>, proofs::LCH14ReedSolomonFactory<proofs::GF2_128<>>> ligero_prover(ligero_geometry);
  proofs::LigeroCommitment<proofs::GF2_128<>> ligero_commitment;
  ligero_prover.commit(ligero_commitment, ligero_transcript, ligero_w.data(), 0, ligero_lqc.data(), ligero_rs, merkle_rng, gf);
  std::vector<uint8_t> ligero_commitment_value; append_digest(ligero_commitment_value, ligero_commitment.root);
  record(output, 61, ligero_commitment_value);
  std::array<proofs::GF2_128<>::Elt, 1> ligero_b = {gf.zero()};
  const proofs::LigeroHash ligero_statement = {0xba, 0xad, 0xf0, 0x0d};
  proofs::LigeroProof<proofs::GF2_128<>> ligero_proof(&ligero_geometry);
  ligero_prover.prove(ligero_proof, ligero_transcript, 1, 0, nullptr, ligero_statement, ligero_lqc.data(), ligero_rs, gf);
  std::vector<uint8_t> ligero_proof_value; append_digest(ligero_proof_value, ligero_commitment.root); ligero_proof_value.push_back(static_cast<uint8_t>(ligero_proof.merkle.path.size()));
  record(output, 62, ligero_proof_value);
  proofs::Transcript ligero_verify_transcript(ligero_seed.data(), ligero_seed.size());
  proofs::LigeroVerifier<proofs::GF2_128<>, proofs::LCH14ReedSolomonFactory<proofs::GF2_128<>>>::receive_commitment(ligero_commitment, ligero_verify_transcript);
  const char* ligero_why = nullptr;
  const bool ligero_ok = proofs::LigeroVerifier<proofs::GF2_128<>, proofs::LCH14ReedSolomonFactory<proofs::GF2_128<>>>::verify(&ligero_why, ligero_geometry, ligero_commitment, ligero_proof, ligero_verify_transcript, 1, 0, nullptr, ligero_statement, ligero_b.data(), ligero_lqc.data(), ligero_rs, gf);
  auto ligero_tampered = ligero_proof;
  ligero_tampered.merkle.path[0].data[0] ^= 1;
  proofs::Transcript ligero_tampered_transcript(ligero_seed.data(), ligero_seed.size());
  proofs::LigeroVerifier<proofs::GF2_128<>, proofs::LCH14ReedSolomonFactory<proofs::GF2_128<>>>::receive_commitment(ligero_commitment, ligero_tampered_transcript);
  const char* ligero_tampered_why = nullptr;
  const bool ligero_tampered_ok = proofs::LigeroVerifier<proofs::GF2_128<>, proofs::LCH14ReedSolomonFactory<proofs::GF2_128<>>>::verify(&ligero_tampered_why, ligero_geometry, ligero_commitment, ligero_tampered, ligero_tampered_transcript, 1, 0, nullptr, ligero_statement, ligero_b.data(), ligero_lqc.data(), ligero_rs, gf);
  record(output, 63, {static_cast<uint8_t>(ligero_ok), static_cast<uint8_t>(ligero_tampered_ok)});
  return output ? 0 : 66;
}
