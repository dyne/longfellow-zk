// LFC2 storage regression tests: deterministic bytes and LFC1 equivalence.
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#include "ec/p256.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "sumcheck/quad_builder.h"
#include "util/byte_cursor.h"

namespace {
using Field = proofs::Fp256Base;

void require(bool condition, const char* message) {
  if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}

proofs::Circuit<Field> make_circuit() {
  proofs::EQuad<Field> terms(2);
  terms.ec_[0] = {0, {0, 1}, proofs::p256_base.one()};
  terms.ec_[1] = {1, {1, 1}, proofs::p256_base.zero()};
  terms.canonicalize(proofs::p256_base);
  proofs::Circuit<Field> circuit{};
  circuit.nv = 2; circuit.logv = 1; circuit.nc = 1; circuit.logc = 0;
  circuit.nl = 1; circuit.npub_in = 1;
  circuit.subfield_boundary = 1; circuit.ninputs = 2;
  circuit.l.push_back({2, 1,
      proofs::QuadBuilder<Field>::compress(&terms, proofs::p256_base)});
  proofs::circuit_id(circuit.id, circuit, proofs::p256_base);
  return circuit;
}

}  // namespace

int main(int argc, char** argv) {
  auto circuit = make_circuit();
  proofs::CircuitWriter<Field> writer(proofs::p256_base, proofs::P256_ID);
  std::vector<uint8_t> lfc1, lfc2, repeated, restored_lfc1;
  writer.to_bytes(circuit, lfc1);
  writer.to_bytes(circuit, lfc2, proofs::CircuitFormat::kLfc2);
  if (argc == 3 && std::strcmp(argv[1], "--write") == 0) {
    std::ofstream output(argv[2], std::ios::binary);
    output.write(reinterpret_cast<const char*>(lfc2.data()), lfc2.size());
    return output.good() ? 0 : 1;
  }
  if (argc == 3 && std::strcmp(argv[1], "--read") == 0) {
    std::ifstream input(argv[2], std::ios::binary);
    std::vector<uint8_t> external((std::istreambuf_iterator<char>(input)), {});
    proofs::ByteCursor external_cursor(external.data(), external.size());
    proofs::CircuitReader<Field> external_reader(proofs::p256_base, proofs::P256_ID);
    return external_reader.from_bytes(external_cursor, true) ? 0 : 1;
  }
  writer.to_bytes(circuit, repeated, proofs::CircuitFormat::kLfc2);
  require(lfc2 == repeated, "LFC2 writer is not deterministic");
  require(lfc2.size() < lfc1.size(), "LFC2 did not compact this fixture");
  require(lfc2.size() >= 4 && std::memcmp(lfc2.data(), "LFC2", 4) == 0,
          "LFC2 magic/version missing");

  proofs::ByteCursor bytes(lfc2.data(), lfc2.size());
  proofs::CircuitReader<Field> reader(proofs::p256_base, proofs::P256_ID);
  auto decoded = reader.from_bytes(bytes, true);
  require(decoded != nullptr, "LFC2 round trip failed");
  uint8_t expected[proofs::CircuitIO::kIdSize];
  proofs::circuit_id(expected, *decoded, proofs::p256_base);
  require(std::memcmp(expected, circuit.id, proofs::CircuitIO::kIdSize) == 0,
          "LFC2 changed canonical circuit ID");
  writer.to_bytes(*decoded, restored_lfc1);
  require(restored_lfc1 == lfc1, "LFC2 changed logical LFC1 serialization");

  std::vector<uint8_t> malformed = lfc2;
  malformed.insert(malformed.begin() + 4, 0x80);  // non-minimal field ID
  proofs::ByteCursor bad(malformed.data(), malformed.size());
  require(reader.from_bytes(bad, true) == nullptr,
          "noncanonical LFC2 varint was accepted");
  return 0;
}
