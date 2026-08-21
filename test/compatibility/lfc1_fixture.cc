// Produces the small canonical LFC1 artifact used by compatibility checks.
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <vector>

#include "ec/p256.h"
#include "proto/circuit_writer.h"
#include "sumcheck/quad_builder.h"

namespace {

using Field = proofs::Fp256Base;

std::vector<uint8_t> BuildFixture() {
  proofs::EQuad<Field> terms(2);
  terms.ec_[0] = {0, {0, 1}, proofs::p256_base.one()};
  terms.ec_[1] = {1, {1, 1}, proofs::p256_base.zero()};
  terms.canonicalize(proofs::p256_base);

  proofs::Circuit<Field> circuit{};
  circuit.nv = 1;
  circuit.nc = 1;
  circuit.npub_in = 1;
  circuit.subfield_boundary = 1;
  circuit.ninputs = 2;
  circuit.l.push_back(
      {2, 1, proofs::QuadBuilder<Field>::compress(&terms, proofs::p256_base)});
  for (size_t index = 0; index < sizeof(circuit.id); ++index) {
    circuit.id[index] = static_cast<uint8_t>(index);
  }

  std::vector<uint8_t> bytes;
  proofs::CircuitWriter<Field>(proofs::p256_base, proofs::P256_ID)
      .to_bytes(circuit, bytes);
  return bytes;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) throw std::runtime_error("usage: lfc1_fixture OUTPUT");
  const auto bytes = BuildFixture();
  std::ofstream output(argv[1], std::ios::binary);
  if (!output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size())) {
    throw std::runtime_error("cannot write LFC1 fixture");
  }
}
