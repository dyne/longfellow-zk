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

size_t read_varint(const std::vector<uint8_t>& bytes, size_t* position) {
  size_t value = 0;
  unsigned shift = 0;
  while (*position < bytes.size() && shift < sizeof(size_t) * 8) {
    const uint8_t byte = bytes[(*position)++];
    value |= static_cast<size_t>(byte & 0x7f) << shift;
    if ((byte & 0x80) == 0) return value;
    shift += 7;
  }
  require(false, "test fixture contains an invalid varint");
  return 0;
}

size_t first_delta_offset(const std::vector<uint8_t>& bytes,
                          size_t* constant_count,
                          size_t* delta_count_offset) {
  require(bytes.size() >= 4 && std::memcmp(bytes.data(), "LFC2", 4) == 0,
          "test fixture is not LFC2");
  size_t position = 4;
  for (size_t field = 0; field < 7; ++field)
    (void)read_varint(bytes, &position);
  *constant_count = read_varint(bytes, &position);
  position += *constant_count * Field::kBytes;
  (void)read_varint(bytes, &position);  // layer logw
  (void)read_varint(bytes, &position);  // layer wire count
  *delta_count_offset = position;
  (void)read_varint(bytes, &position);  // delta count
  require(position < bytes.size(), "test fixture has no delta table");
  return position;
}

void replace_varint(std::vector<uint8_t>* bytes, size_t position,
                    uint64_t replacement) {
  size_t end = position;
  do {
    require(end < bytes->size(), "varint replacement is out of bounds");
  } while ((*bytes)[end++] & 0x80);
  std::vector<uint8_t> encoded;
  do {
    uint8_t byte = static_cast<uint8_t>(replacement & 0x7f);
    replacement >>= 7;
    if (replacement != 0) byte |= 0x80;
    encoded.push_back(byte);
  } while (replacement != 0);
  bytes->erase(bytes->begin() + position, bytes->begin() + end);
  bytes->insert(bytes->begin() + position, encoded.begin(), encoded.end());
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

  size_t constant_count = 0;
  size_t delta_count_offset = 0;
  const size_t delta_offset =
      first_delta_offset(lfc2, &constant_count, &delta_count_offset);
  require(lfc2[delta_offset] == 0, "fixture first delta is not zero");
  std::vector<uint8_t> oversized_delta = lfc2;
  replace_varint(&oversized_delta, delta_offset, uint64_t{1} << 33);
  proofs::ByteCursor oversized(oversized_delta.data(), oversized_delta.size());
  require(reader.from_bytes(oversized, true) == nullptr &&
              reader.last_error().code ==
                  proofs::CircuitReadErrorCode::kInvalidDelta,
          "out-of-domain LFC2 zig-zag delta was narrowed and accepted");

  std::vector<uint8_t> oversized_table = lfc2;
  replace_varint(&oversized_table, delta_count_offset, 1000);
  proofs::ByteCursor allocation_limited(
      oversized_table.data(), oversized_table.size(),
      {.bytes = oversized_table.size(),
       .allocations = constant_count + 10,
       .elements = constant_count + 10});
  require(reader.from_bytes(allocation_limited, true) == nullptr &&
              reader.last_error().code ==
                  proofs::CircuitReadErrorCode::kResourceLimit,
          "LFC2 delta table bypassed the cursor allocation budget");
  return 0;
}
