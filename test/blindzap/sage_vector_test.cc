// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "blindzap/envelope.h"
#include "circuits/blindzap/blindzap_witness.h"
#include "circuits/blindzap/compressed_key_sha256.h"
#include "circuits/blindzap/compressed_key_sha256_witness.h"
#include "circuits/blindzap/hash160.h"
#include "circuits/blindzap/key_ownership.h"
#include "circuits/blindzap/key_ownership_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/ripemd160/ripemd160.h"
#include "cli/json.hpp"
#include "ec/p256k1.h"

namespace proofs {
namespace {

using Field = Fp256k1Base;
using EC = P256k1;
using Backend = EvaluationBackend<Field>;
using LogicCircuit = Logic<Field, Backend>;
using Ownership = KeyOwnershipCircuit<LogicCircuit, Field, EC>;
using OwnershipNative = KeyOwnershipWitness<Field, EC>;
using Sha = CompressedKeySha256Circuit<LogicCircuit>;
using Hash160 = Hash160Circuit<LogicCircuit>;

void Require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

unsigned HexNibble(char character) {
  if (character >= '0' && character <= '9') {
    return static_cast<unsigned>(character - '0');
  }
  if (character >= 'a' && character <= 'f') {
    return static_cast<unsigned>(character - 'a' + 10);
  }
  if (character >= 'A' && character <= 'F') {
    return static_cast<unsigned>(character - 'A' + 10);
  }
  throw std::invalid_argument("invalid hexadecimal character");
}

std::vector<uint8_t> ParseHex(const std::string& encoded) {
  if (encoded.size() % 2 != 0) throw std::invalid_argument("odd hexadecimal length");
  std::vector<uint8_t> bytes(encoded.size() / 2);
  for (size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = static_cast<uint8_t>((HexNibble(encoded[index * 2]) << 4) |
                                        HexNibble(encoded[index * 2 + 1]));
  }
  return bytes;
}

template <size_t Size>
std::array<uint8_t, Size> ParseHexArray(const std::string& encoded) {
  const auto bytes = ParseHex(encoded);
  if (bytes.size() != Size) throw std::invalid_argument("incorrect hexadecimal width");
  std::array<uint8_t, Size> result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

std::string Hex(const uint8_t* bytes, size_t size) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string encoded;
  encoded.reserve(size * 2);
  for (size_t index = 0; index < size; ++index) {
    encoded.push_back(kDigits[bytes[index] >> 4]);
    encoded.push_back(kDigits[bytes[index] & 15]);
  }
  return encoded;
}

std::string HexNat(const Field::N& value) {
  std::array<uint8_t, Field::kBytes> little_endian{};
  value.to_bytes(little_endian.data());
  std::reverse(little_endian.begin(), little_endian.end());
  return Hex(little_endian.data(), little_endian.size());
}

std::array<uint8_t, 32> SecretBytes(const Field::N& value) {
  std::array<uint8_t, 32> little_endian{};
  value.to_bytes(little_endian.data());
  std::array<uint8_t, 32> big_endian{};
  std::reverse_copy(little_endian.begin(), little_endian.end(), big_endian.begin());
  return big_endian;
}

std::array<uint8_t, 33> CompressedSec(const OwnershipNative& native) {
  std::array<uint8_t, 33> sec{};
  sec[0] = static_cast<uint8_t>(
      2 + p256k1_base.from_montgomery(native.y_bits[255]).bit(0));
  for (size_t byte = 0; byte < 32; ++byte) {
    for (size_t bit = 0; bit < 8; ++bit) {
      sec[byte + 1] = static_cast<uint8_t>(
          (static_cast<unsigned>(sec[byte + 1]) << 1U) |
          static_cast<unsigned>(p256k1_base
                                    .from_montgomery(
                                        native.x_bits[byte * 8 + bit])
                                    .bit(0)));
    }
  }
  return sec;
}

Ownership::Witness WireOwnership(const LogicCircuit& circuit,
                                 const OwnershipNative& native) {
  Ownership::Witness witness;
  witness.scalar = circuit.konst(native.scalar);
  witness.scalar_inverse = circuit.konst(native.scalar_inverse);
  for (size_t index = 0; index < EC::kBits; ++index) {
    witness.scalar_mult.bits[index] = circuit.konst(native.scalar_mult.bits[index]);
    if (index + 1 < EC::kBits) {
      witness.scalar_mult.int_x[index] = circuit.konst(native.scalar_mult.int_x[index]);
      witness.scalar_mult.int_y[index] = circuit.konst(native.scalar_mult.int_y[index]);
      witness.scalar_mult.int_z[index] = circuit.konst(native.scalar_mult.int_z[index]);
    }
    witness.x.bits[index] = circuit.konst(native.x_bits[index]);
    witness.y.bits[index] = circuit.konst(native.y_bits[index]);
  }
  witness.affine.z_inv = circuit.konst(native.z_inverse);
  witness.affine.x = circuit.konst(native.x);
  witness.affine.y = circuit.konst(native.y);
  return witness;
}

Sha::Witness WireSha(const LogicCircuit& circuit,
                     const CompressedKeySha256Witness& native) {
  Sha::Witness witness;
  BitPluckerEncoder<Field, 4> encoder(p256k1_base);
  for (size_t index = 0; index < 48; ++index) {
    witness.block.outw[index] =
        circuit.konst(encoder.mkpacked_v32(native.block.outw[index]));
  }
  for (size_t index = 0; index < 64; ++index) {
    witness.block.oute[index] =
        circuit.konst(encoder.mkpacked_v32(native.block.oute[index]));
    witness.block.outa[index] =
        circuit.konst(encoder.mkpacked_v32(native.block.outa[index]));
  }
  for (size_t index = 0; index < 8; ++index) {
    witness.block.h1[index] =
        circuit.konst(encoder.mkpacked_v32(native.block.h1[index]));
  }
  return witness;
}

BlindzapStatementV1 ReferenceStatement() {
  BlindzapStatementV1 statement;
  statement.network = BlindzapNetwork::kSignet;
  statement.verifier = "merchant.example";
  statement.purpose = "proof-of-funds";
  statement.not_before = 100;
  statement.expires_at = 200;
  for (size_t index = 0; index < 32; ++index) {
    statement.nonce[index] = static_cast<uint8_t>(index + 1);
    statement.bip322_message_hash[index] = static_cast<uint8_t>(32 - index);
  }
  BlindzapClaimV1 first;
  first.txid[0] = 1;
  first.vout = 2;
  first.amount_sats = 42;
  first.program[0] = 9;
  BlindzapClaimV1 second;
  second.txid[0] = 2;
  second.vout = 1;
  second.amount_sats = 99;
  second.program[1] = 8;
  statement.claims = {first, second};
  return statement;
}

nlohmann::json LoadFixture(const char* path) {
  constexpr std::streamsize kMaxFixtureBytes = 1'048'576;
  std::ifstream stream(path, std::ios::binary | std::ios::ate);
  Require(stream.good(), std::string("cannot open Sage fixture: ") + path);
  const std::streamsize size = stream.tellg();
  Require(size > 0 && size <= kMaxFixtureBytes,
          "Sage fixture size is invalid");
  stream.seekg(0);
  nlohmann::json fixture;
  stream >> fixture;
  stream >> std::ws;
  Require(stream.eof(), "Sage fixture contains trailing data");
  return fixture;
}

void CheckValidVector(const nlohmann::json& vector, size_t vector_index) {
  const std::string context = "Sage vector " + std::to_string(vector_index);
  const std::string scalar_text = vector.at("secret_scalar").get<std::string>();
  const std::optional<Field::N> parsed_scalar =
      Field::N::of_untrusted_string(scalar_text.c_str());
  if (!parsed_scalar.has_value()) {
    throw std::runtime_error(context + " scalar does not parse");
  }
  const Field::N scalar = parsed_scalar.value();
  const auto secret = SecretBytes(scalar);
  BlindzapWitnessV1<Field, EC> complete_native;
  Require(complete_native.compute(p256k1, secret.data(), secret.size()),
          context + " scalar failed native input validation");

  OwnershipNative ownership_native;
  ownership_native.compute(p256k1, scalar);
  Require(HexNat(p256k1_base.from_montgomery(ownership_native.x)) ==
              vector.at("x_coordinate").get<std::string>(),
          context + " x coordinate differs");
  Require(HexNat(p256k1_base.from_montgomery(ownership_native.y)) ==
              vector.at("y_coordinate").get<std::string>(),
          context + " y coordinate differs");
  Require(p256k1_base.from_montgomery(ownership_native.y_bits[255]).bit(0) ==
              vector.at("y_parity").get<unsigned>(),
          context + " y parity differs");

  const auto sec = CompressedSec(ownership_native);
  Require(Hex(sec.data(), sec.size()) ==
              vector.at("compressed_sec").get<std::string>(),
          context + " compressed SEC differs");
  CompressedKeySha256Witness sha_native;
  sha_native.compute(sec);
  Require(Hex(sha_native.digest.data(), sha_native.digest.size()) ==
              vector.at("sha256").get<std::string>(),
          context + " SHA-256 differs");
  const auto program = Ripemd160::digest(sha_native.digest);
  Require(Hex(program.data(), program.size()) ==
              vector.at("hash160").get<std::string>(),
          context + " HASH160 differs");
  std::array<uint8_t, 22> script{};
  script[1] = 20;
  std::copy(program.begin(), program.end(), script.begin() + 2);
  Require(Hex(script.data(), script.size()) ==
              vector.at("p2wpkh_script_pubkey").get<std::string>(),
          context + " P2WPKH script differs");

  Require(complete_native.program() == program,
          context + " complete native witness differs");

  const Backend backend(p256k1_base, false);
  const LogicCircuit circuit(&backend, p256k1_base);
  const Ownership ownership(circuit, p256k1);
  const Hash160 hash160(circuit);
  std::array<LogicCircuit::v8, 20> target;
  for (size_t index = 0; index < target.size(); ++index) {
    target[index] = circuit.template vbit<8>(program[index]);
  }
  typename Hash160::Witness witness;
  witness.sha = WireSha(circuit, sha_native);
  (void)hash160.assert_hash160(
      ownership.derive(WireOwnership(circuit, ownership_native)), witness,
      target);
  Require(!backend.assertion_failed(), context + " failed full circuit evaluation");
}

void CheckInvalidScalars(const nlohmann::json& invalid_scalars) {
  Require(invalid_scalars.size() == 4, "unexpected Sage invalid-scalar count");
  for (size_t index = 0; index < invalid_scalars.size(); ++index) {
    const std::string scalar_text =
        invalid_scalars.at(index).at("secret_scalar").get<std::string>();
    const std::optional<Field::N> scalar =
        Field::N::of_untrusted_string(scalar_text.c_str());
    if (!scalar.has_value()) {
      Require(!scalar_text.empty() && scalar_text[0] == '-',
              "unexpected unparsable Sage scalar");
      continue;
    }
    const auto secret = SecretBytes(*scalar);
    BlindzapWitnessV1<Field, EC> witness;
    Require(!witness.compute(p256k1, secret.data(), secret.size()),
            "Sage invalid scalar accepted by C++: " + scalar_text);
  }
}

void CheckStatementAndTranscript(const nlohmann::json& fixture) {
  const auto& reference = fixture.at("statement_v1");
  const BlindzapStatementV1 statement = ReferenceStatement();
  std::vector<uint8_t> encoded;
  Require(EncodeBlindzapStatement(statement, &encoded),
          "could not encode Sage reference statement");
  Require(Hex(encoded.data(), encoded.size()) ==
              reference.at("encoded_statement").get<std::string>(),
          "C++ statement encoding differs from Sage fixture");
  std::array<uint8_t, 32> digest{};
  Require(BlindzapStatementDigest(statement, &digest) &&
              Hex(digest.data(), digest.size()) ==
                  reference.at("statement_digest").get<std::string>(),
          "C++ statement digest differs from Sage fixture");

  const auto& transcript = reference.at("transcript_example");
  BlindzapProofV1 proof;
  proof.circuit_digest = ParseHexArray<32>(
      transcript.at("circuit_digest").get<std::string>());
  proof.circuit_version = transcript.at("circuit_version").get<uint32_t>();
  proof.rate = transcript.at("rate").get<size_t>();
  proof.queries = transcript.at("queries").get<size_t>();
  const auto seed = BlindzapTranscriptSeed(statement, proof);
  Require(Hex(seed.data(), seed.size()) ==
              transcript.at("seed").get<std::string>(),
          "C++ transcript seed differs from Sage fixture");
}

void CheckFixture(const nlohmann::json& fixture) {
  Require(fixture.at("format") == "blindzap-v1-sage-reference-vectors",
          "unexpected Sage fixture format");
  const auto& vectors = fixture.at("vectors");
  Require(vectors.is_array() && vectors.size() == 6,
          "unexpected Sage valid-vector count");
  for (size_t index = 0; index < vectors.size(); ++index) {
    CheckValidVector(vectors.at(index), index);
  }
  CheckInvalidScalars(fixture.at("invalid_scalars"));
  Require(fixture.at("invalid_compressed_sec").size() == 3,
          "unexpected Sage invalid-SEC count");
  CheckStatementAndTranscript(fixture);
}

}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  try {
    if (argc != 2) {
      throw std::invalid_argument("usage: sage_vector_test FIXTURE.json");
    }
    proofs::CheckFixture(proofs::LoadFixture(argv[1]));
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "BlindZap Sage/C++ differential vectors passed\n";
  return 0;
}
