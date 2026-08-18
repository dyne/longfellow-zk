#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "circuits/blindzap/compressed_key_sha256.h"
#include "circuits/blindzap/compressed_key_sha256_witness.h"
#include "circuits/blindzap/key_ownership.h"
#include "circuits/blindzap/key_ownership_witness.h"
#include "circuits/bip340/bip340_guard.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256k1.h"

namespace proofs {
namespace {
using Field = Fp256k1Base;
using EC = P256k1;
using Backend = EvaluationBackend<Field>;
using Circuit = Logic<Field, Backend>;
using Ownership = KeyOwnershipCircuit<Circuit, Field, EC>;
using OwnershipNative = KeyOwnershipWitness<Field, EC>;
using Sha = CompressedKeySha256Circuit<Circuit>;
using Flat = FlatSHA256Circuit<Circuit, BitPlucker<Circuit, 4>>;

void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}

unsigned Nibble(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }

void RequireDigest(const uint32_t words[8], const char* hex) {
  for (size_t byte = 0; byte < 32; ++byte) {
    const unsigned actual = (words[byte / 4] >> (24 - 8 * (byte % 4))) & 0xffu;
    Require(actual == ((Nibble(hex[2 * byte]) << 4) | Nibble(hex[2 * byte + 1])),
            "external SHA-256 vector mismatch");
  }
}

std::array<uint8_t, 33> Sec(const OwnershipNative& native) {
  std::array<uint8_t, 33> sec{};
  sec[0] = 2 + p256k1_base.from_montgomery(native.y_bits[255]).bit(0);
  for (size_t byte = 0; byte < 32; ++byte) {
    for (size_t bit = 0; bit < 8; ++bit) {
      sec[byte + 1] = (sec[byte + 1] << 1) |
                      p256k1_base.from_montgomery(native.x_bits[byte * 8 + bit]).bit(0);
    }
  }
  return sec;
}

Ownership::Witness WireOwnership(const Circuit& c, const OwnershipNative& n,
                                 int mutation) {
  Ownership::Witness w;
  w.scalar = c.konst(n.scalar);
  w.scalar_inverse = c.konst(n.scalar_inverse);
  for (size_t i = 0; i < EC::kBits; ++i) {
    w.scalar_mult.bits[i] = c.konst(n.scalar_mult.bits[i]);
    if (i < EC::kBits - 1) {
      w.scalar_mult.int_x[i] = c.konst(n.scalar_mult.int_x[i]);
      w.scalar_mult.int_y[i] = c.konst(n.scalar_mult.int_y[i]);
      w.scalar_mult.int_z[i] = c.konst(n.scalar_mult.int_z[i]);
    }
    w.x.bits[i] = c.konst(mutation == 1 && i == 0
                              ? p256k1_base.subf(n.x_bits[i], p256k1_base.one())
                              : n.x_bits[i]);
    w.y.bits[i] = c.konst(n.y_bits[i]);
  }
  w.affine.z_inv = c.konst(n.z_inverse);
  w.affine.x = c.konst(n.x);
  w.affine.y = c.konst(n.y);
  return w;
}

Sha::Witness WireSha(const Circuit& c, const CompressedKeySha256Witness& native,
                     int mutation) {
  Sha::Witness witness;
  BitPluckerEncoder<Field, 4> encoder(p256k1_base);
  for (size_t i = 0; i < 48; ++i) {
    uint32_t value = native.block.outw[i] ^ (mutation == 2 && i == 0 ? 1u : 0u);
    witness.block.outw[i] = c.konst(encoder.mkpacked_v32(value));
  }
  for (size_t i = 0; i < 64; ++i) {
    witness.block.oute[i] = c.konst(encoder.mkpacked_v32(native.block.oute[i]));
    witness.block.outa[i] = c.konst(encoder.mkpacked_v32(native.block.outa[i]));
  }
  for (size_t i = 0; i < 8; ++i) {
    uint32_t value = native.block.h1[i] ^ (mutation == 3 && i == 0 ? 1u : 0u);
    witness.block.h1[i] = c.konst(encoder.mkpacked_v32(value));
  }
  return witness;
}

void CheckBlindZap(const Field::N& secret, const char* expected_hex, int mutation = 0) {
  OwnershipNative ownership_native;
  ownership_native.compute(p256k1, secret);
  CompressedKeySha256Witness sha_native;
  sha_native.compute(Sec(ownership_native));
  RequireDigest(sha_native.block.h1, expected_hex);
  const Backend backend(p256k1_base, false);
  const Circuit circuit(&backend, p256k1_base);
  const Ownership ownership(circuit, p256k1);
  const Sha sha(circuit);
  const auto key = ownership.derive(WireOwnership(circuit, ownership_native, mutation));
  const auto digest = sha.derive(key, WireSha(circuit, sha_native, mutation));
  for (size_t byte = 0; byte < 32; ++byte) {
    for (size_t bit = 0; bit < 8; ++bit) {
      const unsigned actual = digest[(31 - byte) * 8 + bit].x.elt() == p256k1_base.of_scalar(1);
      const unsigned expected = (sha_native.digest[byte] >> bit) & 1u;
      Require(mutation != 0 || actual == expected, "incorrect SHA-256 digest bit");
    }
  }
  Require(mutation == 0 ? !backend.assertion_failed() : backend.assertion_failed(),
          mutation == 0 ? "valid SHA relation rejected" : "SHA mutation accepted");
}

Flat::BlockWitness WireFlat(const Circuit& c,
                            const FlatSHA256Witness::BlockWitness* native) {
  Flat::BlockWitness result;
  BitPluckerEncoder<Field, 4> encoder(p256k1_base);
  for (size_t i = 0; i < 48; ++i) result.outw[i] = c.konst(encoder.mkpacked_v32(native->outw[i]));
  for (size_t i = 0; i < 64; ++i) {
    result.oute[i] = c.konst(encoder.mkpacked_v32(native->oute[i]));
    result.outa[i] = c.konst(encoder.mkpacked_v32(native->outa[i]));
  }
  for (size_t i = 0; i < 8; ++i) result.h1[i] = c.konst(encoder.mkpacked_v32(native->h1[i]));
  return result;
}

void CheckGeneric(size_t length, const char* expected_hex, int mutation) {
  std::vector<uint8_t> message(length);
  for (size_t i = 0; i < message.size(); ++i) message[i] = 0x31 + i;
  uint8_t nb = 0;
  uint8_t padded[128] = {};
  FlatSHA256Witness::BlockWitness native[2];
  FlatSHA256Witness::transform_and_witness_message(message.size(), message.data(), 2,
                                                   nb, padded, native);
  RequireDigest(native[nb - 1].h1, expected_hex);
  const Backend backend(p256k1_base, false);
  const Circuit circuit(&backend, p256k1_base);
  std::array<Circuit::v8, 128> input;
  for (size_t i = 0; i < input.size(); ++i) {
    uint8_t value = padded[i];
    if ((mutation == 1 && i == 0) || (mutation == 2 && i == length) ||
        (mutation == 3 && i == 34) || (mutation == 4 && i == 127)) value ^= 1;
    input[i] = circuit.template vbit<8>(value);
  }
  Circuit::v256 expected;
  const auto& h = native[nb - 1].h1;
  for (size_t byte = 0; byte < 32; ++byte) {
    for (size_t bit = 0; bit < 8; ++bit) {
      expected[(31 - byte) * 8 + bit] = circuit.bit(((h[byte / 4] >>
          (24 - 8 * (byte % 4) + bit)) & 1u) ^ (mutation == 5 && byte == 0 && bit == 0));
    }
  }
  Flat::BlockWitness witnesses[2] = {WireFlat(circuit, &native[0]), WireFlat(circuit, &native[1])};
  Flat flat(circuit);
  flat.assert_message_hash(2, circuit.template vbit<8>(nb + (mutation == 6)), input.data(), expected, witnesses);
  Require(mutation == 0 ? !backend.assertion_failed() : backend.assertion_failed(),
          mutation == 0 ? "valid generic SHA rejected" : "generic SHA mutation accepted");
}

void CheckCompilerPrivacy() {
  QuadCircuit<Field> q(p256k1_base);
  using CompileBackend = CompilerBackend<Field>;
  using CompileLogic = Logic<Field, CompileBackend>;
  const CompileBackend backend(&q);
  const CompileLogic circuit(&backend, p256k1_base);
  KeyOwnershipCircuit<CompileLogic, Field, EC> ownership(circuit, p256k1);
  CompressedKeySha256Circuit<CompileLogic> sha(circuit);
  typename KeyOwnershipCircuit<CompileLogic, Field, EC>::Witness ownership_witness;
  typename CompressedKeySha256Circuit<CompileLogic>::Witness sha_witness;
  q.private_input(); ownership_witness.input(circuit); sha_witness.input(circuit);
  (void)sha.derive(ownership.derive(ownership_witness), sha_witness);
  const auto compiled = q.mkcircuit(1);
  Require(compiled->npub_in == 1, "SHA stage leaked a public input");
  Require(compiled->ninputs > compiled->npub_in, "SHA witness missing");
}

struct Metrics {
  size_t milliseconds;
  size_t public_inputs;
  size_t total_inputs;
  size_t quadratic_terms;
  size_t depth;
  size_t block_enc;
};

Metrics CompileMetrics(bool include_sha) {
  const auto start = std::chrono::steady_clock::now();
  QuadCircuit<Field> q(p256k1_base);
  using CompileBackend = CompilerBackend<Field>;
  using CompileLogic = Logic<Field, CompileBackend>;
  const CompileBackend backend(&q);
  const CompileLogic circuit(&backend, p256k1_base);
  KeyOwnershipCircuit<CompileLogic, Field, EC> ownership(circuit, p256k1);
  typename KeyOwnershipCircuit<CompileLogic, Field, EC>::Witness ownership_witness;
  q.private_input(); ownership_witness.input(circuit);
  const auto key = ownership.derive(ownership_witness);
  if (include_sha) {
    CompressedKeySha256Circuit<CompileLogic> sha(circuit);
    typename CompressedKeySha256Circuit<CompileLogic>::Witness sha_witness;
    sha_witness.input(circuit);
    (void)sha.derive(key, sha_witness);
  }
  const auto compiled = q.mkcircuit(1);
  const auto finish = std::chrono::steady_clock::now();
  const size_t block_enc = compiled->ninputs - compiled->npub_in + q.nquad_terms_ + 1;
  Require(check_crt_block_enc<CRT256<Field>>(block_enc).empty(), "SHA CRT guard rejected circuit");
  return {static_cast<size_t>(std::chrono::duration_cast<std::chrono::milliseconds>(finish - start).count()),
          compiled->npub_in, compiled->ninputs, q.nquad_terms_, q.depth_, block_enc};
}

void CheckCompositionMetrics() {
  for (const auto& row : std::array<std::pair<const char*, Metrics>, 2>{{
           {"ownership", CompileMetrics(false)},
           {"ownership_plus_sha256", CompileMetrics(true)},
       }}) {
    std::cout << "metrics " << row.first << " build_ms=" << row.second.milliseconds
              << " public_inputs=" << row.second.public_inputs
              << " total_inputs=" << row.second.total_inputs
              << " quad_terms=" << row.second.quadratic_terms
              << " depth=" << row.second.depth
              << " crt_block_enc=" << row.second.block_enc << '\n';
  }
}
}  // namespace
}  // namespace proofs

int main() {
  try {
    const std::array<std::pair<size_t, const char*>, 5> lengths{{
        {0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {32, "fbc974481bd2003e2d7b74f87e5e7ac36b2ef340492ec827703b415c662b5840"},
        {33, "106701674444f1f73a572f43888034b83ee8c41dc898aca6fe0c409867cc6fa8"},
        {55, "566591d4ce1650deae9a29014979093ff5517ef41be759a7a4b5ecd30b513d63"},
        {56, "94dae2297ccda9d313faa37f66a23e67fed295d146244bfad880eeb5ad6a3c08"},
    }};
    for (const auto& vector : lengths) {
      proofs::CheckGeneric(vector.first, vector.second, 0);
      for (int mutation = 1; mutation <= 6; ++mutation) proofs::CheckGeneric(vector.first, vector.second, mutation);
    }
    proofs::CheckBlindZap(proofs::Field::N(1), "0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554");
    proofs::CheckBlindZap(proofs::Field::N(2), "b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7");
    proofs::CheckBlindZap(proofs::Field::N(3), "eae10cdd2f289bdad44615809cb422d2fabe9622ed706ad5d9d3ffd2cdd1c001");
    proofs::CheckBlindZap(proofs::Field::N(153), "b8c4af6879fcb72e31f09986af6f4571967c3ed871f672d83a96d346c76f2cd7");
    proofs::CheckBlindZap(proofs::Field::N(382), "00ab0439dfc6cde6e6a983b33230e07123e996aed6efae1e196327b4a171e338");
    proofs::CheckBlindZap(proofs::Field::N("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"), "fbd27dbb9e7f471bf3de3704a35e884e37d35c676dc2cc8c3cc574c3962376d2");
    for (int mutation = 1; mutation <= 3; ++mutation) proofs::CheckBlindZap(proofs::Field::N(3), "eae10cdd2f289bdad44615809cb422d2fabe9622ed706ad5d9d3ffd2cdd1c001", mutation);
    proofs::CheckCompilerPrivacy();
    proofs::CheckCompositionMetrics();
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "compressed key SHA-256 tests passed\n";
}
