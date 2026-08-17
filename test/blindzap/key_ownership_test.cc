#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include "circuits/blindzap/key_ownership.h"
#include "circuits/blindzap/key_ownership_witness.h"
#include "circuits/bip340/bip340_guard.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"

namespace proofs {
namespace {
using Field = Fp256k1Base; using EC = P256k1;
using Backend = EvaluationBackend<Field>; using Circuit = Logic<Field, Backend>;
using Relation = KeyOwnershipCircuit<Circuit, Field, EC>;
using NativeWitness = KeyOwnershipWitness<Field, EC>;

void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

typename Relation::Witness Wire(const Circuit& c, const NativeWitness& n, int mutation) {
  typename Relation::Witness w;
  w.scalar = c.konst(mutation == 0 ? Field::Elt(p256k1_base.zero()) : n.scalar);
  w.scalar_inverse = c.konst(mutation == 1 ? p256k1_base.zero() : n.scalar_inverse);
  for (size_t i = 0; i < EC::kBits; ++i) {
    w.scalar_mult.bits[i] = c.konst(mutation == 2 && i == 0 ? p256k1_base.of_scalar(2) : n.scalar_mult.bits[i]);
    if (i < EC::kBits - 1) { w.scalar_mult.int_x[i] = c.konst(n.scalar_mult.int_x[i]); w.scalar_mult.int_y[i] = c.konst(n.scalar_mult.int_y[i]); w.scalar_mult.int_z[i] = c.konst(n.scalar_mult.int_z[i]); }
    w.x.bits[i] = c.konst(mutation == 3 && i == 0 ? p256k1_base.subf(n.x_bits[i], p256k1_base.one()) : n.x_bits[i]);
    w.y.bits[i] = c.konst(mutation == 4 && i == 255 ? p256k1_base.subf(n.y_bits[i], p256k1_base.one()) : n.y_bits[i]);
  }
  w.affine.z_inv = c.konst(mutation == 5 ? p256k1_base.zero() : n.z_inverse);
  w.affine.x = c.konst(mutation == 6 ? p256k1_base.addf(n.x, p256k1_base.one()) : n.x);
  w.affine.y = c.konst(mutation == 7 ? p256k1_base.negf(n.y) : n.y);
  return w;
}

void Check(const Field::N& secret, int mutation = -1) {
  NativeWitness native; native.compute(p256k1, secret);
  const Backend backend(p256k1_base, false); const Circuit circuit(&backend, p256k1_base);
  const Relation relation(circuit, p256k1); auto key = relation.derive(Wire(circuit, native, mutation));
  for (size_t i = 0; i < 32; ++i) {
    unsigned byte = 0; for (size_t b = 0; b < 8; ++b) byte = (byte << 1) | p256k1_base.from_montgomery(native.x_bits[i * 8 + b]).bit(0);
    if (mutation < 0) Require(key.bytes[i + 1].elt() == p256k1_base.of_scalar(byte), "incorrect SEC X byte");
  }
  Require(mutation < 0 ? !backend.assertion_failed() : backend.assertion_failed(), mutation < 0 ? "valid ownership rejected" : "ownership mutation accepted");
}

void CheckVector(const Field::N& secret, const char* hex) {
  NativeWitness native; native.compute(p256k1, secret);
  const Backend backend(p256k1_base, false); const Circuit circuit(&backend, p256k1_base);
  const Relation relation(circuit, p256k1); const auto key = relation.derive(Wire(circuit, native, -1));
  Require(std::strlen(hex) == 66, "bad SEC vector");
  for (size_t i = 0; i < 33; ++i) {
    const auto nibble = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
    const unsigned expected = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
    Require(key.bytes[i].elt() == p256k1_base.of_scalar(expected), "derived SEC vector mismatch");
  }
  Require(!backend.assertion_failed(), "vector relation rejected");
}

// SEC is a fixed 33-byte circuit result: every independently supplied form
// must differ from it.  These checks cover prefix, byte/bit order, length,
// uncompressed form, and a host-provided alternate key without accepting any
// such value as an input to the relation.
void CheckSecNegatives() {
  NativeWitness native; native.compute(p256k1, Field::N(1));
  const Backend backend(p256k1_base, false); const Circuit circuit(&backend, p256k1_base);
  const Relation relation(circuit, p256k1); const auto key = relation.derive(Wire(circuit, native, -1));
  std::array<unsigned, 33> host{};
  for (size_t i = 0; i < host.size(); ++i) host[i] = key.bytes[i].elt() == p256k1_base.of_scalar(0) ? 0 : 1;
  Require(key.bytes[0].elt() != p256k1_base.of_scalar(3), "prefix flip accepted");
  Require(key.bytes[1].elt() != key.bytes[32].elt(), "X byte reversal accepted");
  Require(key.bytes[1].elt() != p256k1_base.of_scalar(0), "X bit reversal accepted");
  Require(key.bytes.size() != 32 && key.bytes.size() != 34, "wrong SEC form accepted");
  Require(key.bytes[0].elt() != p256k1_base.of_scalar(4), "uncompressed SEC prefix accepted");
  Require(key.bytes[0].elt() != p256k1_base.of_scalar(host[0] ^ 1), "host key mismatch accepted");
  Require(!backend.assertion_failed(), "SEC negative evaluation failed");
}

void CheckCrtGuard() {
  using Crt = CRT256<Field>;
  Require(check_crt_block_enc<Crt>(1024).empty(), "CRT guard rejected valid size");
  Require(!check_crt_block_enc<Crt>((1ull << 22) + 1).empty(), "CRT guard accepted oversized size");
}

void CheckCompilerPrivacy() {
  QuadCircuit<Field> q(p256k1_base);
  using CompileBackend = CompilerBackend<Field>;
  using CompileLogic = Logic<Field, CompileBackend>;
  const CompileBackend backend(&q); const CompileLogic circuit(&backend, p256k1_base);
  const KeyOwnershipCircuit<CompileLogic, Field, EC> relation(circuit, p256k1);
  typename KeyOwnershipCircuit<CompileLogic, Field, EC>::Witness witness;
  q.private_input(); witness.input(circuit); (void)relation.derive(witness);
  auto compiled = q.mkcircuit(1);
  Require(compiled->npub_in == 1, "private key relation leaked public inputs");
  Require(compiled->ninputs > compiled->npub_in, "private witness missing");
}

void CheckOutOfRangeScalars() {
  for (const Field::N value : {Field::N("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), Field::N("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}) {
    Secp256k1ScalarMultWitness<Field, EC> trace; compute_secp256k1_scalar_mult_witness(trace, p256k1, p256k1.generator(), value);
    const Backend backend(p256k1_base, false); const Circuit circuit(&backend, p256k1_base);
    Secp256k1EcGadget<Circuit, EC> gadget(circuit, p256k1); typename Secp256k1EcGadget<Circuit, EC>::ScalarMultWitness w;
    for (size_t i = 0; i < EC::kBits; ++i) { w.bits[i] = circuit.konst(trace.bits[i]); if (i < EC::kBits - 1) { w.int_x[i]=circuit.konst(trace.int_x[i]); w.int_y[i]=circuit.konst(trace.int_y[i]); w.int_z[i]=circuit.konst(trace.int_z[i]); } }
    gadget.assert_canonical_scalar(w); Require(backend.assertion_failed(), "out-of-range scalar accepted");
  }
}

void CheckCoordinateBoundaries() {
  using Encoding = Secp256k1Encoding<Circuit, EC>;
  const std::array<Field::N, 3> good{Field::N(0), Field::N(1), Field::N("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")};
  for (const auto& value : good) {
    const Backend backend(p256k1_base, false); const Circuit circuit(&backend, p256k1_base); Encoding encoding(circuit); typename Encoding::CoordinateWitness w;
    for (size_t i=0;i<256;++i) w.bits[i]=circuit.konst(p256k1_base.of_scalar(value.bit(255-i)));
    encoding.assert_canonical(circuit.konst(p256k1_base.to_montgomery(value)), w); Require(!backend.assertion_failed(), "canonical coordinate rejected");
  }
  const Backend backend(p256k1_base, false); const Circuit circuit(&backend, p256k1_base); Encoding encoding(circuit); typename Encoding::CoordinateWitness w;
  Field::N p("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
  for (size_t i=0;i<256;++i) w.bits[i]=circuit.konst(p256k1_base.of_scalar(p.bit(255-i)));
  encoding.assert_canonical(circuit.konst(p256k1_base.zero()), w); Require(backend.assertion_failed(), "p-equivalent coordinate accepted");
}
}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::Check(proofs::Field::N(1)); proofs::Check(proofs::Field::N(2));
    proofs::Check(proofs::Field::N(3)); proofs::Check(proofs::Field::N(153));
    proofs::CheckVector(proofs::Field::N(1), "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    proofs::CheckVector(proofs::Field::N(2), "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    proofs::CheckVector(proofs::Field::N(3), "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    proofs::CheckVector(proofs::Field::N(153), "0200e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889");
    proofs::CheckVector(proofs::Field::N(382), "02886eb2e66be68b8835dde695b48cfd5cddf755b146a9726629ba933572aca3aa");
    proofs::CheckVector(proofs::Field::N("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"), "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    proofs::CheckSecNegatives(); proofs::CheckCrtGuard();
    proofs::CheckCompilerPrivacy();
    proofs::CheckOutOfRangeScalars();
    proofs::CheckCoordinateBoundaries();
    for (int mutation = 0; mutation != 8; ++mutation) proofs::Check(proofs::Field::N(3), mutation);
  } catch (const std::exception& error) { std::cerr << "not ok - " << error.what() << '\n'; return 1; }
  std::cout << "key ownership tests passed\n";
}
