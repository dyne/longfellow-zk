#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include "circuits/compiler/compiler.h"
#include "ec/p256.h"
#include "proto/circuit_writer.h"

namespace {
using Field = proofs::Fp256Base;
void require(bool value, const char* message) { if (!value) { std::cerr << message << '\n'; std::exit(1); } }

std::unique_ptr<proofs::Circuit<Field>> build(bool symbols) {
  proofs::QuadCircuit<Field> q(proofs::p256_base);
  const size_t value = q.input_wire();
  if (symbols) { auto scope = q.assertion_scope("ecdsa/scalar/nonzero"); q.assert0(value); }
  else q.assert0(value);
  if (symbols) { auto scope = q.assertion_scope("ecdsa/scalar/alias"); q.assert0(value); }
  return q.mkcircuit(1);
}
}  // namespace

int main() {
  proofs::AssertionSymbolTracker tracker;
  { auto outer = tracker.scope("ecdsa"); auto inner = tracker.scope("scalar"); require(*tracker.path(tracker.current()) == "ecdsa/scalar", "nested source scope was not hierarchical"); }
  auto tagged = build(true);
  auto stripped = build(false);
  proofs::CircuitWriter<Field> writer(proofs::p256_base, proofs::P256_ID);
  std::vector<uint8_t> tagged_bytes, stripped_bytes;
  writer.to_bytes(*tagged, tagged_bytes); writer.to_bytes(*stripped, stripped_bytes);
  require(tagged_bytes == stripped_bytes, "debug symbols changed circuit serialization");
  require(std::memcmp(tagged->id, stripped->id, sizeof(tagged->id)) == 0, "debug symbols changed circuit ID");
  require(tagged->assertion_symbols && tagged->assertion_symbols->entries.size() == 1, "assertion alias did not survive as one symbol wire");
  const auto& entry = tagged->assertion_symbols->entries[0];
  require(entry.paths.size() == 2 && entry.paths[0] == "ecdsa/scalar/nonzero" && entry.paths[1] == "ecdsa/scalar/alias", "exact assertion paths missing");
  require(tagged->assertion_symbols->paths_for(entry.layer, entry.wire) != nullptr, "assertion diagnostic lookup failed");
  const auto artifact = tagged->assertion_symbols->to_bytes(tagged->id);
  require(artifact == tagged->assertion_symbols->to_bytes(tagged->id), "symbol artifact is not deterministic");
  proofs::AssertionSymbols parsed;
  require(proofs::AssertionSymbols::from_bytes(artifact, tagged->id, &parsed) == proofs::AssertionSymbolError::kNone && parsed.entries[0].paths == entry.paths, "symbol artifact did not round trip");
  auto wrong = tagged->id; wrong[0] ^= 1;
  require(proofs::AssertionSymbols::from_bytes(artifact, wrong, &parsed) == proofs::AssertionSymbolError::kWrongCircuit, "wrong-circuit symbols accepted");
  std::vector<uint8_t> malformed = artifact; malformed.pop_back();
  require(proofs::AssertionSymbols::from_bytes(malformed, tagged->id, &parsed) != proofs::AssertionSymbolError::kNone, "malformed symbols accepted");
  std::cout << "assertion symbol tests passed\n";
}
