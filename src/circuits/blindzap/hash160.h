// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0.
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_HASH160_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_HASH160_H_

#include <array>
#include "circuits/blindzap/compressed_key_sha256.h"
#include "circuits/ripemd160/ripemd160_fixed.h"

namespace proofs {

// The v1 public program is twenty explicit byte-shaped inputs.  The SEC key,
// SHA trace and SHA digest remain private witnesses; only these target bytes
// belong in the verifier statement.
template <class Logic>
class Hash160Circuit {
 public:
  using v8 = typename Logic::v8;
  using Sha = CompressedKeySha256Circuit<Logic>;
  struct Witness { typename Sha::Witness sha; void input(const Logic& l) { sha.input(l); } };
  explicit Hash160Circuit(const Logic& logic) : l_(logic), sha_(logic), ripemd_(logic) {}
  template <class CompressedKey>
  std::array<v8, 20> assert_hash160(const CompressedKey& key, const Witness& witness,
                                    const std::array<v8, 20>& public_program) const {
    const auto sha_digest = sha_.derive(key, witness.sha);
    const auto program = ripemd_.derive(sha_digest);
    for (size_t i = 0; i < program.size(); ++i) l_.vassert_eq(program[i], public_program[i]);
    return program;
  }
 private:
  const Logic& l_;
  Sha sha_;
  Ripemd160Fixed32<Logic> ripemd_;
};
}  // namespace proofs
#endif
