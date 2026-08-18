// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0.
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_BLINDZAP_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_BLINDZAP_CIRCUIT_H_

#include <array>

#include "circuits/blindzap/hash160.h"
#include "circuits/blindzap/key_ownership.h"
#include "circuits/logic/bit_plucker.h"

namespace proofs {

// BlindZap v1 has a deliberately small public circuit statement.  The first
// input is Longfellow's mandatory constant one; it is followed by exactly 20
// byte-shaped witness-program elements.  Every scalar, point, SEC byte and
// hash intermediate is allocated after private_input().
template <class LogicCircuit, class Field, class EC>
class BlindzapCircuitV1 {
 public:
  static constexpr size_t kProgramBytes = 20;
  static constexpr uint32_t kVersion = 1;
  using EltW = typename LogicCircuit::EltW;
  using v8 = typename LogicCircuit::v8;
  using BytePlucker = BitPlucker<LogicCircuit, 8>;
  using Ownership = KeyOwnershipCircuit<LogicCircuit, Field, EC>;
  using Hash160 = Hash160Circuit<LogicCircuit>;

  struct Witness {
    typename Ownership::Witness ownership;
    typename Hash160::Witness hash160;
    void input(const LogicCircuit& lc) {
      ownership.input(lc);
      hash160.input(lc);
    }
  };

  explicit BlindzapCircuitV1(const LogicCircuit& lc, const EC& ec)
      : lc_(lc), ownership_(lc, ec), hash160_(lc), bytes_(lc) {}

  // Each public element is constrained by the bit plucker to encode one
  // canonical eight-bit program byte.  The encoded field representation is
  // an API detail; callers use EncodeProgram() when filling public inputs.
  void assert_program(const std::array<EltW, kProgramBytes>& encoded_program,
                      const Witness& witness) const {
    std::array<v8, kProgramBytes> program;
    for (size_t i = 0; i < program.size(); ++i) program[i] = bytes_.pluck(encoded_program[i]);
    const auto key = ownership_.derive(witness.ownership);
    (void)hash160_.assert_hash160(key, witness.hash160, program);
  }

 private:
  const LogicCircuit& lc_;
  Ownership ownership_;
  Hash160 hash160_;
  BytePlucker bytes_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BLINDZAP_BLINDZAP_CIRCUIT_H_
