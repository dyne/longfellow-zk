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
