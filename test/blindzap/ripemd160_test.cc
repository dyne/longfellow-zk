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

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "circuits/ripemd160/ripemd160.h"
#include "circuits/ripemd160/ripemd160_circuit.h"
#include "circuits/ripemd160/ripemd160_fixed.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"

namespace {
unsigned nibble(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }
void check(const char* message, const char* expected) {
  const auto got = proofs::Ripemd160::digest(reinterpret_cast<const uint8_t*>(message), std::strlen(message));
  for (size_t i = 0; i < got.size(); ++i) if (got[i] != ((nibble(expected[2*i]) << 4) | nibble(expected[2*i+1]))) throw std::runtime_error("RIPEMD-160 published vector mismatch");
}
void check_circuit() {
  using Field = proofs::Fp256k1Base;
  using Backend = proofs::EvaluationBackend<Field>;
  using Circuit = proofs::Logic<Field, Backend>;
  std::array<uint8_t, 64> block{};
  const char* abc = "abc";
  std::memcpy(block.data(), abc, 3); block[3] = 0x80; block[56] = 24;
  const Backend backend(proofs::p256k1_base, false);
  const Circuit circuit(&backend, proofs::p256k1_base);
  std::array<Circuit::v8, 64> bits;
  for (size_t i = 0; i < 64; ++i) bits[i] = circuit.template vbit<8>(block[i]);
  const auto words = proofs::Ripemd160Circuit<Circuit>(circuit).compress(bits);
  const auto native = proofs::Ripemd160::digest(reinterpret_cast<const uint8_t*>(abc), 3);
  for (size_t byte = 0; byte < native.size(); ++byte)
    for (size_t bit = 0; bit < 8; ++bit)
      if ((circuit.eval(words[byte / 4][(byte % 4) * 8 + bit]).elt() == proofs::p256k1_base.of_scalar(1)) != ((native[byte] >> bit) & 1u)) {
        throw std::runtime_error("RIPEMD-160 circuit output mismatch");
      }
  if (backend.assertion_failed()) throw std::runtime_error("RIPEMD-160 circuit rejected valid block");
}
void check_fixed_wrapper() {
  using Field = proofs::Fp256k1Base; using Backend = proofs::EvaluationBackend<Field>; using Circuit = proofs::Logic<Field, Backend>;
  const std::array<uint8_t, 32> sha = {0x0f,0x71,0x5b,0xaf,0x5d,0x4c,0x2e,0xd3,0x29,0x78,0x5c,0xef,0x29,0xe5,0x62,0xf7,0x34,0x88,0xc8,0xa2,0xbb,0x9d,0xbc,0x57,0x00,0xb3,0x61,0xd5,0x4b,0x9b,0x05,0x54};
  const auto native = proofs::Ripemd160::digest(sha);
  const Backend backend(proofs::p256k1_base, false); const Circuit circuit(&backend, proofs::p256k1_base);
  Circuit::v256 digest;
  for (size_t byte=0; byte<32; ++byte) for (size_t bit=0; bit<8; ++bit) digest[(31-byte)*8+bit] = circuit.bit((sha[byte] >> bit)&1u);
  const auto out = proofs::Ripemd160Fixed32<Circuit>(circuit).derive(digest);
  for (size_t byte=0; byte<20; ++byte) for (size_t bit=0; bit<8; ++bit)
    if ((circuit.eval(out[byte][bit]).elt() == proofs::p256k1_base.of_scalar(1)) != ((native[byte] >> bit)&1u)) throw std::runtime_error("RIPEMD fixed wrapper mismatch");
  if (backend.assertion_failed()) throw std::runtime_error("RIPEMD fixed wrapper rejected valid digest");
}
}
int main() {
  try {
    check("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    check("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    check("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    check("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36");
    check("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    check_circuit();
    check_fixed_wrapper();
    std::string long_message(1000000, 'a');
    check(long_message.c_str(), "52783243c1697bdbe16d37f97f68f08325dc1528");
    std::cout << "RIPEMD-160 tests passed\n";
  } catch (const std::exception& e) { std::cerr << "not ok - " << e.what() << '\n'; return 1; }
}
