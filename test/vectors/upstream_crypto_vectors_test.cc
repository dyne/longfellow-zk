// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// This test ports the SHA-256 boundary vectors from Google Longfellow-ZK's
// flatsha256_circuit_test and the standard RIPEMD-160 vectors exercised by
// its ripemd_circuit_test into Longfellow-ZK's standalone CTest harness.

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string_view>

#include "circuits/ripemd160/ripemd160.h"
#include "circuits/sha/flatsha256_witness.h"

namespace {

void require(bool condition, std::string_view message) {
  if (!condition) throw std::runtime_error(std::string(message));
}

int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

template <std::size_t N>
std::array<std::uint8_t, N> decode_hex(std::string_view encoded) {
  require(encoded.size() == N * 2, "unexpected hex vector length");
  std::array<std::uint8_t, N> output{};
  for (std::size_t index = 0; index < N; ++index) {
    const int high = hex_value(encoded[index * 2]);
    const int low = hex_value(encoded[index * 2 + 1]);
    require(high >= 0 && low >= 0, "invalid hex vector");
    output[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return output;
}

std::array<std::uint8_t, 32> sha256_witness_digest(std::string_view message) {
  constexpr std::size_t kMaxBlocks = 8;
  std::array<std::uint8_t, 64 * kMaxBlocks> padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, kMaxBlocks> witness{};
  std::uint8_t blocks = 0;
  proofs::FlatSHA256Witness::transform_and_witness_message(
      message.size(), reinterpret_cast<const std::uint8_t*>(message.data()),
      kMaxBlocks, blocks, padded.data(), witness.data());
  require(blocks > 0 && blocks <= kMaxBlocks, "unexpected SHA-256 block count");
  std::array<std::uint8_t, 32> digest{};
  for (std::size_t word = 0; word < 8; ++word) {
    const auto value = witness[blocks - 1].h1[word];
    for (std::size_t byte = 0; byte < 4; ++byte)
      digest[word * 4 + byte] = static_cast<std::uint8_t>(
          value >> (24 - static_cast<unsigned>(byte * 8)));
  }
  return digest;
}

void check_sha256_vectors() {
  struct Vector { std::string_view message; std::string_view digest; };
  constexpr Vector vectors[] = {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
      {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
      {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6"},
      {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"},
      {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
      {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"},
  };
  for (const auto& vector : vectors)
    require(sha256_witness_digest(vector.message) == decode_hex<32>(vector.digest),
            "SHA-256 witness vector mismatch");
  constexpr std::array<std::uint8_t, 4> binary = {0, 1, 2, 3};
  constexpr std::string_view binary_digests[] = {
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
      "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
      "ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc",
      "054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8",
  };
  for (std::size_t length = 1; length <= binary.size(); ++length) {
    const auto message = std::string_view(
        reinterpret_cast<const char*>(binary.data()), length);
    require(sha256_witness_digest(message) ==
                decode_hex<32>(binary_digests[length - 1]),
            "SHA-256 binary vector mismatch");
  }
}

void check_ripemd160_vectors() {
  struct Vector { std::string_view message; std::string_view digest; };
  constexpr Vector vectors[] = {
      {"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
      {"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
      {"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
      {"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
      {"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
  };
  for (const auto& vector : vectors) {
    const auto* input = reinterpret_cast<const std::uint8_t*>(vector.message.data());
    require(proofs::Ripemd160::digest(input, vector.message.size()) ==
                decode_hex<20>(vector.digest),
            "RIPEMD-160 vector mismatch");
  }
}

}  // namespace

int main() {
  try {
    check_sha256_vectors();
    check_ripemd160_vectors();
    std::cout << "upstream SHA-256 and RIPEMD-160 vectors passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
}
