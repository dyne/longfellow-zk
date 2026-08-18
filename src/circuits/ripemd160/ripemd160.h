// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0.
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_RIPEMD160_RIPEMD160_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_RIPEMD160_RIPEMD160_H_

#include <array>
#include <cstddef>
#include <cstdint>

namespace proofs {

// A deliberately small, portable RIPEMD-160 reference.  All message words
// are decoded explicitly little-endian, so the result is independent of host
// endianness and alignment.
class Ripemd160 {
 public:
  static std::array<uint8_t, 20> digest(const uint8_t* message, size_t length) {
    uint32_t h[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
    size_t offset = 0;
    while (length - offset >= 64) { transform(h, message + offset); offset += 64; }
    uint8_t block[128] = {};
    const size_t tail = length - offset;
    for (size_t i = 0; i < tail; ++i) block[i] = message[offset + i];
    block[tail] = 0x80;
    const size_t blocks = tail >= 56 ? 2 : 1;
    const uint64_t bits = static_cast<uint64_t>(length) * 8u;
    const size_t length_offset = blocks * 64 - 8;
    for (size_t i = 0; i < 8; ++i) block[length_offset + i] = static_cast<uint8_t>(bits >> (8 * i));
    transform(h, block);
    if (blocks == 2) transform(h, block + 64);
    std::array<uint8_t, 20> out{};
    for (size_t word = 0; word < 5; ++word)
      for (size_t byte = 0; byte < 4; ++byte) out[word * 4 + byte] = static_cast<uint8_t>(h[word] >> (8 * byte));
    return out;
  }

  template <size_t N>
  static std::array<uint8_t, 20> digest(const std::array<uint8_t, N>& message) {
    return digest(message.data(), message.size());
  }

 private:
  static uint32_t rol(uint32_t value, unsigned count) {
    return (value << count) | (value >> (32u - count));
  }
  static uint32_t read_le(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
  }
  static uint32_t f(unsigned round, uint32_t x, uint32_t y, uint32_t z) {
    if (round < 16) return x ^ y ^ z;
    if (round < 32) return (x & y) | (~x & z);
    if (round < 48) return (x | ~y) ^ z;
    if (round < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }
  static uint32_t k(unsigned round) {
    static constexpr uint32_t v[] = {0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xa953fd4eu};
    return v[round / 16];
  }
  static uint32_t kk(unsigned round) {
    static constexpr uint32_t v[] = {0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x7a6d76e9u, 0x00000000u};
    return v[round / 16];
  }
  static void transform(uint32_t h[5], const uint8_t block[64]) {
    static constexpr uint8_t r[80] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
    static constexpr uint8_t rr[80] = {5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
    static constexpr uint8_t s[80] = {11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
    static constexpr uint8_t ss[80] = {8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
    uint32_t x[16]; for (size_t i = 0; i < 16; ++i) x[i] = read_le(block + 4 * i);
    uint32_t al=h[0], bl=h[1], cl=h[2], dl=h[3], el=h[4];
    uint32_t ar=al, br=bl, cr=cl, dr=dl, er=el;
    for (unsigned j = 0; j < 80; ++j) {
      uint32_t t = rol(al + f(j, bl, cl, dl) + x[r[j]] + k(j), s[j]) + el;
      al=el; el=dl; dl=rol(cl, 10); cl=bl; bl=t;
      t = rol(ar + f(79-j, br, cr, dr) + x[rr[j]] + kk(j), ss[j]) + er;
      ar=er; er=dr; dr=rol(cr, 10); cr=br; br=t;
    }
    const uint32_t t = h[1] + cl + dr;
    h[1] = h[2] + dl + er; h[2] = h[3] + el + ar; h[3] = h[4] + al + br; h[4] = h[0] + bl + cr; h[0] = t;
  }
};

}  // namespace proofs
#endif
