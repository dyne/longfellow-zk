#include <array>
#include <cstdint>

#include "util/randombytes.h"

int main() {
  std::array<std::uint8_t, 8> bytes{};
  return randombytes(bytes.data(), bytes.size());
}
