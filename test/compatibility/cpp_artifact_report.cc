// Independently produces a deterministic byte report for compatibility inputs.
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>

uint64_t Fnv1a(const char* path, uint64_t* size) {
  std::ifstream input(path, std::ios::binary);
  uint64_t hash = 1469598103934665603ULL;
  *size = 0;
  for (char byte; input.get(byte); ++*size) {
    hash ^= static_cast<unsigned char>(byte);
    hash *= 1099511628211ULL;
  }
  return hash;
}

int main(int argc, char** argv) {
  for (int index = 1; index < argc; ++index) {
    uint64_t size = 0;
    const uint64_t hash = Fnv1a(argv[index], &size);
    std::cout << argv[index] << '\t' << size << '\t' << std::hex << std::setw(16)
              << std::setfill('0') << hash << std::dec << '\n';
  }
}
