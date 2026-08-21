// Bounded libFuzzer entry point for untrusted LFC1 circuit bytes.
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>

#include "ec/p256.h"
#include "proto/circuit_reader.h"
#include "util/readbuffer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > 1024 * 1024) return 0;
  std::vector<uint8_t> input(data, data + size);
  proofs::ReadBuffer buffer(input);
  proofs::CircuitReader<proofs::Fp256Base> reader(proofs::p256_base, proofs::P256_ID);
  (void)reader.from_bytes(buffer, true);
  return 0;
}

#ifdef FUZZ_STANDALONE
int main(int argc, char** argv) {
  for (int index = 1; index < argc; ++index) {
    std::ifstream stream(argv[index], std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(stream)), {});
    LLVMFuzzerTestOneInput(data.data(), data.size());
  }
  return 0;
}
#endif
