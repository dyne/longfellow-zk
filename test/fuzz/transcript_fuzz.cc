// Bounded libFuzzer entry point for transcript write/read state transitions.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>

#include "random/transcript.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > 4096) return 0;
  proofs::Transcript transcript(data, size);
  std::vector<uint8_t> output(std::min<size_t>(size, 256));
  transcript.bytes(output.data(), output.size());
  transcript.write(data, size);
  transcript.bytes(output.data(), output.size());
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
