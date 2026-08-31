#include <fstream>
#include <iterator>
#include <string>

int main(int argc, char** argv) {
  if (argc != 3) return 64;
  std::ifstream input(argv[1], std::ios::binary);
  std::ofstream output(argv[2], std::ios::binary);
  if (!input || !output) return 65;
  output << input.rdbuf();
  return output ? 0 : 66;
}
