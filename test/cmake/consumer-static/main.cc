#include <util/randombytes.h>
#include <array>
int main() { std::array<unsigned char, 1> bytes{}; return randombytes(bytes.data(), bytes.size()); }
