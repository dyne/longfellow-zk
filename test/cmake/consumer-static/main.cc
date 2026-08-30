#include <circuits/merkle/fixed_depth_sha256_merkle_membership.h>

int main() {
  constexpr proofs::FixedDepthSha256MerklePath<0> path{};
  return path.direction_bits.size();
}
