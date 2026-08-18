// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_PROOF_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_PROOF_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>

#include "proto/circuit_writer.h"
#include "util/crypto.h"

namespace proofs {

// These parameters are part of the v1 proof identity and must be checked by
// both sides before a serialized proof is accepted.
struct BlindzapProofParametersV1 {
  static constexpr uint32_t kCircuitVersion = 1;
  static constexpr size_t kRate = 4;
  static constexpr size_t kQueries = 128;
};

struct BlindzapProofV1 {
  std::array<uint8_t, 32> circuit_digest{};
  uint32_t circuit_version = BlindzapProofParametersV1::kCircuitVersion;
  size_t rate = BlindzapProofParametersV1::kRate;
  size_t queries = BlindzapProofParametersV1::kQueries;
  std::vector<uint8_t> bytes;
};

// Canonical identity is computed from the exact Longfellow circuit encoding
// followed by the pinned version/rate/query tuple.  Verifiers compare it
// before parsing or invoking any proof machinery.
template <class Field>
inline std::array<uint8_t, 32> BlindzapCircuitDigest(
    const Circuit<Field>& circuit, const Field& field, FieldID field_id,
    size_t rate = BlindzapProofParametersV1::kRate,
    size_t queries = BlindzapProofParametersV1::kQueries) {
  std::vector<uint8_t> bytes;
  CircuitWriter<Field>(field, field_id).to_bytes(circuit, bytes);
  uint8_t params[24] = {};
  const uint64_t values[] = {BlindzapProofParametersV1::kCircuitVersion, rate, queries};
  for (size_t i = 0; i < 3; ++i) for (size_t j = 0; j < 8; ++j) params[i * 8 + j] = static_cast<uint8_t>(values[i] >> (8 * j));
  SHA256 hash; hash.Update(bytes.data(), bytes.size()); hash.Update(params, sizeof(params));
  std::array<uint8_t, 32> digest{}; hash.DigestData(digest.data()); return digest;
}

inline bool BlindzapProofIdentityMatches(const BlindzapProofV1& proof,
                                         const std::array<uint8_t, 32>& digest,
                                         size_t rate = BlindzapProofParametersV1::kRate,
                                         size_t queries = BlindzapProofParametersV1::kQueries) {
  return proof.circuit_version == BlindzapProofParametersV1::kCircuitVersion &&
      proof.rate == rate && proof.queries == queries &&
      std::memcmp(proof.circuit_digest.data(), digest.data(), digest.size()) == 0;
}

}  // namespace proofs
#endif
