// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_STATEMENT_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_STATEMENT_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "util/crypto.h"

namespace proofs {

// Values 0..3 were assigned by the original v1 draft. Testnet4 is appended so
// adding it cannot reinterpret an already serialized signet or regtest request.
enum class BlindzapNetwork : uint8_t {
  kMainnet = 0,
  kTestnet3 = 1,
  kTestnet = kTestnet3,
  kSignet = 2,
  kRegtest = 3,
  kTestnet4 = 4,
};

constexpr size_t kBlindzapMaxVerifierBytes = 256;
constexpr size_t kBlindzapMaxPurposeBytes = 64;
constexpr size_t kBlindzapMaxAssetIdBytes = 256;
constexpr size_t kBlindzapMaxClaims = 16;
constexpr size_t kBlindzapMaxKeys = 2;
constexpr size_t kBlindzapMaxStatementBytes = 4096;
constexpr uint64_t kBlindzapMaxMoneySats = 21000000ULL * 100000000ULL;

enum class BlindzapDecodeError : uint8_t { kNone, kMalformed, kUnsupported };

inline bool BlindzapNetworkValid(BlindzapNetwork network) {
  switch (network) {
    case BlindzapNetwork::kMainnet:
    case BlindzapNetwork::kTestnet3:
    case BlindzapNetwork::kSignet:
    case BlindzapNetwork::kRegtest:
    case BlindzapNetwork::kTestnet4:
      return true;
  }
  return false;
}

inline const char* BlindzapNetworkName(BlindzapNetwork network) {
  switch (network) {
    case BlindzapNetwork::kMainnet: return "mainnet";
    case BlindzapNetwork::kTestnet3: return "testnet3";
    case BlindzapNetwork::kSignet: return "signet";
    case BlindzapNetwork::kRegtest: return "regtest";
    case BlindzapNetwork::kTestnet4: return "testnet4";
  }
  return "unsupported";
}

inline const char* BlindzapBitcoinCoreChainName(BlindzapNetwork network) {
  switch (network) {
    case BlindzapNetwork::kMainnet: return "main";
    case BlindzapNetwork::kTestnet3: return "test";
    case BlindzapNetwork::kSignet: return "signet";
    case BlindzapNetwork::kRegtest: return "regtest";
    case BlindzapNetwork::kTestnet4: return "testnet4";
  }
  return "";
}

inline bool BlindzapParseNetwork(const std::string& name,
                                 BlindzapNetwork* network) {
  if (network == nullptr) return false;
  if (name == "mainnet" || name == "main") {
    *network = BlindzapNetwork::kMainnet;
  } else if (name == "testnet" || name == "testnet3" || name == "test") {
    *network = BlindzapNetwork::kTestnet3;
  } else if (name == "testnet4") {
    *network = BlindzapNetwork::kTestnet4;
  } else if (name == "signet") {
    *network = BlindzapNetwork::kSignet;
  } else if (name == "regtest") {
    *network = BlindzapNetwork::kRegtest;
  } else {
    return false;
  }
  return true;
}

template <size_t N>
inline bool BlindzapAllZero(const std::array<uint8_t, N>& value) {
  uint8_t aggregate = 0;
  for (uint8_t byte : value) aggregate |= byte;
  return aggregate == 0;
}

struct BlindzapClaimV1 {
  std::array<uint8_t, 32> txid{};  // Bitcoin RPC/display byte order.
  uint32_t vout = 0;
  uint64_t amount_sats = 0;
  std::array<uint8_t, 20> program{};

  bool operator<(const BlindzapClaimV1& other) const {
    const int comparison = std::memcmp(txid.data(), other.txid.data(), txid.size());
    return comparison != 0 ? comparison < 0 : vout < other.vout;
  }
  bool operator==(const BlindzapClaimV1& other) const {
    return txid == other.txid && vout == other.vout;
  }
};

struct BlindzapBridgeBindingV1 {
  BlindzapNetwork destination_network = BlindzapNetwork::kMainnet;
  std::array<uint8_t, 32> destination_commitment{};
  std::string asset_id;
  std::array<uint8_t, 32> lock_id{};
};

struct BlindzapStatementV1 {
  BlindzapNetwork network = BlindzapNetwork::kMainnet;
  std::string verifier;
  std::string purpose;
  std::array<uint8_t, 32> nonce{};
  std::array<uint8_t, 32> bip322_message_hash{};
  uint64_t not_before = 0;
  uint64_t expires_at = 0;
  bool has_snapshot = false;
  std::array<uint8_t, 32> snapshot{};
  uint32_t snapshot_height = 0;
  bool has_bridge_binding = false;
  BlindzapBridgeBindingV1 bridge;
  std::vector<BlindzapClaimV1> claims;
};

inline bool BlindzapUtf8(const std::string& text) {
  for (size_t index = 0; index < text.size();) {
    const uint8_t lead = static_cast<uint8_t>(text[index++]);
    if (lead < 0x20 || lead == 0x7f) return false;
    if (lead < 0x80) continue;
    const size_t continuation =
        lead >= 0xf0 && lead <= 0xf4 ? 3 :
        lead >= 0xe0 && lead <= 0xef ? 2 :
        lead >= 0xc2 && lead <= 0xdf ? 1 : 99;
    if (continuation == 99 || index + continuation > text.size()) return false;
    uint32_t codepoint = lead & ((1u << (6 - continuation)) - 1);
    for (size_t i = 0; i < continuation; ++i) {
      const uint8_t byte = static_cast<uint8_t>(text[index++]);
      if ((byte & 0xc0) != 0x80) return false;
      codepoint = (codepoint << 6) | (byte & 0x3f);
    }
    if ((continuation == 1 && codepoint < 0x80) ||
        (continuation == 2 && codepoint < 0x800) ||
        (continuation == 3 && (codepoint < 0x10000 || codepoint > 0x10ffff)) ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
      return false;
    }
  }
  return true;
}

inline bool BlindzapPurposeValid(const std::string& purpose) {
  return purpose == "proof-of-control" || purpose == "proof-of-funds" ||
         purpose == "bridge-authorization";
}

inline bool BlindzapProgramLess(const std::array<uint8_t, 20>& left,
                                const std::array<uint8_t, 20>& right) {
  return std::memcmp(left.data(), right.data(), left.size()) < 0;
}

inline bool BlindzapStatementValid(const BlindzapStatementV1& statement) {
  if (!BlindzapNetworkValid(statement.network) || statement.verifier.empty() ||
      statement.verifier.size() > kBlindzapMaxVerifierBytes ||
      !BlindzapUtf8(statement.verifier) || !BlindzapPurposeValid(statement.purpose) ||
      statement.purpose.size() > kBlindzapMaxPurposeBytes ||
      BlindzapAllZero(statement.nonce) ||
      BlindzapAllZero(statement.bip322_message_hash) ||
      statement.not_before >= statement.expires_at || statement.claims.empty() ||
      statement.claims.size() > kBlindzapMaxClaims) {
    return false;
  }
  if (statement.has_snapshot && BlindzapAllZero(statement.snapshot)) return false;
  if (!statement.has_snapshot &&
      (!BlindzapAllZero(statement.snapshot) || statement.snapshot_height != 0)) {
    return false;
  }
  if (statement.has_bridge_binding) {
    if (statement.purpose != "bridge-authorization" ||
        !BlindzapNetworkValid(statement.bridge.destination_network) ||
        BlindzapAllZero(statement.bridge.destination_commitment) ||
        statement.bridge.asset_id.empty() ||
        statement.bridge.asset_id.size() > kBlindzapMaxAssetIdBytes ||
        !BlindzapUtf8(statement.bridge.asset_id) ||
        BlindzapAllZero(statement.bridge.lock_id)) {
      return false;
    }
  } else if (statement.purpose == "bridge-authorization") {
    return false;
  }

  std::vector<std::array<uint8_t, 20>> programs;
  programs.reserve(statement.claims.size());
  uint64_t total_sats = 0;
  for (size_t index = 0; index < statement.claims.size(); ++index) {
    const auto& claim = statement.claims[index];
    if (BlindzapAllZero(claim.txid) || claim.amount_sats == 0 ||
        claim.amount_sats > kBlindzapMaxMoneySats ||
        claim.amount_sats > kBlindzapMaxMoneySats - total_sats ||
        (index != 0 && !(statement.claims[index - 1] < claim))) {
      return false;
    }
    total_sats += claim.amount_sats;
    programs.push_back(claim.program);
  }
  std::sort(programs.begin(), programs.end(), BlindzapProgramLess);
  programs.erase(std::unique(programs.begin(), programs.end()), programs.end());
  return !programs.empty() && programs.size() <= kBlindzapMaxKeys;
}

inline bool BlindzapDistinctPrograms(
    const BlindzapStatementV1& statement,
    std::vector<std::array<uint8_t, 20>>* programs) {
  if (programs == nullptr || !BlindzapStatementValid(statement)) return false;
  programs->clear();
  programs->reserve(statement.claims.size());
  for (const auto& claim : statement.claims) programs->push_back(claim.program);
  std::sort(programs->begin(), programs->end(), BlindzapProgramLess);
  programs->erase(std::unique(programs->begin(), programs->end()), programs->end());
  return true;
}

inline void BlindzapAppendU16(std::vector<uint8_t>* output, uint16_t value) {
  output->push_back(static_cast<uint8_t>(value >> 8));
  output->push_back(static_cast<uint8_t>(value));
}
inline void BlindzapAppendU32(std::vector<uint8_t>* output, uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8)
    output->push_back(static_cast<uint8_t>(value >> shift));
}
inline void BlindzapAppendU64(std::vector<uint8_t>* output, uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8)
    output->push_back(static_cast<uint8_t>(value >> shift));
}

inline bool EncodeBlindzapStatement(const BlindzapStatementV1& statement,
                                    std::vector<uint8_t>* output) {
  if (output == nullptr || !BlindzapStatementValid(statement)) return false;
  output->clear();
  output->insert(output->end(), {'B', 'Z', 'P', '1', 1,
                                 static_cast<uint8_t>(statement.network)});
  BlindzapAppendU16(output, static_cast<uint16_t>(statement.verifier.size()));
  output->insert(output->end(), statement.verifier.begin(), statement.verifier.end());
  BlindzapAppendU16(output, static_cast<uint16_t>(statement.purpose.size()));
  output->insert(output->end(), statement.purpose.begin(), statement.purpose.end());
  output->insert(output->end(), statement.nonce.begin(), statement.nonce.end());
  output->insert(output->end(), statement.bip322_message_hash.begin(),
                 statement.bip322_message_hash.end());
  BlindzapAppendU64(output, statement.not_before);
  BlindzapAppendU64(output, statement.expires_at);
  output->push_back(statement.has_snapshot ? 1 : 0);
  if (statement.has_snapshot) {
    output->insert(output->end(), statement.snapshot.begin(), statement.snapshot.end());
    BlindzapAppendU32(output, statement.snapshot_height);
  }
  output->push_back(statement.has_bridge_binding ? 1 : 0);
  if (statement.has_bridge_binding) {
    output->push_back(static_cast<uint8_t>(statement.bridge.destination_network));
    output->insert(output->end(), statement.bridge.destination_commitment.begin(),
                   statement.bridge.destination_commitment.end());
    BlindzapAppendU16(output,
                     static_cast<uint16_t>(statement.bridge.asset_id.size()));
    output->insert(output->end(), statement.bridge.asset_id.begin(),
                   statement.bridge.asset_id.end());
    output->insert(output->end(), statement.bridge.lock_id.begin(),
                   statement.bridge.lock_id.end());
  }
  BlindzapAppendU16(output, static_cast<uint16_t>(statement.claims.size()));
  for (const auto& claim : statement.claims) {
    output->insert(output->end(), claim.txid.begin(), claim.txid.end());
    BlindzapAppendU32(output, claim.vout);
    BlindzapAppendU64(output, claim.amount_sats);
    output->insert(output->end(), claim.program.begin(), claim.program.end());
  }
  return output->size() <= kBlindzapMaxStatementBytes;
}

class BlindzapReader {
 public:
  explicit BlindzapReader(const std::vector<uint8_t>& bytes)
      : pointer_(bytes.data()), remaining_(bytes.size()) {}
  bool bytes(uint8_t* output, size_t size) {
    if (size > remaining_ || (size != 0 && output == nullptr)) return false;
    if (size != 0) std::memcpy(output, pointer_, size);
    pointer_ += size;
    remaining_ -= size;
    return true;
  }
  bool u8(uint8_t* output) { return bytes(output, 1); }
  bool u16(uint16_t* output) {
    uint8_t bytes_value[2];
    if (output == nullptr || !bytes(bytes_value, sizeof(bytes_value))) return false;
    *output = (uint16_t(bytes_value[0]) << 8) | bytes_value[1];
    return true;
  }
  bool u32(uint32_t* output) {
    uint8_t bytes_value[4];
    if (output == nullptr || !bytes(bytes_value, sizeof(bytes_value))) return false;
    *output = (uint32_t(bytes_value[0]) << 24) |
              (uint32_t(bytes_value[1]) << 16) |
              (uint32_t(bytes_value[2]) << 8) | bytes_value[3];
    return true;
  }
  bool u64(uint64_t* output) {
    uint8_t bytes_value[8];
    if (output == nullptr || !bytes(bytes_value, sizeof(bytes_value))) return false;
    *output = 0;
    for (uint8_t byte : bytes_value) *output = (*output << 8) | byte;
    return true;
  }
  bool text(std::string* output, size_t maximum) {
    uint16_t size = 0;
    if (output == nullptr || !u16(&size) || size > maximum || size > remaining_)
      return false;
    output->assign(reinterpret_cast<const char*>(pointer_), size);
    pointer_ += size;
    remaining_ -= size;
    return BlindzapUtf8(*output);
  }
  size_t left() const { return remaining_; }

 private:
  const uint8_t* pointer_;
  size_t remaining_;
};

inline bool DecodeBlindzapStatement(
    const std::vector<uint8_t>& bytes, BlindzapStatementV1* statement,
    BlindzapDecodeError* error = nullptr) {
  if (error != nullptr) *error = BlindzapDecodeError::kMalformed;
  if (statement == nullptr || bytes.size() < 6 ||
      bytes.size() > kBlindzapMaxStatementBytes) {
    return false;
  }
  BlindzapReader reader(bytes);
  uint8_t magic[4] = {}, version = 0, network_byte = 0;
  if (!reader.bytes(magic, sizeof(magic)) || std::memcmp(magic, "BZP1", 4) != 0)
    return false;
  if (!reader.u8(&version) || version != 1) {
    if (error != nullptr) *error = BlindzapDecodeError::kUnsupported;
    return false;
  }
  if (!reader.u8(&network_byte)) return false;
  const auto network = static_cast<BlindzapNetwork>(network_byte);
  if (!BlindzapNetworkValid(network)) {
    if (error != nullptr) *error = BlindzapDecodeError::kUnsupported;
    return false;
  }

  BlindzapStatementV1 decoded;
  decoded.network = network;
  if (!reader.text(&decoded.verifier, kBlindzapMaxVerifierBytes) ||
      !reader.text(&decoded.purpose, kBlindzapMaxPurposeBytes) ||
      !reader.bytes(decoded.nonce.data(), decoded.nonce.size()) ||
      !reader.bytes(decoded.bip322_message_hash.data(),
                    decoded.bip322_message_hash.size()) ||
      !reader.u64(&decoded.not_before) || !reader.u64(&decoded.expires_at)) {
    return false;
  }
  uint8_t present = 0;
  if (!reader.u8(&present) || present > 1) return false;
  decoded.has_snapshot = present == 1;
  if (decoded.has_snapshot &&
      (!reader.bytes(decoded.snapshot.data(), decoded.snapshot.size()) ||
       !reader.u32(&decoded.snapshot_height))) {
    return false;
  }
  if (!reader.u8(&present) || present > 1) return false;
  decoded.has_bridge_binding = present == 1;
  if (decoded.has_bridge_binding) {
    uint8_t destination_network = 0;
    if (!reader.u8(&destination_network)) return false;
    decoded.bridge.destination_network =
        static_cast<BlindzapNetwork>(destination_network);
    if (!BlindzapNetworkValid(decoded.bridge.destination_network)) {
      if (error != nullptr) *error = BlindzapDecodeError::kUnsupported;
      return false;
    }
    if (!reader.bytes(decoded.bridge.destination_commitment.data(),
                      decoded.bridge.destination_commitment.size()) ||
        !reader.text(&decoded.bridge.asset_id, kBlindzapMaxAssetIdBytes) ||
        !reader.bytes(decoded.bridge.lock_id.data(), decoded.bridge.lock_id.size())) {
      return false;
    }
  }
  uint16_t count = 0;
  if (!reader.u16(&count) || count == 0 || count > kBlindzapMaxClaims) return false;
  decoded.claims.resize(count);
  for (auto& claim : decoded.claims) {
    if (!reader.bytes(claim.txid.data(), claim.txid.size()) ||
        !reader.u32(&claim.vout) || !reader.u64(&claim.amount_sats) ||
        !reader.bytes(claim.program.data(), claim.program.size())) {
      return false;
    }
  }
  if (reader.left() != 0 || !BlindzapStatementValid(decoded)) return false;
  *statement = std::move(decoded);
  if (error != nullptr) *error = BlindzapDecodeError::kNone;
  return true;
}

inline std::array<uint8_t, 32> BlindzapTaggedHash(const char* tag,
                                                  const uint8_t* data,
                                                  size_t size) {
  std::array<uint8_t, 32> tag_hash{}, output{};
  SHA256 tag_hasher;
  tag_hasher.Update(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag));
  tag_hasher.DigestData(tag_hash.data());
  SHA256 hasher;
  hasher.Update(tag_hash.data(), tag_hash.size());
  hasher.Update(tag_hash.data(), tag_hash.size());
  if (size != 0) hasher.Update(data, size);
  hasher.DigestData(output.data());
  return output;
}

inline std::array<uint8_t, 32> BlindzapBip322MessageHash(
    const uint8_t* message, size_t size) {
  return BlindzapTaggedHash("BIP0322-signed-message", message, size);
}

inline bool BlindzapStatementDigest(const BlindzapStatementV1& statement,
                                    std::array<uint8_t, 32>* digest) {
  std::vector<uint8_t> bytes;
  if (digest == nullptr || !EncodeBlindzapStatement(statement, &bytes)) return false;
  *digest = BlindzapTaggedHash("BlindZap/statement/v1", bytes.data(), bytes.size());
  return true;
}

}  // namespace proofs
#endif
