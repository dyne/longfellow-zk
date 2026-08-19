// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_STATEMENT_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_STATEMENT_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "util/crypto.h"

namespace proofs {

// This is a protocol object, not a Bitcoin transaction or BIP-322 witness.
enum class BlindzapNetwork : uint8_t { kMainnet = 0, kTestnet = 1, kRegtest = 2 };
constexpr size_t kBlindzapMaxTextBytes = 1024;
constexpr size_t kBlindzapMaxClaims = 64;

struct BlindzapClaimV1 {
  std::array<uint8_t, 32> txid{};  // Bitcoin wire-order txid bytes.
  uint32_t vout = 0;
  uint64_t amount_sats = 0;
  std::array<uint8_t, 20> program{};
  bool operator<(const BlindzapClaimV1& other) const {
    const int c = std::memcmp(txid.data(), other.txid.data(), txid.size());
    return c != 0 ? c < 0 : vout < other.vout;
  }
  bool operator==(const BlindzapClaimV1& other) const {
    return txid == other.txid && vout == other.vout;
  }
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
  std::vector<BlindzapClaimV1> claims;
};

inline void BlindzapAppendU16(std::vector<uint8_t>* out, uint16_t value) {
  out->push_back(static_cast<uint8_t>(value >> 8)); out->push_back(static_cast<uint8_t>(value));
}
inline void BlindzapAppendU32(std::vector<uint8_t>* out, uint32_t value) {
  for (int i = 3; i >= 0; --i) out->push_back(static_cast<uint8_t>(value >> (i * 8)));
}
inline void BlindzapAppendU64(std::vector<uint8_t>* out, uint64_t value) {
  for (int i = 7; i >= 0; --i) out->push_back(static_cast<uint8_t>(value >> (i * 8)));
}
inline bool BlindzapUtf8(const std::string& text) {
  for (size_t i = 0; i < text.size();) {
    const uint8_t c = static_cast<uint8_t>(text[i++]);
    if (c < 0x80) continue;
    size_t n = c >= 0xf0 && c <= 0xf4 ? 3 : c >= 0xe0 && c <= 0xef ? 2 : c >= 0xc2 && c <= 0xdf ? 1 : 99;
    if (n == 99 || i + n > text.size()) return false;
    uint32_t code = c & ((1u << (6 - n)) - 1);
    for (size_t j = 0; j < n; ++j) { const uint8_t x = static_cast<uint8_t>(text[i++]); if ((x & 0xc0) != 0x80) return false; code = (code << 6) | (x & 0x3f); }
    if ((n == 1 && code < 0x80) || (n == 2 && code < 0x800) || (n == 3 && (code < 0x10000 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)))) return false;
  }
  return true;
}
inline bool BlindzapStatementValid(const BlindzapStatementV1& statement) {
  if (static_cast<uint8_t>(statement.network) > static_cast<uint8_t>(BlindzapNetwork::kRegtest) ||
      statement.verifier.empty() || statement.purpose.empty() || statement.verifier.size() > kBlindzapMaxTextBytes ||
      statement.purpose.size() > kBlindzapMaxTextBytes || !BlindzapUtf8(statement.verifier) || !BlindzapUtf8(statement.purpose) ||
      statement.not_before > statement.expires_at || statement.claims.empty() || statement.claims.size() > kBlindzapMaxClaims) return false;
  for (size_t i = 1; i < statement.claims.size(); ++i) if (!(statement.claims[i - 1] < statement.claims[i])) return false;
  return true;
}
inline bool EncodeBlindzapStatement(const BlindzapStatementV1& statement, std::vector<uint8_t>* out) {
  if (!out || !BlindzapStatementValid(statement)) return false;
  out->clear(); out->insert(out->end(), {'B','Z','P','1',1,static_cast<uint8_t>(statement.network)});
  BlindzapAppendU16(out, static_cast<uint16_t>(statement.verifier.size())); out->insert(out->end(), statement.verifier.begin(), statement.verifier.end());
  BlindzapAppendU16(out, static_cast<uint16_t>(statement.purpose.size())); out->insert(out->end(), statement.purpose.begin(), statement.purpose.end());
  out->insert(out->end(), statement.nonce.begin(), statement.nonce.end()); out->insert(out->end(), statement.bip322_message_hash.begin(), statement.bip322_message_hash.end());
  BlindzapAppendU64(out, statement.not_before); BlindzapAppendU64(out, statement.expires_at); out->push_back(statement.has_snapshot ? 1 : 0);
  if (statement.has_snapshot) out->insert(out->end(), statement.snapshot.begin(), statement.snapshot.end());
  BlindzapAppendU16(out, static_cast<uint16_t>(statement.claims.size()));
  for (const auto& claim : statement.claims) { out->insert(out->end(), claim.txid.begin(), claim.txid.end()); BlindzapAppendU32(out, claim.vout); BlindzapAppendU64(out, claim.amount_sats); out->insert(out->end(), claim.program.begin(), claim.program.end()); }
  return true;
}

class BlindzapReader {
 public:
  explicit BlindzapReader(const std::vector<uint8_t>& bytes) : p_(bytes.data()), left_(bytes.size()) {}
  bool bytes(uint8_t* out, size_t n) { if (n > left_) return false; std::memcpy(out, p_, n); p_ += n; left_ -= n; return true; }
  bool u8(uint8_t* out) { return bytes(out, 1); }
  bool u16(uint16_t* out) { uint8_t b[2]; if (!bytes(b, 2)) return false; *out = (uint16_t(b[0]) << 8) | b[1]; return true; }
  bool u32(uint32_t* out) { uint8_t b[4]; if (!bytes(b, 4)) return false; *out = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | b[3]; return true; }
  bool u64(uint64_t* out) { uint8_t b[8]; if (!bytes(b, 8)) return false; *out = 0; for (uint8_t x : b) *out = (*out << 8) | x; return true; }
  bool text(std::string* out) { uint16_t n; if (!u16(&n) || n > kBlindzapMaxTextBytes || n > left_) return false; out->assign(reinterpret_cast<const char*>(p_), n); p_ += n; left_ -= n; return BlindzapUtf8(*out); }
  size_t left() const { return left_; }
 private: const uint8_t* p_; size_t left_;
};

inline bool DecodeBlindzapStatement(const std::vector<uint8_t>& bytes, BlindzapStatementV1* statement) {
  if (!statement || bytes.size() < 6) return false; BlindzapReader r(bytes); uint8_t magic[4], version, network;
  if (!r.bytes(magic, 4) || std::memcmp(magic, "BZP1", 4) || !r.u8(&version) || version != 1 || !r.u8(&network) || network > 2) return false;
  BlindzapStatementV1 out; out.network = static_cast<BlindzapNetwork>(network);
  if (!r.text(&out.verifier) || !r.text(&out.purpose) || !r.bytes(out.nonce.data(), 32) || !r.bytes(out.bip322_message_hash.data(), 32) || !r.u64(&out.not_before) || !r.u64(&out.expires_at)) return false;
  uint8_t present; if (!r.u8(&present) || present > 1) return false; out.has_snapshot = present == 1; if (out.has_snapshot && !r.bytes(out.snapshot.data(), 32)) return false;
  uint16_t count; if (!r.u16(&count) || !count || count > kBlindzapMaxClaims) return false; out.claims.resize(count);
  for (auto& claim : out.claims) if (!r.bytes(claim.txid.data(), 32) || !r.u32(&claim.vout) || !r.u64(&claim.amount_sats) || !r.bytes(claim.program.data(), 20)) return false;
  if (r.left() || !BlindzapStatementValid(out)) return false; *statement = std::move(out); return true;
}

inline std::array<uint8_t, 32> BlindzapTaggedHash(const char* tag, const uint8_t* data, size_t size) {
  std::array<uint8_t, 32> tag_hash{}, out{}; SHA256 hash; hash.Update(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag)); hash.DigestData(tag_hash.data());
  SHA256 tagged; tagged.Update(tag_hash.data(), tag_hash.size()); tagged.Update(tag_hash.data(), tag_hash.size()); if (size) tagged.Update(data, size); tagged.DigestData(out.data()); return out;
}
inline std::array<uint8_t, 32> BlindzapBip322MessageHash(const uint8_t* message, size_t size) { return BlindzapTaggedHash("BIP0322-signed-message", message, size); }
inline bool BlindzapStatementDigest(const BlindzapStatementV1& statement, std::array<uint8_t, 32>* digest) { std::vector<uint8_t> bytes; if (!digest || !EncodeBlindzapStatement(statement, &bytes)) return false; *digest = BlindzapTaggedHash("BlindZap/proof/v1", bytes.data(), bytes.size()); return true; }

}  // namespace proofs
#endif
