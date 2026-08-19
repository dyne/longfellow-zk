// Copyright 2026 Google LLC.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_ENVELOPE_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_ENVELOPE_H_

#include <functional>
#include <sstream>
#include "blindzap/proof.h"
#include "blindzap/statement.h"

namespace proofs {
// The v1 native BlindZap proof measured 46,879,xxx bytes.  Keep a fixed 64
// MiB parsing ceiling: it admits that representation with about 17 MiB of
// headroom, while retaining a finite allocation limit at the wire boundary.
constexpr size_t kBlindzapMaxProofBytes = 64 * 1024 * 1024;
struct BlindzapEnvelopeV1 { BlindzapStatementV1 statement; BlindzapProofV1 proof; };

inline bool EncodeBlindzapEnvelope(const BlindzapEnvelopeV1& envelope, std::vector<uint8_t>* out) {
  std::vector<uint8_t> statement; if (!out || !EncodeBlindzapStatement(envelope.statement, &statement) || statement.size() > std::numeric_limits<uint32_t>::max() || envelope.proof.bytes.size() > kBlindzapMaxProofBytes || envelope.proof.rate > std::numeric_limits<uint32_t>::max() || envelope.proof.queries > std::numeric_limits<uint32_t>::max()) return false;
  out->clear(); out->insert(out->end(), {'B','Z','E','1',1}); BlindzapAppendU32(out, static_cast<uint32_t>(statement.size())); out->insert(out->end(), statement.begin(), statement.end()); out->insert(out->end(), envelope.proof.circuit_digest.begin(), envelope.proof.circuit_digest.end()); BlindzapAppendU32(out, envelope.proof.circuit_version); BlindzapAppendU32(out, static_cast<uint32_t>(envelope.proof.rate)); BlindzapAppendU32(out, static_cast<uint32_t>(envelope.proof.queries)); BlindzapAppendU32(out, static_cast<uint32_t>(envelope.proof.bytes.size())); out->insert(out->end(), envelope.proof.bytes.begin(), envelope.proof.bytes.end()); return true;
}
inline bool DecodeBlindzapEnvelope(const std::vector<uint8_t>& bytes, BlindzapEnvelopeV1* envelope) {
  if (!envelope || bytes.size() < 5) return false; BlindzapReader r(bytes); uint8_t magic[4], version; uint32_t n;
  if (!r.bytes(magic, 4) || std::memcmp(magic, "BZE1", 4) || !r.u8(&version) || version != 1 || !r.u32(&n) || n > r.left()) return false;
  std::vector<uint8_t> statement(n); if (!r.bytes(statement.data(), n)) return false; BlindzapEnvelopeV1 out; if (!DecodeBlindzapStatement(statement, &out.statement) || !r.bytes(out.proof.circuit_digest.data(), 32) || !r.u32(&out.proof.circuit_version)) return false;
  uint32_t rate, queries, proof_size; if (!r.u32(&rate) || !r.u32(&queries) || !r.u32(&proof_size) ||
      out.proof.circuit_version != BlindzapProofParametersV1::kCircuitVersion || rate != BlindzapProofParametersV1::kRate ||
      queries != BlindzapProofParametersV1::kQueries || proof_size > kBlindzapMaxProofBytes || proof_size != r.left()) return false;
  out.proof.rate = rate; out.proof.queries = queries; out.proof.bytes.resize(proof_size); if (!r.bytes(out.proof.bytes.data(), proof_size)) return false; *envelope = std::move(out); return true;
}

// Inspection is deliberately a presentation format. Verification always uses
// EncodeBlindzapStatement/EncodeBlindzapEnvelope, never this JSON.
inline std::string BlindzapInspectJson(const BlindzapEnvelopeV1& envelope) {
  std::vector<uint8_t> statement; if (!EncodeBlindzapStatement(envelope.statement, &statement)) return "";
  static const char hex[] = "0123456789abcdef";
  auto hexify = [&](const uint8_t* p, size_t n) { std::string out; out.reserve(n * 2); for (size_t i = 0; i < n; ++i) { out.push_back(hex[p[i] >> 4]); out.push_back(hex[p[i] & 15]); } return out; };
  auto json = [](const std::string& value) { std::string out; for (unsigned char c : value) { if (c == '"' || c == '\\') out.push_back('\\'); if (c >= 0x20) out.push_back(static_cast<char>(c)); } return out; };
  std::ostringstream out; out << "{\"format\":\"blindzap-pof-v1\",\"network\":" << unsigned(envelope.statement.network)
      << ",\"verifier\":\"" << json(envelope.statement.verifier) << "\",\"purpose\":\"" << json(envelope.statement.purpose)
      << "\",\"statement_bytes\":" << statement.size() << ",\"circuit_digest\":\"" << hexify(envelope.proof.circuit_digest.data(), 32)
      << "\",\"proof_bytes\":" << envelope.proof.bytes.size() << ",\"claims\":" << envelope.statement.claims.size() << "}";
  return out.str();
}

inline std::array<uint8_t, 32> BlindzapTranscriptSeed(const BlindzapStatementV1& statement, const BlindzapProofV1& proof) {
  std::array<uint8_t, 32> digest{}; if (!BlindzapStatementDigest(statement, &digest)) return {}; std::vector<uint8_t> binding(digest.begin(), digest.end()); binding.insert(binding.end(), proof.circuit_digest.begin(), proof.circuit_digest.end()); BlindzapAppendU32(&binding, proof.circuit_version); BlindzapAppendU32(&binding, static_cast<uint32_t>(proof.rate)); BlindzapAppendU32(&binding, static_cast<uint32_t>(proof.queries)); return BlindzapTaggedHash("BlindZap/transcript/v1", binding.data(), binding.size());
}

enum class BlindzapAuthorization { kInvalid, kPendingReplayCheck, kReplayRejected, kPolicyRejected, kAuthorized };
struct BlindzapReplayPolicy { uint64_t now = 0; uint64_t max_lifetime = 0; std::string verifier; std::string purpose; std::function<bool(const std::array<uint8_t, 32>&)> nonce_seen; std::function<bool(const std::array<uint8_t, 32>&)> consume_nonce; };
inline BlindzapAuthorization BlindzapCheckPolicy(const BlindzapStatementV1& statement, const BlindzapReplayPolicy& policy, bool proof_valid) {
  if (!proof_valid || !BlindzapStatementValid(statement) || statement.verifier != policy.verifier || statement.purpose != policy.purpose || policy.now < statement.not_before || policy.now > statement.expires_at || (policy.max_lifetime && statement.expires_at - statement.not_before > policy.max_lifetime)) return BlindzapAuthorization::kPolicyRejected;
  if (policy.nonce_seen && policy.nonce_seen(statement.nonce)) return BlindzapAuthorization::kReplayRejected; return BlindzapAuthorization::kPendingReplayCheck;
}
inline BlindzapAuthorization BlindzapConsumeNonce(const BlindzapStatementV1& statement, const BlindzapReplayPolicy& policy) { return policy.consume_nonce && policy.consume_nonce(statement.nonce) ? BlindzapAuthorization::kAuthorized : BlindzapAuthorization::kReplayRejected; }
}  // namespace proofs
#endif
