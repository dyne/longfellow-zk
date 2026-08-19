#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "blindzap/envelope.h"

namespace proofs {
namespace {
void Require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
BlindzapStatementV1 Statement() {
  BlindzapStatementV1 s; s.network = BlindzapNetwork::kRegtest; s.verifier = "merchant.example"; s.purpose = "proof-of-funds"; s.not_before = 100; s.expires_at = 200;
  for (size_t i = 0; i < 32; ++i) { s.nonce[i] = static_cast<uint8_t>(i); s.bip322_message_hash[i] = static_cast<uint8_t>(31 - i); }
  s.has_snapshot = true; s.snapshot[0] = 7; BlindzapClaimV1 a, b; a.txid[0] = 1; a.vout = 2; a.amount_sats = 42; a.program[0] = 9; b.txid[0] = 2; b.vout = 1; b.amount_sats = 99; b.program[1] = 8; s.claims = {a, b}; return s;
}
void TestStatement() {
  auto s = Statement(); std::vector<uint8_t> bytes; Require(EncodeBlindzapStatement(s, &bytes), "encode statement"); BlindzapStatementV1 decoded; Require(DecodeBlindzapStatement(bytes, &decoded), "decode statement"); std::vector<uint8_t> again; Require(EncodeBlindzapStatement(decoded, &again) && bytes == again, "noncanonical statement round trip");
  for (size_t i = 0; i < bytes.size(); ++i) { std::vector<uint8_t> cut(bytes.begin(), bytes.begin() + i); Require(!DecodeBlindzapStatement(cut, &decoded), "accepted truncated statement"); }
  auto trailing = bytes; trailing.push_back(0); Require(!DecodeBlindzapStatement(trailing, &decoded), "accepted trailing statement byte");
  auto unsorted = s; std::swap(unsorted.claims[0], unsorted.claims[1]); Require(!EncodeBlindzapStatement(unsorted, &again), "accepted unsorted claims");
  auto duplicate = s; duplicate.claims[1] = duplicate.claims[0]; Require(!EncodeBlindzapStatement(duplicate, &again), "accepted duplicate claims");
  auto bad_text = s; bad_text.verifier = "\xc0\x80"; Require(!EncodeBlindzapStatement(bad_text, &again), "accepted invalid UTF-8");
}
void TestHashesAndEnvelope() {
  const uint8_t message[] = {'h','e','l','l','o'}; const auto bip = BlindzapBip322MessageHash(message, sizeof(message)); const auto same = BlindzapBip322MessageHash(message, sizeof(message)); Require(bip == same, "unstable BIP-322 hash"); auto altered = Statement(); altered.bip322_message_hash = bip; std::array<uint8_t, 32> digest, other; Require(BlindzapStatementDigest(altered, &digest), "statement digest"); altered.purpose = "other"; Require(BlindzapStatementDigest(altered, &other) && digest != other, "purpose not bound");
  BlindzapEnvelopeV1 e; e.statement = Statement(); e.proof.circuit_digest[0] = 4; e.proof.bytes = {1,2,3,4}; const auto seed = BlindzapTranscriptSeed(e.statement, e.proof); Require(seed != bip, "BIP-322 hash reused as BlindZap transcript"); e.statement.nonce[0] ^= 1; Require(seed != BlindzapTranscriptSeed(e.statement, e.proof), "nonce not transcript bound"); e.statement.nonce[0] ^= 1;
  std::vector<uint8_t> bytes; Require(EncodeBlindzapEnvelope(e, &bytes), "encode envelope"); BlindzapEnvelopeV1 parsed; Require(DecodeBlindzapEnvelope(bytes, &parsed), "decode envelope"); std::vector<uint8_t> again; Require(EncodeBlindzapEnvelope(parsed, &again) && bytes == again, "noncanonical envelope round trip");
  const std::string inspection = BlindzapInspectJson(parsed); Require(inspection.find("blindzap-pof-v1") != std::string::npos && inspection.find("proof_bytes") != std::string::npos && inspection.find("nonce") == std::string::npos, "inspection leaks private or nonce material");
  for (size_t i = 0; i < bytes.size(); ++i) { std::vector<uint8_t> cut(bytes.begin(), bytes.begin() + i); Require(!DecodeBlindzapEnvelope(cut, &parsed), "accepted truncated envelope"); }
  auto trailing = bytes; trailing.push_back(0); Require(!DecodeBlindzapEnvelope(trailing, &parsed), "accepted trailing envelope byte"); auto huge = bytes; huge[5] = 0xff; huge[6] = 0xff; huge[7] = 0xff; huge[8] = 0xff; Require(!DecodeBlindzapEnvelope(huge, &parsed), "accepted oversized statement");
  auto wrong_parameters = bytes; const size_t parameter_version = 5 + 4 + bytes[8] + (size_t(bytes[7]) << 8) + (size_t(bytes[6]) << 16) + (size_t(bytes[5]) << 24) + 32; wrong_parameters[parameter_version + 3] = 2; Require(!DecodeBlindzapEnvelope(wrong_parameters, &parsed), "accepted unknown proof parameters");
  e.proof.bytes.assign(48 * 1024 * 1024, 0xa5); Require(EncodeBlindzapEnvelope(e, &bytes), "rejected current-proof-scale envelope"); Require(DecodeBlindzapEnvelope(bytes, &parsed) && parsed.proof.bytes == e.proof.bytes, "failed current-proof-scale envelope round trip");
  e.proof.bytes.assign(kBlindzapMaxProofBytes + 1, 0); Require(!EncodeBlindzapEnvelope(e, &bytes), "accepted proof over allocation limit");
}
void TestMultiClaimAndBridgeBinding() {
  auto s=Statement(); std::vector<std::array<uint8_t,20>> programs; Require(BlindzapDistinctPrograms(s,&programs) && programs.size()==2,"distinct program grouping");
  s.claims.push_back(s.claims[0]); Require(!BlindzapStatementValid(s),"duplicate outpoint accepted"); s=Statement(); s.claims[1].program=s.claims[0].program; Require(BlindzapDistinctPrograms(s,&programs) && programs.size()==1,"shared program grouping");
  s=Statement(); s.has_bridge_binding=true; s.bridge.destination_network=BlindzapNetwork::kTestnet; s.bridge.destination_commitment[0]=4; s.bridge.asset_id="asset"; s.bridge.lock_id[0]=5; std::vector<uint8_t> wire; Require(EncodeBlindzapStatement(s,&wire),"bridge encode"); BlindzapStatementV1 decoded; Require(DecodeBlindzapStatement(wire,&decoded) && decoded.bridge.asset_id=="asset","bridge round trip"); std::array<uint8_t,32> one,two; Require(BlindzapStatementDigest(s,&one),"bridge digest"); s.bridge.lock_id[0]^=1; Require(BlindzapStatementDigest(s,&two) && one!=two,"bridge lock not transcript bound");
}
void TestReplayPolicy() {
  auto s = Statement(); BlindzapReplayPolicy policy; policy.now = 150; policy.max_lifetime = 200; policy.verifier = s.verifier; policy.purpose = s.purpose; bool consumed = false; policy.nonce_seen = [&](const std::array<uint8_t,32>&) { return consumed; }; policy.consume_nonce = [&](const std::array<uint8_t,32>&) { if (consumed) return false; consumed = true; return true; };
  Require(BlindzapCheckPolicy(s, policy, true) == BlindzapAuthorization::kPendingReplayCheck, "fresh nonce not pending"); Require(BlindzapConsumeNonce(s, policy) == BlindzapAuthorization::kAuthorized, "fresh nonce not consumed"); Require(BlindzapCheckPolicy(s, policy, true) == BlindzapAuthorization::kReplayRejected, "replay accepted"); consumed = false; Require(BlindzapCheckPolicy(s, policy, false) == BlindzapAuthorization::kPolicyRejected && !consumed, "invalid proof consumed nonce"); s.expires_at = 149; Require(BlindzapCheckPolicy(s, policy, true) == BlindzapAuthorization::kPolicyRejected, "expired statement accepted");
}
}  // namespace
}  // namespace proofs
int main() { try { proofs::TestStatement(); proofs::TestHashesAndEnvelope(); proofs::TestMultiClaimAndBridgeBinding(); proofs::TestReplayPolicy(); } catch (const std::exception& e) { std::cerr << "not ok - " << e.what() << '\n'; return 1; } std::cout << "BlindZap protocol tests passed\n"; }
