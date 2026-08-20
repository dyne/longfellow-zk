#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "blindzap/envelope.h"

namespace proofs {
namespace {

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

BlindzapStatementV1 Statement() {
  BlindzapStatementV1 statement;
  statement.network = BlindzapNetwork::kSignet;
  statement.verifier = "merchant.example";
  statement.purpose = "proof-of-funds";
  statement.not_before = 100;
  statement.expires_at = 200;
  for (size_t index = 0; index < 32; ++index) {
    statement.nonce[index] = static_cast<uint8_t>(index + 1);
    statement.bip322_message_hash[index] = static_cast<uint8_t>(32 - index);
  }
  BlindzapClaimV1 first;
  first.txid[0] = 1;
  first.vout = 2;
  first.amount_sats = 42;
  first.program[0] = 9;
  BlindzapClaimV1 second;
  second.txid[0] = 2;
  second.vout = 1;
  second.amount_sats = 99;
  second.program[1] = 8;
  statement.claims = {first, second};
  return statement;
}

void TestNetworks() {
  const std::pair<const char*, BlindzapNetwork> networks[] = {
      {"mainnet", BlindzapNetwork::kMainnet},
      {"testnet", BlindzapNetwork::kTestnet3},
      {"testnet3", BlindzapNetwork::kTestnet3},
      {"testnet4", BlindzapNetwork::kTestnet4},
      {"signet", BlindzapNetwork::kSignet},
      {"regtest", BlindzapNetwork::kRegtest},
  };
  for (const auto& entry : networks) {
    BlindzapNetwork parsed = BlindzapNetwork::kMainnet;
    Require(BlindzapParseNetwork(entry.first, &parsed) && parsed == entry.second,
            "network name rejected");
    auto statement = Statement();
    statement.network = entry.second;
    std::vector<uint8_t> encoded;
    BlindzapStatementV1 decoded;
    Require(EncodeBlindzapStatement(statement, &encoded) &&
                DecodeBlindzapStatement(encoded, &decoded) &&
                decoded.network == entry.second,
            "network wire round trip failed");
  }
  BlindzapNetwork ignored = BlindzapNetwork::kMainnet;
  Require(!BlindzapParseNetwork("testnet5", &ignored),
          "unknown future network accepted");
}

void TestStatementRoundTrip() {
  const auto statement = Statement();
  std::vector<uint8_t> encoded;
  Require(EncodeBlindzapStatement(statement, &encoded), "encode statement");
  Require(encoded.size() <= kBlindzapMaxStatementBytes, "statement exceeds cap");
  BlindzapStatementV1 decoded;
  Require(DecodeBlindzapStatement(encoded, &decoded), "decode statement");
  std::vector<uint8_t> again;
  Require(EncodeBlindzapStatement(decoded, &again) && encoded == again,
          "statement is not canonical");
  const std::array<uint8_t, 32> expected_digest = {
      0xfc, 0x1f, 0x6c, 0xce, 0x6a, 0xd6, 0xe1, 0xff,
      0x35, 0xe8, 0x4b, 0xc3, 0xa1, 0x27, 0xb3, 0x91,
      0x7e, 0x09, 0xa6, 0x19, 0x64, 0x75, 0xf9, 0x17,
      0x6c, 0x08, 0xf8, 0x29, 0x33, 0x30, 0xf7, 0x5a};
  std::array<uint8_t, 32> digest{};
  Require(BlindzapStatementDigest(statement, &digest) &&
              digest == expected_digest,
          "statement digest differs from independent vector");
  for (size_t size = 0; size < encoded.size(); ++size) {
    const auto end = encoded.begin() +
                     static_cast<std::vector<uint8_t>::difference_type>(size);
    const std::vector<uint8_t> truncated(encoded.begin(), end);
    Require(!DecodeBlindzapStatement(truncated, &decoded),
            "truncated statement accepted");
  }
  auto trailing = encoded;
  trailing.push_back(0);
  Require(!DecodeBlindzapStatement(trailing, &decoded),
          "trailing statement byte accepted");

  auto snapshot = statement;
  snapshot.has_snapshot = true;
  snapshot.snapshot[0] = 7;
  snapshot.snapshot_height = 123;
  Require(EncodeBlindzapStatement(snapshot, &encoded) &&
              DecodeBlindzapStatement(encoded, &decoded) &&
              decoded.snapshot_height == 123,
          "snapshot hash/height round trip failed");
}

void TestMalformedStatementCorpus() {
  std::vector<uint8_t> output;
  auto invalid = Statement();
  invalid.nonce.fill(0);
  Require(!EncodeBlindzapStatement(invalid, &output), "zero nonce accepted");
  invalid = Statement();
  invalid.bip322_message_hash.fill(0);
  Require(!EncodeBlindzapStatement(invalid, &output), "zero message hash accepted");
  invalid = Statement();
  invalid.not_before = invalid.expires_at;
  Require(!EncodeBlindzapStatement(invalid, &output), "empty lifetime accepted");
  invalid = Statement();
  invalid.purpose = "anything-goes";
  Require(!EncodeBlindzapStatement(invalid, &output), "unknown purpose accepted");
  invalid = Statement();
  invalid.claims[0].txid.fill(0);
  Require(!EncodeBlindzapStatement(invalid, &output), "zero txid accepted");
  invalid = Statement();
  invalid.claims[0].amount_sats = 0;
  Require(!EncodeBlindzapStatement(invalid, &output), "zero amount accepted");
  invalid = Statement();
  invalid.claims[0].amount_sats = kBlindzapMaxMoneySats + 1;
  Require(!EncodeBlindzapStatement(invalid, &output), "excess amount accepted");
  invalid = Statement();
  invalid.claims[0].amount_sats = kBlindzapMaxMoneySats;
  Require(!EncodeBlindzapStatement(invalid, &output),
          "aggregate amount above maximum accepted");
  invalid = Statement();
  std::swap(invalid.claims[0], invalid.claims[1]);
  Require(!EncodeBlindzapStatement(invalid, &output), "unsorted claims accepted");
  invalid = Statement();
  invalid.claims[1] = invalid.claims[0];
  Require(!EncodeBlindzapStatement(invalid, &output), "duplicate outpoint accepted");
  invalid = Statement();
  BlindzapClaimV1 third = invalid.claims.back();
  third.txid[0] = 3;
  third.program[2] = 7;
  invalid.claims.push_back(third);
  Require(!EncodeBlindzapStatement(invalid, &output),
          "third ownership relation accepted");
  invalid = Statement();
  invalid.has_snapshot = true;
  Require(!EncodeBlindzapStatement(invalid, &output), "zero snapshot hash accepted");
  invalid = Statement();
  invalid.snapshot_height = 1;
  Require(!EncodeBlindzapStatement(invalid, &output),
          "snapshot height without snapshot accepted");
  invalid = Statement();
  invalid.has_bridge_binding = true;
  Require(!EncodeBlindzapStatement(invalid, &output),
          "incomplete bridge binding accepted");
  invalid = Statement();
  invalid.verifier = "\xc0\x80";
  Require(!EncodeBlindzapStatement(invalid, &output), "invalid UTF-8 accepted");
  invalid = Statement();
  invalid.verifier = "line\nbreak";
  Require(!EncodeBlindzapStatement(invalid, &output),
          "control character accepted in verifier ID");
  invalid = Statement();
  invalid.verifier = std::string("bad") + "\xed\xa0\x80";
  Require(!EncodeBlindzapStatement(invalid, &output),
          "UTF-8 surrogate accepted");
  invalid = Statement();
  invalid.verifier = "v\xc3\xa9rificateur";
  Require(EncodeBlindzapStatement(invalid, &output), "valid UTF-8 rejected");
}

void TestEnvelopeAndTranscript() {
  BlindzapEnvelopeV1 envelope;
  envelope.statement = Statement();
  envelope.proof.circuit_digest[0] = 4;
  envelope.proof.bytes = {1, 2, 3, 4};
  const auto seed = BlindzapTranscriptSeed(envelope.statement, envelope.proof);
  envelope.statement.nonce[0] ^= 1;
  Require(seed != BlindzapTranscriptSeed(envelope.statement, envelope.proof),
          "nonce not transcript-bound");
  envelope.statement.nonce[0] ^= 1;

  std::vector<uint8_t> wire;
  Require(EncodeBlindzapEnvelope(envelope, &wire), "encode envelope");
  BlindzapEnvelopeV1 decoded;
  Require(DecodeBlindzapEnvelope(wire, &decoded), "decode envelope");
  std::vector<uint8_t> again;
  Require(EncodeBlindzapEnvelope(decoded, &again) && wire == again,
          "envelope is not canonical");
  auto invalid_envelope = envelope;
  invalid_envelope.proof.bytes.clear();
  Require(!EncodeBlindzapEnvelope(invalid_envelope, &again),
          "empty proof encoded");
  invalid_envelope = envelope;
  invalid_envelope.proof.circuit_digest.fill(0);
  Require(!EncodeBlindzapEnvelope(invalid_envelope, &again),
          "zero circuit digest encoded");
  invalid_envelope = envelope;
  ++invalid_envelope.proof.circuit_version;
  Require(!EncodeBlindzapEnvelope(invalid_envelope, &again),
          "unsupported proof parameters encoded");
  for (size_t size = 0; size < wire.size(); ++size) {
    const auto end = wire.begin() +
                     static_cast<std::vector<uint8_t>::difference_type>(size);
    const std::vector<uint8_t> truncated(wire.begin(), end);
    Require(!DecodeBlindzapEnvelope(truncated, &decoded),
            "truncated envelope accepted");
  }

  auto unsupported = wire;
  unsupported[4] = 2;
  BlindzapDecodeError error = BlindzapDecodeError::kNone;
  Require(!DecodeBlindzapEnvelope(unsupported, &decoded, &error) &&
              error == BlindzapDecodeError::kUnsupported,
          "unsupported envelope version misclassified");

  std::vector<uint8_t> oversized = {'B', 'Z', 'E', '1', 1};
  BlindzapAppendU32(&oversized,
                    static_cast<uint32_t>(kBlindzapMaxStatementBytes + 1));
  oversized.resize(oversized.size() + kBlindzapMaxStatementBytes + 1);
  Require(!DecodeBlindzapEnvelope(oversized, &decoded),
          "oversized statement allocation accepted");

  const std::string inspection = BlindzapInspectJson(envelope);
  Require(inspection.find("\"network\":\"signet\"") != std::string::npos &&
              inspection.find("nonce") == std::string::npos,
          "inspection output is incorrect or leaks nonce material");
}

void TestReplayPolicy() {
  const auto statement = Statement();
  BlindzapReplayPolicy policy;
  policy.now = 150;
  policy.max_lifetime = 200;
  policy.verifier = statement.verifier;
  policy.purpose = statement.purpose;
  bool consumed = false;
  policy.nonce_seen = [&](const std::array<uint8_t, 32>&) { return consumed; };
  policy.consume_nonce = [&](const std::array<uint8_t, 32>&) {
    if (consumed) return false;
    consumed = true;
    return true;
  };
  Require(BlindzapCheckPolicy(statement, policy, true) ==
              BlindzapAuthorization::kPendingReplayCheck,
          "fresh nonce rejected");
  Require(BlindzapConsumeNonce(statement, policy) ==
              BlindzapAuthorization::kAuthorized,
          "fresh nonce not consumed");
  Require(BlindzapCheckPolicy(statement, policy, true) ==
              BlindzapAuthorization::kReplayRejected,
          "replay accepted");
  policy.now = statement.expires_at;
  Require(BlindzapCheckPolicy(statement, policy, true) ==
              BlindzapAuthorization::kPolicyRejected,
          "expiry boundary accepted");
}

}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::TestNetworks();
    proofs::TestStatementRoundTrip();
    proofs::TestMalformedStatementCorpus();
    proofs::TestEnvelopeAndTranscript();
    proofs::TestReplayPolicy();
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "BlindZap protocol tests passed\n";
  return 0;
}
