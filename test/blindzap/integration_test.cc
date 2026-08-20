#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "blindzap/bitcoin_core.h"
#include "blindzap/nonce_store.h"
#include "blindzap/verifier.h"

namespace proofs {
namespace {

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

BlindzapEnvelopeV1 Envelope() {
  BlindzapEnvelopeV1 envelope;
  auto& statement = envelope.statement;
  statement.network = BlindzapNetwork::kRegtest;
  statement.verifier = "verifier";
  statement.purpose = "proof-of-funds";
  statement.not_before = 1;
  statement.expires_at = 9;
  statement.nonce[0] = 1;
  statement.bip322_message_hash[0] = 2;
  BlindzapClaimV1 claim;
  claim.txid[0] = 3;
  claim.amount_sats = 7;
  claim.program[0] = 4;
  statement.claims = {claim};
  envelope.proof.circuit_digest[0] = 1;
  envelope.proof.bytes = {1};
  return envelope;
}

class FakeProvider final : public BlindzapChainProvider {
 public:
  BlindzapProviderKind kind() const override {
    return historical ? BlindzapProviderKind::kHistoricalSnapshot
                      : BlindzapProviderKind::kCurrentTip;
  }
  BlindzapChainEvidence Lookup(const BlindzapChainRequest& request) override {
    ++calls;
    last_request = request;
    auto result = evidence;
    if (advance_block) result.block[0] = static_cast<uint8_t>(result.block[0] + calls);
    return result;
  }
  bool historical = false;
  int calls = 0;
  bool advance_block = false;
  BlindzapChainRequest last_request{};
  BlindzapChainEvidence evidence;
};

BlindzapVerifierConfig Config(FakeProvider* provider) {
  BlindzapVerifierConfig config;
  config.policy.now = 2;
  config.policy.verifier = "verifier";
  config.policy.purpose = "proof-of-funds";
  config.policy.consume_nonce = [](const std::array<uint8_t, 32>&) {
    return true;
  };
  config.verify_proof = [](const BlindzapEnvelopeV1&) { return true; };
  config.provider = provider;
  return config;
}

void SetMatchingEvidence(const BlindzapEnvelopeV1& envelope,
                         FakeProvider* provider) {
  provider->evidence.status = BlindzapChainStatus::kUnspent;
  provider->evidence.network = envelope.statement.network;
  provider->evidence.amount_sats = envelope.statement.claims[0].amount_sats;
  provider->evidence.confirmations = 2;
  provider->evidence.block[0] = 1;
  provider->evidence.height = 100;
  provider->evidence.script_pub_key = {0, 20};
  provider->evidence.script_pub_key.insert(
      provider->evidence.script_pub_key.end(),
      envelope.statement.claims[0].program.begin(),
      envelope.statement.claims[0].program.end());
}

void TestVerifierStates() {
  auto envelope = Envelope();
  std::vector<uint8_t> wire;
  Require(EncodeBlindzapEnvelope(envelope, &wire), "encode envelope");
  FakeProvider provider;
  SetMatchingEvidence(envelope, &provider);
  Require(VerifyBlindzap(wire, Config(&provider)).result ==
              BlindzapVerifyResult::kValidCurrent,
          "current proof rejected");

  envelope.statement.has_snapshot = true;
  envelope.statement.snapshot[0] = 9;
  envelope.statement.snapshot_height = 123;
  provider.historical = true;
  provider.evidence.block = envelope.statement.snapshot;
  provider.evidence.height = envelope.statement.snapshot_height;
  Require(EncodeBlindzapEnvelope(envelope, &wire), "encode snapshot envelope");
  Require(VerifyBlindzap(wire, Config(&provider)).result ==
              BlindzapVerifyResult::kValidHistorical &&
              provider.last_request.snapshot_height == 123,
          "historical proof rejected or height not forwarded");
  provider.evidence.height = 124;
  Require(VerifyBlindzap(wire, Config(&provider)).result ==
              BlindzapVerifyResult::kStateInconclusive,
          "historical provider substituted a different snapshot");
  provider.evidence.height = envelope.statement.snapshot_height;
  provider.historical = false;
  Require(VerifyBlindzap(wire, Config(&provider)).result ==
              BlindzapVerifyResult::kStateInconclusive,
          "current provider accepted historical request");

  envelope.statement.has_snapshot = false;
  envelope.statement.snapshot.fill(0);
  envelope.statement.snapshot_height = 0;
  Require(EncodeBlindzapEnvelope(envelope, &wire), "encode current envelope");
  provider.evidence.amount_sats = 8;
  Require(VerifyBlindzap(wire, Config(&provider)).result ==
              BlindzapVerifyResult::kStateInconclusive,
          "amount substitution accepted");
  SetMatchingEvidence(envelope, &provider);
  provider.evidence.status = BlindzapChainStatus::kSpent;
  Require(VerifyBlindzap(wire, Config(&provider)).result ==
              BlindzapVerifyResult::kSpentAtSnapshot,
          "spent output accepted");
  SetMatchingEvidence(envelope, &provider);
  auto config = Config(&provider);
  config.min_confirmations = 3;
  Require(VerifyBlindzap(wire, config).result ==
              BlindzapVerifyResult::kStaleSnapshot,
          "confirmation policy bypassed");
  config = Config(&provider);
  config.verify_proof = [](const BlindzapEnvelopeV1&) { return false; };
  const int calls_before = provider.calls;
  Require(VerifyBlindzap(wire, config).result ==
              BlindzapVerifyResult::kInvalidProof &&
              provider.calls == calls_before,
          "invalid proof reached chain provider");
  config = Config(&provider);
  config.supports = [](const BlindzapEnvelopeV1&) { return false; };
  Require(VerifyBlindzap(wire, config).result ==
              BlindzapVerifyResult::kUnsupported,
          "unknown circuit identity misclassified");
  auto multiple = envelope;
  auto second_claim = multiple.statement.claims[0];
  second_claim.txid[0] = 4;
  multiple.statement.claims.push_back(second_claim);
  Require(EncodeBlindzapEnvelope(multiple, &wire), "encode multi-claim envelope");
  SetMatchingEvidence(multiple, &provider);
  provider.calls = 0;
  provider.advance_block = true;
  Require(VerifyBlindzap(wire, Config(&provider)).result ==
              BlindzapVerifyResult::kStateInconclusive,
          "multi-claim verification mixed chain tips");
  provider.advance_block = false;
  int proof_calls = 0;
  config = Config(&provider);
  config.policy.now = envelope.statement.expires_at;
  config.verify_proof = [&](const BlindzapEnvelopeV1&) {
    ++proof_calls;
    return true;
  };
  Require(VerifyBlindzap(wire, config).result ==
              BlindzapVerifyResult::kInvalidProof &&
              proof_calls == 0,
          "expired request reached expensive proof verification");
}

std::string TipJson(const std::string& chain, char block_digit = 'a',
                    uint64_t height = 100) {
  return "{\"chain\":\"" + chain + "\",\"blocks\":" +
         std::to_string(height) + ",\"bestblockhash\":\"" +
         std::string(64, block_digit) + "\"}";
}

std::string TxoutJson(const std::string& amount = "0.00000007",
                      char block_digit = 'a') {
  return "{\"bestblock\":\"" + std::string(64, block_digit) +
         "\",\"confirmations\":2,\"value\":" + amount +
         ",\"scriptPubKey\":{\"hex\":"
         "\"00140400000000000000000000000000000000000000\"}}";
}

void TestBitcoinAmounts() {
  uint64_t sats = 0;
  Require(blindzap_internal::BitcoinAmountToSats("0.00000001", &sats) &&
              sats == 1,
          "one satoshi parse failed");
  Require(blindzap_internal::BitcoinAmountToSats("21000000.00000000", &sats) &&
              sats == kBlindzapMaxMoneySats,
          "maximum supply parse failed");
  Require(!blindzap_internal::BitcoinAmountToSats("0.000000001", &sats),
          "sub-satoshi amount accepted");
  Require(!blindzap_internal::BitcoinAmountToSats("21000000.00000001", &sats),
          "amount above maximum accepted");
  Require(!blindzap_internal::BitcoinAmountToSats("1e-8", &sats),
          "noncanonical exponent accepted");
  std::string token;
  Require(!blindzap_internal::TopLevelNumberToken(
              "{\"value\":1,\"value\":2}", "value", &token),
          "duplicate top-level amount accepted");
}

void TestCoreNetworks() {
  struct NetworkCase { BlindzapNetwork network; const char* chain; const char* flag; };
  const NetworkCase networks[] = {
      {BlindzapNetwork::kMainnet, "main", ""},
      {BlindzapNetwork::kTestnet3, "test", "-testnet"},
      {BlindzapNetwork::kTestnet4, "testnet4", "-testnet4"},
      {BlindzapNetwork::kSignet, "signet", "-signet"},
      {BlindzapNetwork::kRegtest, "regtest", "-regtest"},
  };
  for (const auto& network : networks) {
    int calls = 0;
    BitcoinCoreCurrentTipProvider provider(
        "/usr/bin/bitcoin-cli", network.network,
        [&](const std::vector<std::string>& arguments) {
          ++calls;
          Require((network.flag[0] == '\0' && arguments.size() >= 2) ||
                      (arguments.size() >= 3 && arguments[1] == network.flag),
                  "Bitcoin Core network selector missing");
          if (arguments.back() == "getblockchaininfo")
            return BlindzapProcessResult{0, TipJson(network.chain), ""};
          return BlindzapProcessResult{0, TxoutJson(), ""};
        });
    BlindzapChainRequest request;
    request.network = network.network;
    request.txid[0] = 3;
    const auto evidence = provider.Lookup(request);
    Require(evidence.status == BlindzapChainStatus::kUnspent &&
                evidence.amount_sats == 7 && evidence.confirmations == 2 &&
                evidence.height == 100 && calls == 3,
            "realistic gettxout response rejected");
  }
}

void TestCoreFailures() {
  BlindzapChainRequest request;
  request.network = BlindzapNetwork::kSignet;
  request.txid[0] = 3;
  BitcoinCoreCurrentTipProvider wrong_network(
      "/usr/bin/bitcoin-cli", BlindzapNetwork::kSignet,
      [](const std::vector<std::string>&) {
        return BlindzapProcessResult{0, TipJson("main"), ""};
      });
  Require(wrong_network.Lookup(request).status == BlindzapChainStatus::kWrongNetwork,
          "wrong Bitcoin Core network accepted");

  BitcoinCoreCurrentTipProvider missing(
      "/usr/bin/bitcoin-cli", BlindzapNetwork::kSignet,
      [](const std::vector<std::string>& arguments) {
        if (arguments.back() == "getblockchaininfo")
          return BlindzapProcessResult{0, TipJson("signet"), ""};
        return BlindzapProcessResult{0, "null\n", ""};
      });
  Require(missing.Lookup(request).status == BlindzapChainStatus::kInconclusive,
          "missing outpoint incorrectly asserted spent");

  int tip_calls = 0;
  BitcoinCoreCurrentTipProvider reorg(
      "/usr/bin/bitcoin-cli", BlindzapNetwork::kSignet,
      [&](const std::vector<std::string>& arguments) {
        if (arguments.back() == "getblockchaininfo") {
          ++tip_calls;
          return BlindzapProcessResult{
              0, TipJson("signet", tip_calls == 1 ? 'a' : 'b'), ""};
        }
        return BlindzapProcessResult{0, TxoutJson(), ""};
      });
  Require(reorg.Lookup(request).status == BlindzapChainStatus::kInconclusive,
          "tip race accepted");
}

void TestProcessRunner() {
  const auto result = BlindzapRunArgv({"/bin/echo", "safe argument; no shell"});
  Require(result.exit_code == 0 &&
              result.stdout_text == "safe argument; no shell\n" &&
              result.stderr_text.empty(),
          "argv process runner failed");
  Require(BlindzapRunArgv({"echo", "relative"}).exit_code == -1,
          "relative executable accepted");
  Require(BlindzapRunArgv({"/bin/false"}).exit_code != 0,
          "child failure reported as success");
  const auto excessive = BlindzapRunArgv({"/usr/bin/yes", "bounded"});
  Require(excessive.output_limit_exceeded && excessive.exit_code == -1 &&
              excessive.stdout_text.size() == kBlindzapMaxRpcOutputBytes,
          "RPC output ceiling not enforced");
}

void TestNonceStore() {
  char path[] = "/tmp/blindzap-nonce-test.XXXXXX";
  const int descriptor = mkstemp(path);
  Require(descriptor >= 0 && fchmod(descriptor, 0600) == 0 &&
              close(descriptor) == 0,
          "nonce store fixture failed");
  std::array<uint8_t, 32> nonce{};
  nonce[0] = 1;
  Require(BlindzapConsumeNonceFile(path, nonce), "fresh nonce not stored");
  Require(!BlindzapConsumeNonceFile(path, nonce), "stored nonce replay accepted");
  std::array<uint8_t, 32> another{};
  another[0] = 2;
  Require(chmod(path, 0644) == 0 &&
              !BlindzapConsumeNonceFile(path, another),
          "insecure nonce-store permissions accepted");
  Require(unlink(path) == 0, "nonce store fixture cleanup failed");
}

}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::TestVerifierStates();
    proofs::TestBitcoinAmounts();
    proofs::TestCoreNetworks();
    proofs::TestCoreFailures();
    proofs::TestProcessRunner();
    proofs::TestNonceStore();
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "BlindZap integration tests passed\n";
  return 0;
}
