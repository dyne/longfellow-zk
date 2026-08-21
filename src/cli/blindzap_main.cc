// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "blindzap/bitcoin_core.h"
#include "blindzap/envelope.h"
#include "blindzap/nonce_store.h"
#include "blindzap/prover.h"
#include "blindzap/verifier.h"
#include "cli/json.hpp"
#include "util/randombytes.h"

namespace {

constexpr int kUsage = 64;
constexpr int kData = 65;
constexpr int kSoftware = 70;
constexpr int kIoError = 74;
constexpr uint64_t kDefaultLifetimeSeconds = 300;
constexpr uint64_t kMaximumLifetimeSeconds = 86400;

using Options = std::map<std::string, std::vector<std::string>>;

void SecureErase(void* pointer, size_t size) {
  volatile uint8_t* bytes = static_cast<volatile uint8_t*>(pointer);
  while (size-- != 0) *bytes++ = 0;
}

void PrintUsage(std::ostream& output) {
  output
      << "usage:\n"
      << "  blindzap challenge create --network NETWORK --verifier ID "
         "--purpose PURPOSE --message TEXT --claim "
         "TXID:VOUT:SATOSHIS:PROGRAM [--claim ...] --output REQUEST\n"
      << "  blindzap prove --request REQUEST --output PROOF\n"
      << "  blindzap verify PROOF --bitcoin-cli /ABSOLUTE/PATH --verifier ID "
         "--purpose PURPOSE --nonce-store FILE [--min-confirmations N] "
         "[--minimum-total-sats N] [--max-lifetime SECONDS]\n"
      << "  blindzap inspect FILE\n"
      << "networks: mainnet, testnet3 (alias testnet), testnet4, signet, regtest\n";
}

int Usage() {
  PrintUsage(std::cerr);
  return kUsage;
}

bool ParseOptions(int argc, char** argv, int begin,
                  const std::set<std::string>& allowed, Options* options) {
  if (options == nullptr) return false;
  options->clear();
  for (int index = begin; index < argc; index += 2) {
    const std::string name = argv[index];
    if (name.rfind("--", 0) != 0 || !allowed.count(name) || index + 1 >= argc)
      return false;
    (*options)[name].emplace_back(argv[index + 1]);
  }
  return true;
}

bool One(const Options& options, const std::string& name, std::string* value,
         bool required = true) {
  const auto found = options.find(name);
  if (found == options.end()) return !required;
  if (value == nullptr || found->second.size() != 1) return false;
  *value = found->second.front();
  return true;
}

bool ParseU64(const std::string& text, uint64_t* value) {
  if (value == nullptr || text.empty()) return false;
  uint64_t parsed = 0;
  for (char digit : text) {
    if (digit < '0' || digit > '9' ||
        parsed > (std::numeric_limits<uint64_t>::max() -
                  static_cast<uint64_t>(digit - '0')) / 10) return false;
    parsed = parsed * 10 + static_cast<uint64_t>(digit - '0');
  }
  *value = parsed;
  return true;
}

int HexNibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

template <size_t N>
bool HexArray(const std::string& hex, std::array<uint8_t, N>* output) {
  if (output == nullptr || hex.size() != N * 2) return false;
  for (size_t index = 0; index < N; ++index) {
    const int high = HexNibble(hex[index * 2]);
    const int low = HexNibble(hex[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    (*output)[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

template <size_t N>
std::string ArrayHex(const std::array<uint8_t, N>& value) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(N * 2);
  for (uint8_t byte : value) {
    output.push_back(kHex[byte >> 4]);
    output.push_back(kHex[byte & 15]);
  }
  return output;
}

bool ParseClaim(const std::string& text, proofs::BlindzapClaimV1* claim) {
  if (claim == nullptr) return false;
  std::array<std::string, 4> fields;
  size_t begin = 0;
  for (size_t index = 0; index < fields.size(); ++index) {
    const size_t separator = text.find(':', begin);
    if ((index + 1 < fields.size() && separator == std::string::npos) ||
        (index + 1 == fields.size() && separator != std::string::npos)) return false;
    fields[index] = text.substr(begin, separator - begin);
    begin = separator == std::string::npos ? text.size() : separator + 1;
  }
  uint64_t vout = 0, amount = 0;
  proofs::BlindzapClaimV1 parsed;
  if (!HexArray(fields[0], &parsed.txid) || !ParseU64(fields[1], &vout) ||
      vout > std::numeric_limits<uint32_t>::max() ||
      !ParseU64(fields[2], &amount) || amount == 0 ||
      amount > proofs::kBlindzapMaxMoneySats ||
      !HexArray(fields[3], &parsed.program)) return false;
  parsed.vout = static_cast<uint32_t>(vout);
  parsed.amount_sats = amount;
  *claim = parsed;
  return true;
}

bool ReadBounded(const std::string& path, size_t maximum,
                 std::vector<uint8_t>* output) {
  if (output == nullptr) return false;
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return false;
  output->clear();
  std::array<char, 8192> buffer{};
  while (stream) {
    stream.read(buffer.data(), buffer.size());
    const std::streamsize count = stream.gcount();
    if (count < 0 || static_cast<size_t>(count) > maximum - output->size()) {
      output->clear();
      return false;
    }
    output->insert(output->end(), buffer.data(), buffer.data() + count);
  }
  return stream.eof();
}

bool WriteAll(int descriptor, const uint8_t* bytes, size_t size) {
  while (size != 0) {
    const ssize_t written = write(descriptor, bytes, size);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return false;
    bytes += written;
    size -= static_cast<size_t>(written);
  }
  return true;
}

bool WriteNewFileAtomic(const std::string& path,
                        const std::vector<uint8_t>& bytes) {
  if (path.empty()) return false;
  std::array<uint8_t, 8> random_suffix{};
  if (randombytes(random_suffix.data(), random_suffix.size()) != 0) return false;
  const std::string temporary = path + ".tmp." + std::to_string(getpid()) + "." +
                                ArrayHex(random_suffix);
  const int descriptor =
      open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) return false;
  const bool written = WriteAll(descriptor, bytes.data(), bytes.size()) &&
                       fsync(descriptor) == 0;
  const int close_result = close(descriptor);
  if (!written || close_result != 0 || link(temporary.c_str(), path.c_str()) != 0) {
    (void)unlink(temporary.c_str());
    return false;
  }
  (void)unlink(temporary.c_str());
  const size_t separator = path.find_last_of('/');
  const std::string directory = separator == std::string::npos
                                    ? "."
                                    : separator == 0 ? "/" : path.substr(0, separator);
  const int directory_descriptor =
      open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  const bool durable = directory_descriptor >= 0 &&
                       fsync(directory_descriptor) == 0;
  if (directory_descriptor >= 0) (void)close(directory_descriptor);
  if (!durable) (void)unlink(path.c_str());
  return durable;
}

class TerminalEchoGuard {
 public:
  TerminalEchoGuard() {
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &original_) != 0) return;
    termios hidden = original_;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    active_ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0;
  }
  ~TerminalEchoGuard() {
    if (active_) (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
  }
  TerminalEchoGuard(const TerminalEchoGuard&) = delete;
  TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

 private:
  termios original_{};
  bool active_ = false;
};

bool ReadSecrets(size_t count,
                 std::vector<std::array<uint8_t, 32>>* secrets) {
  if (secrets == nullptr || count == 0 || count > proofs::kBlindzapMaxKeys)
    return false;
  secrets->clear();
  secrets->reserve(count);
  const bool terminal = isatty(STDIN_FILENO);
  if (terminal)
    std::cerr << "enter " << count << " hexadecimal secret key(s), one per line: ";
  TerminalEchoGuard echo_guard;
  for (size_t index = 0; index < count; ++index) {
    std::string line;
    if (!std::getline(std::cin, line)) return false;
    std::array<uint8_t, 32> secret{};
    const bool valid = HexArray(line, &secret);
    if (!line.empty()) SecureErase(line.data(), line.size());
    if (!valid) {
      SecureErase(secret.data(), secret.size());
      return false;
    }
    secrets->push_back(secret);
    SecureErase(secret.data(), secret.size());
  }
  if (terminal) std::cerr << '\n';
  return true;
}

void EraseSecrets(std::vector<std::array<uint8_t, 32>>* secrets) {
  if (secrets == nullptr) return;
  for (auto& secret : *secrets) SecureErase(secret.data(), secret.size());
  secrets->clear();
}

int PrintResult(const proofs::BlindzapVerification& verification) {
  nlohmann::json output = {
      {"result", proofs::BlindzapVerifyResultName(verification.result)},
      {"exit_code", proofs::BlindzapVerifyExitCode(verification.result)},
      {"total_sats", verification.total_sats},
      {"claims_checked", verification.claims.size()},
  };
  std::cout << output.dump() << '\n';
  return proofs::BlindzapVerifyExitCode(verification.result);
}

int ChallengeCreate(int argc, char** argv) {
  const std::set<std::string> allowed = {
      "--network", "--verifier", "--purpose", "--message", "--claim",
      "--output", "--expires-in"};
  Options options;
  if (!ParseOptions(argc, argv, 3, allowed, &options)) return Usage();
  std::string network_name, verifier, purpose, message, output_path,
      lifetime_text;
  if (!One(options, "--network", &network_name) ||
      !One(options, "--verifier", &verifier) ||
      !One(options, "--purpose", &purpose) ||
      !One(options, "--message", &message) ||
      !One(options, "--output", &output_path) ||
      !One(options, "--expires-in", &lifetime_text, false)) return Usage();
  uint64_t lifetime = kDefaultLifetimeSeconds;
  if (!lifetime_text.empty() && !ParseU64(lifetime_text, &lifetime)) return Usage();
  if (lifetime == 0 || lifetime > kMaximumLifetimeSeconds) return Usage();
  const auto claims = options.find("--claim");
  if (claims == options.end() || claims->second.empty() ||
      claims->second.size() > proofs::kBlindzapMaxClaims) return Usage();

  proofs::BlindzapStatementV1 statement;
  if (!proofs::BlindzapParseNetwork(network_name, &statement.network)) return Usage();
  statement.verifier = verifier;
  statement.purpose = purpose;
  for (size_t attempt = 0; proofs::BlindzapAllZero(statement.nonce); ++attempt) {
    if (attempt == 4 ||
        randombytes(statement.nonce.data(), statement.nonce.size()) != 0)
      return kIoError;
  }
  statement.bip322_message_hash = proofs::BlindzapBip322MessageHash(
      reinterpret_cast<const uint8_t*>(message.data()), message.size());
  const auto now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  if (now < 0 || static_cast<uint64_t>(now) >
                     std::numeric_limits<uint64_t>::max() - lifetime) return kIoError;
  statement.not_before = static_cast<uint64_t>(now);
  statement.expires_at = statement.not_before + lifetime;
  for (const auto& encoded_claim : claims->second) {
    proofs::BlindzapClaimV1 claim;
    if (!ParseClaim(encoded_claim, &claim)) return Usage();
    statement.claims.push_back(claim);
  }
  std::sort(statement.claims.begin(), statement.claims.end());
  std::vector<uint8_t> request;
  if (!proofs::EncodeBlindzapStatement(statement, &request)) {
    std::cerr << "challenge violates the BlindZap v1 statement contract\n";
    return kData;
  }
  if (!WriteNewFileAtomic(output_path, request)) {
    std::cerr << "could not create request file (the destination must not exist)\n";
    return kIoError;
  }
  nlohmann::json result = {{"result", "challenge_created"},
                           {"request", output_path},
                           {"network", proofs::BlindzapNetworkName(statement.network)},
                           {"expires_at", statement.expires_at},
                           {"claims", statement.claims.size()}};
  std::cout << result.dump() << '\n';
  return 0;
}

int Prove(int argc, char** argv) {
  Options options;
  if (!ParseOptions(argc, argv, 2, {"--request", "--output"}, &options))
    return Usage();
  std::string request_path, output_path;
  if (!One(options, "--request", &request_path) ||
      !One(options, "--output", &output_path)) return Usage();
  std::vector<uint8_t> request;
  proofs::BlindzapStatementV1 statement;
  proofs::BlindzapDecodeError error = proofs::BlindzapDecodeError::kMalformed;
  if (!ReadBounded(request_path, proofs::kBlindzapMaxStatementBytes, &request) ||
      !proofs::DecodeBlindzapStatement(request, &statement, &error)) {
    std::cerr << "invalid or unsupported BlindZap request\n";
    return kData;
  }
  const auto now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  if (now < 0 || static_cast<uint64_t>(now) < statement.not_before ||
      static_cast<uint64_t>(now) >= statement.expires_at) {
    std::cerr << "BlindZap request is not currently valid\n";
    return kData;
  }
  std::vector<std::array<uint8_t, 20>> programs;
  if (!proofs::BlindzapDistinctPrograms(statement, &programs)) return kData;
  std::vector<std::array<uint8_t, 32>> secrets;
  if (!ReadSecrets(programs.size(), &secrets)) {
    EraseSecrets(&secrets);
    std::cerr << "expected one 32-byte hexadecimal secret per distinct program\n";
    return kData;
  }
  proofs::BlindzapEnvelopeV1 envelope;
  bool proved = false;
  if (programs.size() == 1)
    proved = proofs::BlindzapProveKeys<1>(secrets, statement, &envelope);
  else if (programs.size() == 2)
    proved = proofs::BlindzapProveKeys<2>(secrets, statement, &envelope);
  EraseSecrets(&secrets);
  std::vector<uint8_t> wire;
  if (!proved || !proofs::EncodeBlindzapEnvelope(envelope, &wire)) {
    std::cerr << "proof generation failed\n";
    return 2;
  }
  if (!WriteNewFileAtomic(output_path, wire)) {
    std::cerr << "could not create proof file (the destination must not exist)\n";
    return kIoError;
  }
  std::cout << nlohmann::json({{"result", "proof_created"},
                               {"proof", output_path},
                               {"proof_bytes", envelope.proof.bytes.size()}}).dump()
            << '\n';
  return 0;
}

int Verify(int argc, char** argv) {
  if (argc < 3) return Usage();
  const std::string proof_path = argv[2];
  Options options;
  if (!ParseOptions(argc, argv, 3,
                    {"--bitcoin-cli", "--verifier", "--purpose",
                     "--nonce-store", "--min-confirmations",
                     "--minimum-total-sats", "--max-lifetime"},
                    &options)) return Usage();
  std::string executable, verifier, purpose, nonce_store, confirmations_text,
      minimum_text, lifetime_text;
  if (!One(options, "--bitcoin-cli", &executable) ||
      !One(options, "--verifier", &verifier) ||
      !One(options, "--purpose", &purpose) ||
      !One(options, "--nonce-store", &nonce_store) ||
      !One(options, "--min-confirmations", &confirmations_text, false) ||
      !One(options, "--minimum-total-sats", &minimum_text, false) ||
      !One(options, "--max-lifetime", &lifetime_text, false)) return Usage();
  if (executable.empty() || executable[0] != '/' ||
      access(executable.c_str(), X_OK) != 0) return Usage();
  uint64_t min_confirmations = 1, minimum_total = 0,
           max_lifetime = kMaximumLifetimeSeconds;
  if ((!confirmations_text.empty() &&
       !ParseU64(confirmations_text, &min_confirmations)) ||
      (!minimum_text.empty() && !ParseU64(minimum_text, &minimum_total)) ||
      (!lifetime_text.empty() && !ParseU64(lifetime_text, &max_lifetime)) ||
      minimum_total > proofs::kBlindzapMaxMoneySats || max_lifetime == 0 ||
      max_lifetime > kMaximumLifetimeSeconds) return Usage();

  std::vector<uint8_t> wire;
  if (!ReadBounded(proof_path, proofs::kBlindzapMaxEnvelopeBytes, &wire))
    return PrintResult({proofs::BlindzapVerifyResult::kMalformedStatement, {}});
  proofs::BlindzapEnvelopeV1 envelope;
  proofs::BlindzapDecodeError error = proofs::BlindzapDecodeError::kMalformed;
  if (!proofs::DecodeBlindzapEnvelope(wire, &envelope, &error))
    return PrintResult({error == proofs::BlindzapDecodeError::kUnsupported
                            ? proofs::BlindzapVerifyResult::kUnsupported
                            : proofs::BlindzapVerifyResult::kMalformedStatement,
                        {}});
  proofs::BitcoinCoreCurrentTipProvider provider(executable,
                                                  envelope.statement.network);
  proofs::BlindzapVerifierConfig config;
  config.provider = &provider;
  config.supports = [](const proofs::BlindzapEnvelopeV1& candidate) {
    return proofs::BlindzapProofSupported(candidate);
  };
  config.verify_proof = [](const proofs::BlindzapEnvelopeV1& candidate) {
    return proofs::BlindzapVerifyProof(candidate);
  };
  const auto now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  if (now < 0) {
    std::cerr << "system clock is outside the supported range\n";
    return kIoError;
  }
  config.policy.now = static_cast<uint64_t>(now);
  config.policy.max_lifetime = max_lifetime;
  config.policy.verifier = verifier;
  config.policy.purpose = purpose;
  config.policy.consume_nonce = [&nonce_store](const std::array<uint8_t, 32>& nonce) {
    return proofs::BlindzapConsumeNonceFile(nonce_store, nonce);
  };
  config.min_confirmations = min_confirmations;
  config.minimum_total_sats = minimum_total;
  return PrintResult(proofs::VerifyBlindzap(wire, config));
}

int Inspect(const std::string& path) {
  std::vector<uint8_t> bytes;
  if (!ReadBounded(path, proofs::kBlindzapMaxEnvelopeBytes, &bytes)) return kData;
  proofs::BlindzapEnvelopeV1 envelope;
  if (proofs::DecodeBlindzapEnvelope(bytes, &envelope)) {
    std::cout << proofs::BlindzapInspectJson(envelope) << '\n';
    return 0;
  }
  proofs::BlindzapStatementV1 statement;
  if (!proofs::DecodeBlindzapStatement(bytes, &statement)) return kData;
  nlohmann::json output = {{"format", "blindzap-request-v1"},
                           {"network", proofs::BlindzapNetworkName(statement.network)},
                           {"verifier", statement.verifier},
                           {"purpose", statement.purpose},
                           {"not_before", statement.not_before},
                           {"expires_at", statement.expires_at},
                           {"claims", statement.claims.size()},
                           {"has_snapshot", statement.has_snapshot}};
  std::cout << output.dump() << '\n';
  return 0;
}

}  // namespace

int BlindzapMain(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--help") {
    std::cout << "BlindZap private proof-of-control CLI\n";
    PrintUsage(std::cout);
    return 0;
  }
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--secret" || argument.rfind("--secret=", 0) == 0) {
      std::cerr << "secret material is accepted only from protected stdin\n";
      return kUsage;
    }
  }
  if (argc >= 3 && std::string(argv[1]) == "challenge" &&
      std::string(argv[2]) == "create") return ChallengeCreate(argc, argv);
  if (argc >= 2 && std::string(argv[1]) == "prove") return Prove(argc, argv);
  if (argc >= 3 && std::string(argv[1]) == "verify") return Verify(argc, argv);
  if (argc == 3 && std::string(argv[1]) == "inspect") return Inspect(argv[2]);
  return Usage();
}

int main(int argc, char** argv) {
  try {
    return BlindzapMain(argc, argv);
  } catch (const std::exception& exception) {
    std::cerr << "fatal BlindZap error: " << exception.what() << '\n';
  } catch (...) {
    std::cerr << "fatal BlindZap error\n";
  }
  return kSoftware;
}
