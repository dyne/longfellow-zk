// Copyright 2026 Google LLC.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_BITCOIN_CORE_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_BITCOIN_CORE_H_

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <functional>
#include <initializer_list>
#include <poll.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "blindzap/chain_state.h"
#include "cli/json.hpp"

namespace proofs {

constexpr size_t kBlindzapMaxRpcOutputBytes = size_t{1024} * 1024;
constexpr std::chrono::seconds kBlindzapRpcTimeout{30};

struct BlindzapProcessResult {
  int exit_code = -1;
  std::string stdout_text;
  std::string stderr_text;
  bool timed_out = false;
  bool output_limit_exceeded = false;
};

namespace blindzap_internal {

class FileDescriptor {
 public:
  FileDescriptor() = default;
  explicit FileDescriptor(int descriptor) : descriptor_(descriptor) {}
  ~FileDescriptor() { reset(); }
  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;
  FileDescriptor(FileDescriptor&& other) noexcept
      : descriptor_(std::exchange(other.descriptor_, -1)) {}
  FileDescriptor& operator=(FileDescriptor&& other) noexcept {
    if (this != &other) reset(std::exchange(other.descriptor_, -1));
    return *this;
  }
  int get() const { return descriptor_; }
  explicit operator bool() const { return descriptor_ >= 0; }
  int release() { return std::exchange(descriptor_, -1); }
  void reset(int descriptor = -1) {
    if (descriptor_ >= 0) {
      while (close(descriptor_) < 0 && errno == EINTR) {}
    }
    descriptor_ = descriptor;
  }

 private:
  int descriptor_ = -1;
};

inline bool MakePipe(FileDescriptor* read_end, FileDescriptor* write_end) {
  if (read_end == nullptr || write_end == nullptr) return false;
  int descriptors[2] = {-1, -1};
  if (pipe(descriptors) != 0) return false;
  read_end->reset(descriptors[0]);
  write_end->reset(descriptors[1]);
  for (int descriptor : descriptors) {
    const int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 || fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) < 0) return false;
  }
  return true;
}

inline bool SetNonBlocking(int descriptor) {
  const int flags = fcntl(descriptor, F_GETFL);
  return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

inline void KillProcessGroup(pid_t child) {
  // The parent and child both attempt setpgid. The direct kill is a fallback
  // for the narrow race where process-group creation was not possible.
  (void)kill(-child, SIGKILL);
  (void)kill(child, SIGKILL);
}

inline bool AppendAvailable(FileDescriptor* descriptor, std::string* output,
                            bool* limit_exceeded) {
  if (descriptor == nullptr || output == nullptr || limit_exceeded == nullptr)
    return false;
  std::array<char, 4096> buffer{};
  while (*descriptor) {
    const ssize_t count = read(descriptor->get(), buffer.data(), buffer.size());
    if (count > 0) {
      const size_t available = kBlindzapMaxRpcOutputBytes -
                               std::min(output->size(), kBlindzapMaxRpcOutputBytes);
      if (static_cast<size_t>(count) > available) {
        output->append(buffer.data(), available);
        *limit_exceeded = true;
        return false;
      }
      output->append(buffer.data(), static_cast<size_t>(count));
      continue;
    }
    if (count == 0) {
      descriptor->reset();
      return true;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
    descriptor->reset();
    return false;
  }
  return true;
}

inline bool IsLowerHex(const std::string& value, size_t expected_size) {
  if (value.size() != expected_size) return false;
  for (char byte : value) {
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f')))
      return false;
  }
  return true;
}

inline int HexNibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

inline bool DecodeHex(const std::string& value, std::vector<uint8_t>* output) {
  if (output == nullptr || value.size() % 2 != 0 ||
      !IsLowerHex(value, value.size())) return false;
  output->clear();
  output->reserve(value.size() / 2);
  for (size_t index = 0; index < value.size(); index += 2) {
    const int high = HexNibble(value[index]);
    const int low = HexNibble(value[index + 1]);
    output->push_back(static_cast<uint8_t>((high << 4) | low));
  }
  return true;
}

inline bool JsonUnsigned(const nlohmann::json& value, uint64_t* output) {
  if (output == nullptr) return false;
  if (value.is_number_unsigned()) {
    *output = value.get<uint64_t>();
    return true;
  }
  if (value.is_number_integer()) {
    const int64_t signed_value = value.get<int64_t>();
    if (signed_value < 0) return false;
    *output = static_cast<uint64_t>(signed_value);
    return true;
  }
  return false;
}

// Bitcoin Core emits the top-level `value` field as a JSON decimal in BTC.
// Keep its original token so no IEEE-754 conversion can move the amount by a
// satoshi. The full response is independently parsed as JSON before this runs.
inline bool TopLevelNumberToken(const std::string& json, const std::string& key,
                                std::string* token) {
  if (token == nullptr) return false;
  size_t depth = 0;
  bool found = false;
  for (size_t index = 0; index < json.size();) {
    const char current = json[index];
    if (current == '{' || current == '[') {
      ++depth;
      ++index;
      continue;
    }
    if (current == '}' || current == ']') {
      if (depth == 0) return false;
      --depth;
      ++index;
      continue;
    }
    if (current != '"') {
      ++index;
      continue;
    }
    const size_t begin = ++index;
    bool escaped = false;
    while (index < json.size()) {
      if (!escaped && json[index] == '"') break;
      if (!escaped && json[index] == '\\') {
        escaped = true;
      } else {
        escaped = false;
      }
      ++index;
    }
    if (index == json.size()) return false;
    const std::string candidate = json.substr(begin, index - begin);
    ++index;
    if (depth != 1 || candidate != key) continue;
    if (found) return false;
    while (index < json.size() &&
           (json[index] == ' ' || json[index] == '\t' || json[index] == '\r' ||
            json[index] == '\n')) ++index;
    if (index == json.size() || json[index] != ':') return false;
    ++index;
    while (index < json.size() &&
           (json[index] == ' ' || json[index] == '\t' || json[index] == '\r' ||
            json[index] == '\n')) ++index;
    const size_t number_begin = index;
    while (index < json.size() && json[index] != ',' && json[index] != '}' &&
           json[index] != ' ' && json[index] != '\t' && json[index] != '\r' &&
           json[index] != '\n') ++index;
    if (number_begin == index) return false;
    *token = json.substr(number_begin, index - number_begin);
    found = true;
  }
  return found;
}

inline bool BitcoinAmountToSats(const std::string& value, uint64_t* sats) {
  if (sats == nullptr || value.empty() || value[0] == '-') return false;
  const size_t decimal = value.find('.');
  if (value.find_first_of("eE") != std::string::npos ||
      (decimal != std::string::npos && value.find('.', decimal + 1) != std::string::npos))
    return false;
  const std::string whole_text = value.substr(0, decimal);
  std::string fractional = decimal == std::string::npos
                               ? std::string()
                               : value.substr(decimal + 1);
  if (whole_text.empty() || fractional.size() > 8) return false;
  uint64_t whole = 0;
  for (char digit : whole_text) {
    if (digit < '0' || digit > '9' ||
        whole > (kBlindzapMaxMoneySats / 100000000ULL -
                 static_cast<uint64_t>(digit - '0')) / 10) return false;
    whole = whole * 10 + static_cast<uint64_t>(digit - '0');
  }
  uint64_t fraction = 0;
  for (char digit : fractional) {
    if (digit < '0' || digit > '9') return false;
    fraction = fraction * 10 + static_cast<uint64_t>(digit - '0');
  }
  for (size_t index = fractional.size(); index < 8; ++index) fraction *= 10;
  if (whole > kBlindzapMaxMoneySats / 100000000ULL) return false;
  const uint64_t result = whole * 100000000ULL + fraction;
  if (result > kBlindzapMaxMoneySats) return false;
  *sats = result;
  return true;
}

struct Tip {
  std::string chain;
  std::string best_block_hash;
  uint64_t height = 0;
};

inline bool ParseTip(const std::string& text, Tip* tip) {
  if (tip == nullptr || text.size() > kBlindzapMaxRpcOutputBytes) return false;
  const auto json = nlohmann::json::parse(text, nullptr, false);
  if (json.is_discarded() || !json.is_object() || !json.contains("chain") ||
      !json["chain"].is_string() || !json.contains("bestblockhash") ||
      !json["bestblockhash"].is_string() || !json.contains("blocks")) return false;
  Tip parsed;
  parsed.chain = json["chain"].get<std::string>();
  parsed.best_block_hash = json["bestblockhash"].get<std::string>();
  if (!IsLowerHex(parsed.best_block_hash, 64) ||
      !JsonUnsigned(json["blocks"], &parsed.height)) return false;
  *tip = std::move(parsed);
  return true;
}

}  // namespace blindzap_internal

inline BlindzapProcessResult BlindzapRunArgv(
    const std::vector<std::string>& argv) {
  BlindzapProcessResult result;
  if (argv.empty() || argv.front().empty() || argv.front()[0] != '/') return result;

  blindzap_internal::FileDescriptor stdout_read, stdout_write, stderr_read,
      stderr_write;
  if (!blindzap_internal::MakePipe(&stdout_read, &stdout_write) ||
      !blindzap_internal::MakePipe(&stderr_read, &stderr_write)) return result;

  const pid_t child = fork();
  if (child == 0) {
    (void)setpgid(0, 0);
    stdout_read.reset();
    stderr_read.reset();
    if (dup2(stdout_write.get(), STDOUT_FILENO) < 0 ||
        dup2(stderr_write.get(), STDERR_FILENO) < 0) _exit(126);
    stdout_write.reset();
    stderr_write.reset();
    std::vector<char*> arguments;
    arguments.reserve(argv.size() + 1);
    for (const auto& value : argv)
      arguments.push_back(const_cast<char*>(value.c_str()));
    arguments.push_back(nullptr);
    execv(arguments.front(), arguments.data());
    _exit(errno == ENOENT ? 127 : 126);
  }
  stdout_write.reset();
  stderr_write.reset();
  if (child < 0) return result;
  (void)setpgid(child, child);
  if (!blindzap_internal::SetNonBlocking(stdout_read.get()) ||
      !blindzap_internal::SetNonBlocking(stderr_read.get())) {
    blindzap_internal::KillProcessGroup(child);
    (void)waitpid(child, nullptr, 0);
    return result;
  }

  const auto deadline = std::chrono::steady_clock::now() + kBlindzapRpcTimeout;
  int status = 0;
  bool child_reaped = false;
  bool child_status_available = false;
  while (stdout_read || stderr_read || !child_reaped) {
    if (!result.timed_out && std::chrono::steady_clock::now() >= deadline) {
      result.timed_out = true;
      if (!child_reaped) blindzap_internal::KillProcessGroup(child);
    }
    std::array<pollfd, 2> descriptors{{
        {stdout_read ? stdout_read.get() : -1, POLLIN | POLLHUP, 0},
        {stderr_read ? stderr_read.get() : -1, POLLIN | POLLHUP, 0},
    }};
    const int poll_result = poll(descriptors.data(), descriptors.size(), 100);
    if (poll_result < 0 && errno != EINTR) {
      blindzap_internal::KillProcessGroup(child);
      result.exit_code = -1;
      break;
    }
    bool limit = false;
    (void)blindzap_internal::AppendAvailable(&stdout_read, &result.stdout_text,
                                             &limit);
    result.output_limit_exceeded |= limit;
    limit = false;
    (void)blindzap_internal::AppendAvailable(&stderr_read, &result.stderr_text,
                                             &limit);
    result.output_limit_exceeded |= limit;
    if (result.output_limit_exceeded && !child_reaped)
      blindzap_internal::KillProcessGroup(child);
    if (!child_reaped) {
      const pid_t waited = waitpid(child, &status, WNOHANG);
      if (waited == child) {
        child_reaped = true;
        child_status_available = true;
      } else if (waited < 0 && errno == ECHILD) {
        child_reaped = true;
      }
    }
    if ((result.timed_out || result.output_limit_exceeded) && child_reaped) {
      stdout_read.reset();
      stderr_read.reset();
    }
  }
  if (!child_reaped) {
    pid_t waited = -1;
    do {
      waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    child_status_available = waited == child;
  }
  if (!result.timed_out && !result.output_limit_exceeded &&
      child_status_available && WIFEXITED(status))
    result.exit_code = WEXITSTATUS(status);
  return result;
}

class BitcoinCoreCurrentTipProvider final : public BlindzapChainProvider {
 public:
  using Runner =
      std::function<BlindzapProcessResult(const std::vector<std::string>&)>;

  BitcoinCoreCurrentTipProvider(std::string executable, BlindzapNetwork network,
                                Runner runner = BlindzapRunArgv)
      : executable_(std::move(executable)), network_(network),
        runner_(std::move(runner)) {}

  BlindzapProviderKind kind() const override {
    return BlindzapProviderKind::kCurrentTip;
  }

  BlindzapChainEvidence Lookup(const BlindzapChainRequest& request) override {
    BlindzapChainEvidence evidence;
    if (!runner_ || request.has_snapshot || request.network != network_ ||
        !BlindzapNetworkValid(network_)) {
      evidence.status = BlindzapChainStatus::kInconclusive;
      evidence.detail = "provider/request mismatch";
      return evidence;
    }
    const auto tip_result = runner_(Command({"getblockchaininfo"}));
    blindzap_internal::Tip tip;
    if (tip_result.exit_code != 0 ||
        !blindzap_internal::ParseTip(tip_result.stdout_text, &tip)) {
      evidence.status = BlindzapChainStatus::kUnavailable;
      evidence.detail = "getblockchaininfo failed";
      return evidence;
    }
    if (tip.chain != BlindzapBitcoinCoreChainName(network_)) {
      evidence.status = BlindzapChainStatus::kWrongNetwork;
      evidence.detail = "Bitcoin Core network does not match statement";
      return evidence;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::string txid;
    txid.reserve(64);
    for (uint8_t byte : request.txid) {
      txid.push_back(kHex[byte >> 4]);
      txid.push_back(kHex[byte & 15]);
    }
    const auto txout_result = runner_(Command(
        {"gettxout", txid, std::to_string(request.vout), "true"}));
    if (txout_result.exit_code != 0) {
      evidence.status = BlindzapChainStatus::kUnavailable;
      evidence.detail = "gettxout failed";
      return evidence;
    }
    const auto txout =
        nlohmann::json::parse(txout_result.stdout_text, nullptr, false);
    if (txout.is_discarded()) {
      evidence.status = BlindzapChainStatus::kMalformed;
      evidence.detail = "gettxout returned invalid JSON";
      return evidence;
    }
    if (txout.is_null()) {
      // gettxout cannot distinguish a spent output from a nonexistent one.
      evidence.status = BlindzapChainStatus::kInconclusive;
      evidence.detail = "outpoint is absent from the current UTXO set";
      return evidence;
    }
    if (!txout.is_object() || !txout.contains("bestblock") ||
        !txout["bestblock"].is_string() || !txout.contains("confirmations") ||
        !txout.contains("value") || !txout.contains("scriptPubKey") ||
        !txout["scriptPubKey"].is_object() ||
        !txout["scriptPubKey"].contains("hex") ||
        !txout["scriptPubKey"]["hex"].is_string()) {
      evidence.status = BlindzapChainStatus::kMalformed;
      evidence.detail = "gettxout response has an unexpected shape";
      return evidence;
    }
    const std::string best_block = txout["bestblock"].get<std::string>();
    const std::string script = txout["scriptPubKey"]["hex"].get<std::string>();
    std::string amount_token;
    uint64_t amount_sats = 0, confirmations = 0;
    if (best_block != tip.best_block_hash ||
        !blindzap_internal::TopLevelNumberToken(txout_result.stdout_text,
                                                "value", &amount_token) ||
        !blindzap_internal::BitcoinAmountToSats(amount_token, &amount_sats) ||
        !blindzap_internal::JsonUnsigned(txout["confirmations"], &confirmations) ||
        !blindzap_internal::DecodeHex(script, &evidence.script_pub_key)) {
      evidence.status = BlindzapChainStatus::kMalformed;
      evidence.detail = "gettxout fields are not canonical";
      return evidence;
    }

    const auto tip_after_result = runner_(Command({"getblockchaininfo"}));
    blindzap_internal::Tip tip_after;
    if (tip_after_result.exit_code != 0 ||
        !blindzap_internal::ParseTip(tip_after_result.stdout_text, &tip_after) ||
        tip_after.chain != tip.chain ||
        tip_after.best_block_hash != tip.best_block_hash ||
        tip_after.height != tip.height) {
      evidence.status = BlindzapChainStatus::kInconclusive;
      evidence.detail = "chain tip changed during lookup";
      return evidence;
    }

    evidence.network = network_;
    evidence.height = tip.height;
    evidence.confirmations = confirmations;
    evidence.amount_sats = amount_sats;
    std::vector<uint8_t> block_bytes;
    if (!blindzap_internal::DecodeHex(tip.best_block_hash, &block_bytes) ||
        block_bytes.size() != evidence.block.size()) {
      evidence.status = BlindzapChainStatus::kMalformed;
      evidence.detail = "best block hash is malformed";
      return evidence;
    }
    std::copy(block_bytes.begin(), block_bytes.end(), evidence.block.begin());
    evidence.status = BlindzapChainStatus::kUnspent;
    return evidence;
  }

 private:
  std::vector<std::string> Command(
      std::initializer_list<std::string> rpc_arguments) const {
    std::vector<std::string> arguments{executable_};
    switch (network_) {
      case BlindzapNetwork::kMainnet: break;
      case BlindzapNetwork::kTestnet3: arguments.emplace_back("-testnet"); break;
      case BlindzapNetwork::kSignet: arguments.emplace_back("-signet"); break;
      case BlindzapNetwork::kRegtest: arguments.emplace_back("-regtest"); break;
      case BlindzapNetwork::kTestnet4: arguments.emplace_back("-testnet4"); break;
    }
    arguments.insert(arguments.end(), rpc_arguments.begin(), rpc_arguments.end());
    return arguments;
  }

  std::string executable_;
  BlindzapNetwork network_;
  Runner runner_;
};

}  // namespace proofs
#endif
