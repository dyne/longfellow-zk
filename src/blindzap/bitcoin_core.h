// Copyright 2026 Google LLC.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_BITCOIN_CORE_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_BITCOIN_CORE_H_
#include <functional>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include "blindzap/chain_state.h"
namespace proofs {
// The transport receives an argv vector.  Implementations must use exec-style
// process creation; this boundary intentionally never constructs a shell command.
struct BlindzapProcessResult { int exit_code = -1; std::string stdout_text; std::string stderr_text; };

// Runs an explicitly configured executable with execv(3).  Arguments are
// passed as argv entries; neither this helper nor its callers invoke a shell.
inline BlindzapProcessResult BlindzapRunArgv(const std::vector<std::string>& argv) {
  BlindzapProcessResult result;
  if (argv.empty() || argv.front().empty()) return result;
  int output[2] = {-1, -1};
  if (pipe(output) != 0) return result;
  const pid_t child = fork();
  if (child == 0) {
    close(output[0]);
    dup2(output[1], STDOUT_FILENO);
    dup2(output[1], STDERR_FILENO);
    close(output[1]);
    std::vector<char*> args;
    args.reserve(argv.size() + 1);
    for (const auto& value : argv) args.push_back(const_cast<char*>(value.c_str()));
    args.push_back(nullptr);
    execv(args.front(), args.data());
    _exit(127);
  }
  close(output[1]);
  if (child < 0) { close(output[0]); return result; }
  char buffer[4096];
  while (result.stdout_text.size() <= 1024 * 1024) {
    const ssize_t n = read(output[0], buffer, sizeof(buffer));
    if (n <= 0) break;
    result.stdout_text.append(buffer, static_cast<size_t>(n));
  }
  close(output[0]);
  int status = 0;
  if (waitpid(child, &status, 0) < 0) return result;
  result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  if (result.stdout_text.size() > 1024 * 1024) result.exit_code = -1;
  return result;
}

class BitcoinCoreCurrentTipProvider final : public BlindzapChainProvider {
 public:
  using Runner = std::function<BlindzapProcessResult(const std::vector<std::string>&)>;
  BitcoinCoreCurrentTipProvider(std::string executable, BlindzapNetwork network, Runner runner = BlindzapRunArgv) : executable_(std::move(executable)), network_(network), runner_(std::move(runner)) {}
  BlindzapProviderKind kind() const override { return BlindzapProviderKind::kCurrentTip; }
  BlindzapChainEvidence Lookup(const BlindzapChainRequest& request) override {
    BlindzapChainEvidence out; out.network = network_; if (!runner_ || request.has_snapshot || request.network != network_) { out.status = BlindzapChainStatus::kInconclusive; return out; }
    const auto tip = runner_({executable_, "getblockchaininfo"}); if (tip.exit_code || tip.stdout_text.size() > 1024 * 1024 || tip.stdout_text.find("\"chain\"") == std::string::npos) { out.status = BlindzapChainStatus::kUnavailable; return out; }
    static const char hex[] = "0123456789abcdef"; std::string txid; for (uint8_t b : request.txid) { txid += hex[b >> 4]; txid += hex[b & 15]; }
    const auto txout = runner_({executable_, "gettxout", txid, std::to_string(request.vout), "true"}); if (txout.exit_code || txout.stdout_text.size() > 1024 * 1024) { out.status = BlindzapChainStatus::kUnavailable; return out; }
    if (txout.stdout_text == "null\n" || txout.stdout_text == "null") { out.status = BlindzapChainStatus::kSpent; return out; }
    const auto tip_after = runner_({executable_, "getblockchaininfo"}); if (tip_after.exit_code || tip_after.stdout_text != tip.stdout_text) { out.status = BlindzapChainStatus::kInconclusive; return out; }
    const auto field = [&](const char* name) { const std::string key = std::string("\"") + name + "\":"; size_t p=txout.stdout_text.find(key); if(p==std::string::npos) return std::string(); p+=key.size(); while(p<txout.stdout_text.size() && (txout.stdout_text[p]==' ' || txout.stdout_text[p]=='\"')) ++p; size_t e=p; while(e<txout.stdout_text.size() && txout.stdout_text[e]!=',' && txout.stdout_text[e]!='}' && txout.stdout_text[e]!='\"') ++e; return txout.stdout_text.substr(p,e-p); };
    const std::string value=field("valueSat"), conf=field("confirmations"), script=field("hex"); uint64_t sats=0, confirmations=0; std::istringstream vs(value), cs(conf); if (!(vs>>sats) || !(cs>>confirmations) || script.size()!=44) { out.status=BlindzapChainStatus::kMalformed; return out; }
    out.script_pub_key.reserve(22); for(size_t i=0;i<script.size();i+=2) { unsigned n=0; std::istringstream h(script.substr(i,2)); h>>std::hex>>n; if(h.fail()) { out.status=BlindzapChainStatus::kMalformed; return out; } out.script_pub_key.push_back(static_cast<uint8_t>(n)); }
    out.amount_sats=sats; out.confirmations=confirmations; out.status=BlindzapChainStatus::kUnspent; return out;
  }
 private: std::string executable_; BlindzapNetwork network_; Runner runner_;
};
}  // namespace proofs
#endif
