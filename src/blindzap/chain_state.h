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
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_CHAIN_STATE_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_CHAIN_STATE_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include "blindzap/statement.h"

namespace proofs {
enum class BlindzapProviderKind : uint8_t { kCurrentTip, kHistoricalSnapshot };
enum class BlindzapChainStatus : uint8_t { kUnspent, kSpent, kInconclusive, kUnavailable, kMalformed, kWrongNetwork, kStale };
struct BlindzapChainRequest {
  BlindzapNetwork network;
  std::array<uint8_t, 32> txid{};
  uint32_t vout = 0;
  bool has_snapshot = false;
  std::array<uint8_t, 32> snapshot{};
  uint32_t snapshot_height = 0;
};
struct BlindzapChainEvidence { BlindzapChainStatus status = BlindzapChainStatus::kUnavailable; BlindzapNetwork network = BlindzapNetwork::kMainnet; std::array<uint8_t,32> block{}; uint64_t height = 0; uint64_t confirmations = 0; uint64_t amount_sats = 0; std::vector<uint8_t> script_pub_key; std::string detail; };
class BlindzapChainProvider { public: virtual ~BlindzapChainProvider() = default; virtual BlindzapProviderKind kind() const = 0; virtual BlindzapChainEvidence Lookup(const BlindzapChainRequest&) = 0; };
inline bool BlindzapIsP2wpkh(const BlindzapClaimV1& claim, const std::vector<uint8_t>& script) { return script.size() == 22 && script[0] == 0 && script[1] == 20 && std::equal(claim.program.begin(), claim.program.end(), script.begin() + 2); }
inline BlindzapChainStatus BlindzapMatchClaim(const BlindzapClaimV1& claim, BlindzapNetwork network, const BlindzapChainEvidence& evidence) {
  if (evidence.status != BlindzapChainStatus::kUnspent) return evidence.status;
  if (evidence.network != network || evidence.amount_sats != claim.amount_sats || !BlindzapIsP2wpkh(claim, evidence.script_pub_key)) return BlindzapChainStatus::kInconclusive;
  return BlindzapChainStatus::kUnspent;
}
}  // namespace proofs
#endif
