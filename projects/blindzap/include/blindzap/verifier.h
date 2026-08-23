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
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_VERIFIER_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_VERIFIER_H_
#include <limits>
#include "blindzap/chain_state.h"
#include "blindzap/envelope.h"
namespace proofs {
enum class BlindzapVerifyResult : uint8_t { kInvalidProof, kMalformedStatement, kUnsupported, kStateInconclusive, kSpentAtSnapshot, kStaleSnapshot, kBridgeRejected, kValidHistorical, kValidCurrent };
inline const char* BlindzapVerifyResultName(BlindzapVerifyResult r) { switch(r) { case BlindzapVerifyResult::kInvalidProof:return "invalid_proof"; case BlindzapVerifyResult::kMalformedStatement:return "malformed_statement"; case BlindzapVerifyResult::kUnsupported:return "unsupported"; case BlindzapVerifyResult::kStateInconclusive:return "state_inconclusive"; case BlindzapVerifyResult::kSpentAtSnapshot:return "spent_at_snapshot"; case BlindzapVerifyResult::kStaleSnapshot:return "stale_snapshot"; case BlindzapVerifyResult::kBridgeRejected:return "bridge_rejected"; case BlindzapVerifyResult::kValidHistorical:return "valid_historical"; case BlindzapVerifyResult::kValidCurrent:return "valid_current"; } return "invalid_proof"; }
inline int BlindzapVerifyExitCode(BlindzapVerifyResult r) { switch(r) { case BlindzapVerifyResult::kValidCurrent: return 0; case BlindzapVerifyResult::kValidHistorical: return 1; case BlindzapVerifyResult::kSpentAtSnapshot: return 3; case BlindzapVerifyResult::kStaleSnapshot: return 4; case BlindzapVerifyResult::kStateInconclusive: return 5; case BlindzapVerifyResult::kBridgeRejected: return 6; case BlindzapVerifyResult::kMalformedStatement: return 65; case BlindzapVerifyResult::kUnsupported: return 66; case BlindzapVerifyResult::kInvalidProof: return 67; } return 67; }
struct BlindzapVerification { BlindzapVerifyResult result = BlindzapVerifyResult::kMalformedStatement; std::vector<BlindzapChainEvidence> claims; uint64_t total_sats = 0; };
struct BlindzapVerifierConfig { BlindzapReplayPolicy policy; std::function<bool(const BlindzapEnvelopeV1&)> verify_proof; std::function<bool(const BlindzapEnvelopeV1&)> supports; std::function<bool(const BlindzapStatementV1&)> bridge_authorized; BlindzapChainProvider* provider = nullptr; uint64_t min_confirmations = 0; uint64_t minimum_total_sats = 0; };
inline BlindzapVerification VerifyBlindzap(const std::vector<uint8_t>& bytes, const BlindzapVerifierConfig& config) {
  BlindzapEnvelopeV1 envelope;
  BlindzapDecodeError decode_error = BlindzapDecodeError::kMalformed;
  if (!DecodeBlindzapEnvelope(bytes, &envelope, &decode_error)) {
    return {decode_error == BlindzapDecodeError::kUnsupported
                ? BlindzapVerifyResult::kUnsupported
                : BlindzapVerifyResult::kMalformedStatement,
            {}};
  }
  if (BlindzapCheckPolicy(envelope.statement, config.policy, true) != BlindzapAuthorization::kPendingReplayCheck) return {BlindzapVerifyResult::kInvalidProof, {}};
  if (config.supports && !config.supports(envelope)) return {BlindzapVerifyResult::kUnsupported, {}};
  if (!config.verify_proof || !config.verify_proof(envelope)) return {BlindzapVerifyResult::kInvalidProof, {}};
  if (!config.provider || (envelope.statement.has_snapshot && config.provider->kind() != BlindzapProviderKind::kHistoricalSnapshot)) return {BlindzapVerifyResult::kStateInconclusive, {}};
  BlindzapVerification out; bool historical = envelope.statement.has_snapshot;
  std::array<uint8_t, 32> current_block{};
  uint64_t current_height = 0;
  bool have_current_tip = false;
  for (const auto& claim : envelope.statement.claims) {
    BlindzapChainRequest request{envelope.statement.network, claim.txid,
                                 claim.vout, historical,
                                 envelope.statement.snapshot,
                                 envelope.statement.snapshot_height};
    BlindzapChainEvidence evidence = config.provider->Lookup(request); out.claims.push_back(evidence);
    if (historical && (evidence.block != envelope.statement.snapshot ||
                       evidence.height != envelope.statement.snapshot_height)) {
      out.result = BlindzapVerifyResult::kStateInconclusive;
      return out;
    }
    if (!historical) {
      if (BlindzapAllZero(evidence.block)) {
        out.result = BlindzapVerifyResult::kStateInconclusive;
        return out;
      }
      if (!have_current_tip) {
        current_block = evidence.block;
        current_height = evidence.height;
        have_current_tip = true;
      } else if (evidence.block != current_block ||
                 evidence.height != current_height) {
        out.result = BlindzapVerifyResult::kStateInconclusive;
        return out;
      }
    }
    const auto state = BlindzapMatchClaim(claim, envelope.statement.network, evidence);
    if (state == BlindzapChainStatus::kSpent) { out.result = BlindzapVerifyResult::kSpentAtSnapshot; return out; }
    if (state != BlindzapChainStatus::kUnspent) { out.result = BlindzapVerifyResult::kStateInconclusive; return out; }
    if (evidence.confirmations < config.min_confirmations) { out.result = BlindzapVerifyResult::kStaleSnapshot; return out; }
    if (claim.amount_sats > std::numeric_limits<uint64_t>::max() - out.total_sats) { out.result = BlindzapVerifyResult::kStateInconclusive; return out; }
    out.total_sats += claim.amount_sats;
  }
  if (out.total_sats < config.minimum_total_sats) { out.result = BlindzapVerifyResult::kStateInconclusive; return out; }
  if (envelope.statement.has_bridge_binding && (!config.bridge_authorized || !config.bridge_authorized(envelope.statement))) { out.result = BlindzapVerifyResult::kBridgeRejected; return out; }
  if (BlindzapConsumeNonce(envelope.statement, config.policy) != BlindzapAuthorization::kAuthorized) return {BlindzapVerifyResult::kInvalidProof, out.claims};
  out.result = historical ? BlindzapVerifyResult::kValidHistorical : BlindzapVerifyResult::kValidCurrent; return out;
}
}  // namespace proofs
#endif
