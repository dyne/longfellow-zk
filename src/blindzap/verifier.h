// Copyright 2026 Google LLC.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_VERIFIER_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_VERIFIER_H_
#include "blindzap/chain_state.h"
#include "blindzap/envelope.h"
namespace proofs {
enum class BlindzapVerifyResult { kInvalidProof, kMalformedStatement, kUnsupported, kStateInconclusive, kSpentAtSnapshot, kStaleSnapshot, kValidHistorical, kValidCurrent };
inline const char* BlindzapVerifyResultName(BlindzapVerifyResult r) { switch(r) { case BlindzapVerifyResult::kInvalidProof:return "invalid_proof"; case BlindzapVerifyResult::kMalformedStatement:return "malformed_statement"; case BlindzapVerifyResult::kUnsupported:return "unsupported"; case BlindzapVerifyResult::kStateInconclusive:return "state_inconclusive"; case BlindzapVerifyResult::kSpentAtSnapshot:return "spent_at_snapshot"; case BlindzapVerifyResult::kStaleSnapshot:return "stale_snapshot"; case BlindzapVerifyResult::kValidHistorical:return "valid_historical"; case BlindzapVerifyResult::kValidCurrent:return "valid_current"; } return "invalid_proof"; }
inline int BlindzapVerifyExitCode(BlindzapVerifyResult r) { switch(r) { case BlindzapVerifyResult::kValidCurrent: return 0; case BlindzapVerifyResult::kValidHistorical: return 1; case BlindzapVerifyResult::kSpentAtSnapshot: return 3; case BlindzapVerifyResult::kStaleSnapshot: return 4; case BlindzapVerifyResult::kStateInconclusive: return 5; case BlindzapVerifyResult::kMalformedStatement: return 65; case BlindzapVerifyResult::kUnsupported: return 66; case BlindzapVerifyResult::kInvalidProof: return 67; } return 67; }
struct BlindzapVerification { BlindzapVerifyResult result = BlindzapVerifyResult::kMalformedStatement; std::vector<BlindzapChainEvidence> claims; };
struct BlindzapVerifierConfig { BlindzapReplayPolicy policy; std::function<bool(const BlindzapEnvelopeV1&)> verify_proof; std::function<bool(const BlindzapEnvelopeV1&)> supports; BlindzapChainProvider* provider = nullptr; uint64_t min_confirmations = 0; };
inline BlindzapVerification VerifyBlindzap(const std::vector<uint8_t>& bytes, const BlindzapVerifierConfig& config) {
  BlindzapEnvelopeV1 envelope; if (!DecodeBlindzapEnvelope(bytes, &envelope)) return {};
  if (config.supports && !config.supports(envelope)) return {BlindzapVerifyResult::kUnsupported, {}};
  if (!config.verify_proof || !config.verify_proof(envelope)) return {BlindzapVerifyResult::kInvalidProof, {}};
  if (BlindzapCheckPolicy(envelope.statement, config.policy, true) != BlindzapAuthorization::kPendingReplayCheck) return {BlindzapVerifyResult::kInvalidProof, {}};
  if (!config.provider || (envelope.statement.has_snapshot && config.provider->kind() != BlindzapProviderKind::kHistoricalSnapshot)) return {BlindzapVerifyResult::kStateInconclusive, {}};
  BlindzapVerification out; bool historical = envelope.statement.has_snapshot;
  for (const auto& claim : envelope.statement.claims) {
    BlindzapChainRequest request{envelope.statement.network, claim.txid, claim.vout, historical, envelope.statement.snapshot};
    BlindzapChainEvidence evidence = config.provider->Lookup(request); out.claims.push_back(evidence);
    const auto state = BlindzapMatchClaim(claim, envelope.statement.network, evidence);
    if (state == BlindzapChainStatus::kSpent) { out.result = BlindzapVerifyResult::kSpentAtSnapshot; return out; }
    if (state != BlindzapChainStatus::kUnspent) { out.result = BlindzapVerifyResult::kStateInconclusive; return out; }
    if (evidence.confirmations < config.min_confirmations) { out.result = BlindzapVerifyResult::kStaleSnapshot; return out; }
  }
  if (BlindzapConsumeNonce(envelope.statement, config.policy) != BlindzapAuthorization::kAuthorized) return {BlindzapVerifyResult::kInvalidProof, out.claims};
  out.result = historical ? BlindzapVerifyResult::kValidHistorical : BlindzapVerifyResult::kValidCurrent; return out;
}
}  // namespace proofs
#endif
