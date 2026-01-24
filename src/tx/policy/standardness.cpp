#include "policy/standardness.hpp"

#include <cstddef>
#include <unordered_set>

#include "script/l2_anchor.hpp"
#include "consensus/utxo.hpp"

namespace qryptcoin::policy {

ScriptType ClassifyScriptPubKey(const script::ScriptPubKey& script) {
  if (script.data.empty()) {
    return ScriptType::kNonStandard;
  }
  std::array<std::uint8_t, script::kP2QHWitnessProgramSize> program{};
  if (script::ExtractWitnessProgram(script, &program)) {
    return ScriptType::kP2QH;
  }
  script::Layer2Commitment anchor{};
  if (script::ParseL2Anchor(script, &anchor)) {
    return ScriptType::kL2Anchor;
  }
  return ScriptType::kNonStandard;
}

bool IsStandardTransaction(const primitives::CTransaction& tx, std::string* reason) {
  if (tx.IsCoinbase()) {
    if (reason) *reason = "coinbase transactions are not relayed";
    return false;
  }
  if (tx.vin.empty()) {
    if (reason) *reason = "transaction has no inputs";
    return false;
  }
  if (tx.vout.empty()) {
    if (reason) *reason = "transaction has no outputs";
    return false;
  }

  constexpr std::size_t kMaxScriptSize = 10'000;

  // Inputs: today we only support P2QH-style spends, which require an
  // empty unlocking_descriptor. Any non-empty payload is reserved for
  // future upgrades and treated as non-standard for relay purposes.
  for (const auto& in : tx.vin) {
    if (!in.unlocking_descriptor.empty()) {
      if (reason) *reason = "unlocking_descriptor must be empty for standard P2QH spends";
      return false;
    }
  }

  // Outputs: restrict to known script templates and bound script size.
  for (const auto& out : tx.vout) {
    if (out.locking_descriptor.size() > kMaxScriptSize) {
      if (reason) *reason = "script too large for standard relay";
      return false;
    }
    script::ScriptPubKey script_pub{out.locking_descriptor};
    switch (ClassifyScriptPubKey(script_pub)) {
      case ScriptType::kP2QH:
      case ScriptType::kL2Anchor:
        break;
      case ScriptType::kNonStandard:
        if (reason) *reason = "non-standard scriptPubKey";
        return false;
    }
  }

  return true;
}

bool IsStandardPackage(const std::vector<primitives::CTransaction>& txs, std::string* reason) {
  if (txs.empty()) {
    if (reason) *reason = "empty package";
    return false;
  }
  std::unordered_set<primitives::COutPoint, consensus::OutPointHasher> spent;
  for (const auto& tx : txs) {
    if (!IsStandardTransaction(tx, reason)) {
      return false;
    }
    for (const auto& in : tx.vin) {
      if (!spent.insert(in.prevout).second) {
        if (reason) *reason = "package double-spends the same outpoint";
        return false;
      }
    }
  }
  return true;
}

bool SignalsOptInRbf(const primitives::CTransaction& tx) {
  for (const auto& in : tx.vin) {
    if (in.sequence != 0xFFFFFFFFu) {
      return true;
    }
  }
  return false;
}

}  // namespace qryptcoin::policy
