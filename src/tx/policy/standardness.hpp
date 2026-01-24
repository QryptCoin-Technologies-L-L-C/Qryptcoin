#pragma once

#include <string>
#include <vector>

#include "primitives/transaction.hpp"
#include "script/script.hpp"

namespace qryptcoin::policy {

enum class ScriptType {
  kNonStandard,
  kP2QH,
  kL2Anchor,
};

// Classify a ScriptPubKey into one of the known standard forms.
ScriptType ClassifyScriptPubKey(const script::ScriptPubKey& script);

// Lightweight, non-consensus standardness checks used for mempool policy.
// Returns true when the transaction is eligible for relay and mempool
// admission on this node. On failure, |reason| is populated with a
// human-readable hint when non-null.
bool IsStandardTransaction(const primitives::CTransaction& tx, std::string* reason);

// Simple package-aware check that applies IsStandardTransaction to each
// transaction in a dependency-ordered vector and enforces that no two
// transactions in the package double-spend the same outpoint.
bool IsStandardPackage(const std::vector<primitives::CTransaction>& txs, std::string* reason);

// Opt-in Replace-By-Fee signaling. Returns true if any
// input sequence number is non-final (!= 0xFFFFFFFF), indicating the
// transaction may be replaced in the mempool by higher-fee spends.
bool SignalsOptInRbf(const primitives::CTransaction& tx);

}  // namespace qryptcoin::policy
