#pragma once

#include <string>
#include <vector>

#include "consensus/revealed_pubkeys.hpp"
#include "consensus/tx_validator.hpp"
#include "consensus/utxo.hpp"
#include "primitives/block.hpp"

namespace qryptcoin::consensus {

struct BlockValidationResult {
  bool ok{false};
  std::string error;
  primitives::Amount fees{0};
};

// Validate a block's transactions and apply them to the provided UTXO view.
// The lock_time_cutoff_time must be the chain-derived time used for
// lock_time finality checks (median-time-past of the previous block).
bool ValidateAndApplyBlock(const primitives::CBlock& block, std::uint32_t height,
                           std::uint64_t lock_time_cutoff_time,
                           std::uint32_t max_block_serialized_bytes,
                           std::uint32_t witness_commitment_activation_height,
                           UTXOSet* view,
                           RevealedPubkeySet* revealed_pubkeys,
                           std::string* error,
                           std::vector<primitives::Amount>* tx_fees_out = nullptr);

}  // namespace qryptcoin::consensus
