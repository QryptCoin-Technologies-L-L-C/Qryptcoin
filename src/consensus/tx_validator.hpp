#pragma once

#include <string>
#include <vector>

#include "consensus/revealed_pubkeys.hpp"
#include "consensus/utxo.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::consensus {

// Validate a non-coinbase transaction against the current UTXO view and
// basic finality rules. spending_height is the height of the block that
// would include this transaction; lock_time_cutoff_time is the time value
// used for absolute-time lock_time comparisons (UNIX seconds). For
// consensus safety this is derived from chain history (median-time-past),
// not the candidate block header timestamp.
//
// When `revealed_pubkeys_out` is non-null, it is populated with the set of
// public-key hashes (H3(pk_bytes)) revealed by this transaction's inputs.
bool ValidateTransaction(const primitives::CTransaction& tx, const UTXOSet& view,
                         const RevealedPubkeySet& revealed_pubkeys,
                         std::uint32_t spending_height, std::uint64_t lock_time_cutoff_time,
                         std::vector<primitives::Hash256>* revealed_pubkeys_out,
                         std::string* error);

}  // namespace qryptcoin::consensus
