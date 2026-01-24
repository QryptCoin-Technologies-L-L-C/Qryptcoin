#include "consensus/block_validator.hpp"

#include <algorithm>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "consensus/block_hash.hpp"
#include "consensus/block_weight.hpp"
#include "consensus/monetary.hpp"
#include "consensus/pow.hpp"
#include "consensus/witness_commitment.hpp"
#include "primitives/amount.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "primitives/txid.hpp"

namespace qryptcoin::consensus {

namespace {

bool SumOutputsChecked(const primitives::CTransaction& tx, primitives::Amount* total) {
  if (!total) return false;
  primitives::Amount sum = 0;
  for (const auto& out : tx.vout) {
    if (!primitives::MoneyRange(out.value)) {
      return false;
    }
    primitives::Amount next = 0;
    if (!primitives::CheckedAdd(sum, out.value, &next)) {
      return false;
    }
    sum = next;
  }
  *total = sum;
  return true;
}

bool TargetIsZero(const std::array<std::uint8_t, 32>& target) {
  for (auto b : target) {
    if (b != 0) return false;
  }
  return true;
}

}  // namespace

bool ValidateAndApplyBlock(const primitives::CBlock& block, std::uint32_t height,
                           std::uint64_t lock_time_cutoff_time,
                           std::uint32_t max_block_serialized_bytes,
                           std::uint32_t witness_commitment_activation_height,
                           UTXOSet* view,
                           RevealedPubkeySet* revealed_pubkeys,
                           std::string* error) {
  if (!view || !revealed_pubkeys) {
    if (error) *error = "invalid validation state";
    return false;
  }
  if (block.transactions.empty()) {
    if (error) *error = "empty block";
    return false;
  }
  if (!block.transactions.front().IsCoinbase()) {
    if (error) *error = "missing coinbase";
    return false;
  }

  // Header-level checks: Merkle root and proof-of-work.
  const auto merkle = primitives::ComputeMerkleRoot(block.transactions);
  if (merkle != block.header.merkle_root) {
    if (error) *error = "merkle root mismatch";
    return false;
  }
  const auto header_hash = ComputeBlockHash(block.header);
  const auto target = CompactToTarget(block.header.difficulty_bits);
  if (TargetIsZero(target)) {
    if (error) *error = "invalid difficulty target";
    return false;
  }
  if (!HashMeetsTarget(header_hash, target)) {
    if (error) *error = "insufficient proof-of-work";
    return false;
  }

  // Enforce basic coinbase structure and signaling rules.
  const auto& coinbase = block.transactions.front();
  if (coinbase.vin.size() != 1) {
    if (error) *error = "coinbase must have exactly one input";
    return false;
  }
  if (!coinbase.vin.front().prevout.IsNull()) {
    if (error) *error = "coinbase input must use null outpoint";
    return false;
  }
  if (coinbase.lock_time != 0) {
    if (error) *error = "coinbase lock_time must be zero";
    return false;
  }
  if (coinbase.vin.front().sequence != 0xFFFFFFFFu) {
    if (error) *error = "coinbase sequence must be final";
    return false;
  }
  if (coinbase.vin.front().unlocking_descriptor.size() > 100) {
    if (error) *error = "coinbase unlocking_descriptor too large";
    return false;
  }
  // Coinbase height commitment: coinbase unlocking_descriptor must start with
  // the canonical varint-encoded block height.
  // This makes coinbase txids unique across heights and removes a class of
  // duplicate-txid attacks.
  const auto& desc = coinbase.vin.front().unlocking_descriptor;
  std::size_t cursor = 0;
  std::uint64_t encoded_height = 0;
  if (!primitives::serialize::ReadVarInt(desc, &cursor, &encoded_height) ||
      encoded_height != static_cast<std::uint64_t>(height)) {
    if (error) *error = "coinbase must start with varint-encoded block height";
    return false;
  }

  const bool enforce_witness_commitment =
      height >= witness_commitment_activation_height;
  if (enforce_witness_commitment) {
    // Witness commitment: the coinbase MUST carry a single,
    // unambiguous commitment to the witness merkle root so that witness data
    // becomes consensus-critical. This eliminates the "same header hash,
    // different body" class where witness malleability can otherwise create
    // multiple valid blocks with identical headers/txids.
    //
    // Commitment layout is enforced strictly to keep parsing deterministic:
    //   [varint(height)] [uint64 extra_nonce LE] [tag] [32-byte witness_merkle_root]
    const std::size_t expected_size =
        cursor + consensus::kCoinbaseExtraNonceSize + consensus::kWitnessCommitmentSize;
    if (desc.size() != expected_size) {
      if (error) *error = "coinbase missing witness commitment";
      return false;
    }
    const std::size_t tag_offset = cursor + consensus::kCoinbaseExtraNonceSize;
    if (!std::equal(consensus::kWitnessCommitmentTag.begin(),
                    consensus::kWitnessCommitmentTag.end(),
                    desc.begin() + static_cast<std::ptrdiff_t>(tag_offset))) {
      if (error) *error = "coinbase witness commitment tag mismatch";
      return false;
    }
    primitives::Hash256 committed_root{};
    const std::size_t root_offset = tag_offset + consensus::kWitnessCommitmentTag.size();
    std::copy_n(desc.begin() + static_cast<std::ptrdiff_t>(root_offset),
                committed_root.size(), committed_root.begin());
    const auto expected_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
    if (committed_root != expected_root) {
      if (error) *error = "coinbase witness commitment mismatch";
      return false;
    }
  }

  const auto weight = CalculateBlockWeight(block);
  const auto weight_limit = AdaptiveBlockWeightLimit(weight);
  if (weight.weight > weight_limit) {
    if (error) {
      *error = "block weight exceeds adaptive limit (" + std::to_string(weight.weight) + " > " +
               std::to_string(weight_limit) + ")";
    }
    return false;
  }
  // Consensus safety cap: blocks must be small enough to fit within the P2P
  // transport framing limits so every valid block can be relayed by the
  // network. This is enforced separately from the weight limit.
  if (max_block_serialized_bytes != 0) {
    const auto serialized_bytes = weight.base_bytes + weight.witness_bytes;
    if (serialized_bytes > max_block_serialized_bytes) {
      if (error) {
        *error = "block exceeds max serialized size (" + std::to_string(serialized_bytes) + " > " +
                 std::to_string(max_block_serialized_bytes) + ")";
      }
      return false;
    }
  }

  primitives::Amount fees = 0;
  std::unordered_set<primitives::Hash256, Hash256Hasher> seen_txids;
  seen_txids.reserve(block.transactions.size());

  for (std::size_t tx_index = 1; tx_index < block.transactions.size(); ++tx_index) {
    const auto& tx = block.transactions[tx_index];
    if (tx.IsCoinbase()) {
      if (error) *error = "additional coinbase";
      return false;
    }

    primitives::Amount input_sum = 0;
    for (const auto& in : tx.vin) {
      const Coin* coin = view->GetCoin(in.prevout);
      if (coin == nullptr) {
        if (error) *error = "missing UTXO";
        return false;
      }
      primitives::Amount next = 0;
      if (!primitives::CheckedAdd(input_sum, coin->out.value, &next)) {
        if (error) *error = "input amount out of range";
        return false;
      }
      input_sum = next;
    }
    std::string tx_error;
    std::vector<primitives::Hash256> revealed_keys;
    if (!ValidateTransaction(tx, *view, *revealed_pubkeys, static_cast<std::uint32_t>(height),
                             lock_time_cutoff_time, &revealed_keys, &tx_error)) {
      if (error) *error = "tx invalid: " + tx_error;
      return false;
    }
    for (const auto& pk_hash : revealed_keys) {
      if (!revealed_pubkeys->Insert(pk_hash)) {
        if (error) *error = "tx invalid: public key already revealed";
        return false;
      }
    }
    for (const auto& in : tx.vin) {
      view->SpendCoin(in.prevout);
    }
    primitives::Amount output_sum = 0;
    if (!SumOutputsChecked(tx, &output_sum)) {
      if (error) *error = "output amount out of range";
      return false;
    }
    if (output_sum > input_sum) {
      if (error) *error = "outputs exceed inputs";
      return false;
    }
    primitives::Amount fee_delta = 0;
    if (!primitives::CheckedSub(input_sum, output_sum, &fee_delta)) {
      if (error) *error = "fee computation overflow";
      return false;
    }
    primitives::Amount next_fees = 0;
    if (!primitives::CheckedAdd(fees, fee_delta, &next_fees)) {
      if (error) *error = "fee total out of range";
      return false;
    }
    fees = next_fees;
    auto txid = primitives::ComputeTxId(tx);
    if (!seen_txids.insert(txid).second) {
      if (error) *error = "duplicate txid within block";
      return false;
    }
    for (std::size_t out_index = 0; out_index < tx.vout.size(); ++out_index) {
      primitives::COutPoint outpoint;
      outpoint.txid = txid;
      outpoint.index = static_cast<std::uint32_t>(out_index);
      if (view->GetCoin(outpoint) != nullptr) {
        if (error) *error = "txid collision would overwrite an existing UTXO";
        return false;
      }
      Coin coin;
      coin.out = tx.vout[out_index];
      coin.height = height;
      coin.coinbase = false;
      view->AddCoin(outpoint, coin);
    }
  }

  primitives::Amount coinbase_total = 0;
  if (!SumOutputsChecked(coinbase, &coinbase_total)) {
    if (error) *error = "coinbase output out of range";
    return false;
  }
  primitives::Amount subsidy = CalculateBlockSubsidy(height);
  primitives::Amount subsidy_plus_fees = 0;
  if (!primitives::CheckedAdd(subsidy, fees, &subsidy_plus_fees)) {
    if (error) *error = "subsidy+fees out of range";
    return false;
  }
  if (coinbase_total > subsidy_plus_fees) {
    if (error) *error = "coinbase exceeds subsidy + fees";
    return false;
  }
  auto coinbase_id = primitives::ComputeTxId(coinbase);
  if (!seen_txids.insert(coinbase_id).second) {
    if (error) *error = "duplicate txid within block (coinbase)";
    return false;
  }
  for (std::size_t out_index = 0; out_index < coinbase.vout.size(); ++out_index) {
    primitives::COutPoint outpoint;
    outpoint.txid = coinbase_id;
    outpoint.index = static_cast<std::uint32_t>(out_index);
    if (view->GetCoin(outpoint) != nullptr) {
      if (error) *error = "coinbase txid collision would overwrite an existing UTXO";
      return false;
    }
    Coin coin;
    coin.out = coinbase.vout[out_index];
    coin.height = height;
    coin.coinbase = true;
    view->AddCoin(outpoint, coin);
  }
  return true;
}

}  // namespace qryptcoin::consensus
