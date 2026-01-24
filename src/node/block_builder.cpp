#include "node/block_builder.hpp"

#include <algorithm>
#include <chrono>
#include <vector>

#include "config/network.hpp"
#include "consensus/monetary.hpp"
#include "consensus/params.hpp"
#include "consensus/pow.hpp"
#include "consensus/witness_commitment.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "script/p2qh.hpp"

namespace qryptcoin::node {

namespace {

primitives::CTransaction CreateCoinbase(std::uint32_t height, primitives::Amount subsidy,
                                        const crypto::P2QHDescriptor& reward) {
  primitives::CTransaction tx;
  tx.version = 1;
  tx.vin.resize(1);
  tx.vin[0].prevout = primitives::COutPoint::Null();
  tx.vin[0].sequence = 0xFFFFFFFF;
  // Encode the block height as a canonical varint followed by an extra-nonce
  // field so miners can mutate the coinbase and recompute the Merkle root.
  //
  // Consensus enforces that non-genesis coinbases start with the varint
  // height, so this also prevents duplicate coinbase txids across heights.
  tx.vin[0].unlocking_descriptor.clear();
  primitives::serialize::WriteVarInt(&tx.vin[0].unlocking_descriptor,
                                     static_cast<std::uint64_t>(height));
  primitives::serialize::WriteUint64(&tx.vin[0].unlocking_descriptor, 0);
  // Witness commitment: non-genesis blocks must commit to the witness merkle
  // root in the coinbase. At template construction time we only have the
  // coinbase, so the witness merkle root is 32 bytes of zero.
  tx.vin[0].unlocking_descriptor.insert(tx.vin[0].unlocking_descriptor.end(),
                                        consensus::kWitnessCommitmentTag.begin(),
                                        consensus::kWitnessCommitmentTag.end());
  tx.vin[0].unlocking_descriptor.resize(tx.vin[0].unlocking_descriptor.size() +
                                        primitives::Hash256{}.size());
  tx.vout.resize(1);
  tx.vout[0].value = subsidy;
  auto script = script::CreateP2QHScript(reward);
  tx.vout[0].locking_descriptor = script.data;
  return tx;
}

std::uint32_t NextDifficultyBits(const ChainState& chain,
                                 const consensus::ChainParams& params,
                                 std::uint32_t next_height,
                                 const BlockRecord* tip) {
  if (!tip) {
    return params.genesis_bits;
  }

  const std::uint32_t prev_bits = tip->header.difficulty_bits;
  if (params.difficulty_adjustment_activation_height != 0 &&
      next_height < params.difficulty_adjustment_activation_height) {
    return params.pow_limit_bits;
  }
  const std::uint32_t interval = params.difficulty_adjustment_interval;
  if (interval == 0) {
    return prev_bits;
  }
  if (next_height == 0 || next_height % interval != 0) {
    return prev_bits;
  }
  if (next_height < interval) {
    return prev_bits;
  }

  const auto* first = chain.GetByHeight(static_cast<std::size_t>(next_height - interval));
  const auto* last = chain.GetByHeight(static_cast<std::size_t>(next_height - 1));
  if (!first || !last) {
    return prev_bits;
  }

  const auto first_time = static_cast<std::uint32_t>(first->header.timestamp);
  const auto last_time = static_cast<std::uint32_t>(last->header.timestamp);
  return consensus::CalculateNextWorkRequired(prev_bits, first_time, last_time,
                                              params.target_block_time_seconds, interval,
                                              params.pow_limit_bits);
}

}  // namespace

bool BuildBlockTemplate(const ChainState& chain, const crypto::P2QHDescriptor& reward,
                        BlockTemplate* out, std::string* /*error*/) {
  if (!out) return false;
  BlockTemplate templ;
  templ.height = static_cast<std::uint32_t>(chain.BlockCount());
  const auto* tip = chain.Tip();
  const auto& params = consensus::Params(config::GetNetworkConfig().type);

  templ.block.header.version = 1;
  if (tip) {
    templ.block.header.previous_block_hash = tip->hash;
    templ.block.header.difficulty_bits = NextDifficultyBits(chain, params, templ.height, tip);
  } else {
    templ.block.header.previous_block_hash.fill(0);
    templ.block.header.difficulty_bits = params.genesis_bits;
  }
  const auto now = static_cast<std::uint64_t>(
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
  std::uint64_t mtp = 0;
  if (tip) {
    std::vector<std::uint64_t> times;
    times.reserve(11);
    const auto tip_height = chain.Height();
    const std::size_t count = std::min<std::size_t>(tip_height + 1, 11);
    for (std::size_t i = 0; i < count; ++i) {
      const auto* record = chain.GetByHeight(tip_height - i);
      if (!record) {
        break;
      }
      times.push_back(record->header.timestamp);
    }
    if (!times.empty()) {
      std::sort(times.begin(), times.end());
      mtp = times[times.size() / 2];
    }
  }
  templ.block.header.timestamp = tip ? std::max(now, mtp + 1) : now;
  templ.block.header.nonce = 0;

  const auto subsidy = consensus::CalculateBlockSubsidy(templ.height);
  templ.block.transactions = {CreateCoinbase(templ.height, subsidy, reward)};
  templ.block.header.merkle_root = primitives::ComputeMerkleRoot(templ.block.transactions);

  templ.target = consensus::CompactToTarget(templ.block.header.difficulty_bits);
  *out = templ;
  return true;
}

}  // namespace qryptcoin::node
