#include "consensus/block_weight.hpp"

#include <algorithm>

#include "crypto/p2qh_descriptor.hpp"
#include "primitives/serialize.hpp"

namespace qryptcoin::consensus {

namespace {

constexpr std::size_t kBaseBlockWeightLimit = 4'000'000;
constexpr std::size_t kMaxBlockWeightLimit = 8'000'000;

}  // namespace

BlockWeight CalculateBlockWeight(const primitives::CBlock& block) {
  BlockWeight stats{};
  const auto totals = primitives::serialize::MeasureBlockSizes(block);
  stats.base_bytes = totals.base_size;
  stats.witness_bytes = totals.witness_size;
  stats.weight = stats.base_bytes * 4 + stats.witness_bytes;

  // Tally Dilithium signature bytes for observability. With the
  // Dilithium-only policy this is the entire PQ witness region.
  for (const auto& tx : block.transactions) {
    for (const auto& in : tx.vin) {
      if (in.witness_stack.size() < 2) continue;
      stats.dilithium_signature_bytes += in.witness_stack[1].data.size();
    }
  }
  return stats;
}

std::size_t AdaptiveBlockWeightLimit(const BlockWeight& weight) {
  (void)weight;
  // With Dilithium-only signatures, always allow the elastic upper bound.
  return kMaxBlockWeightLimit;
}

}  // namespace qryptcoin::consensus
