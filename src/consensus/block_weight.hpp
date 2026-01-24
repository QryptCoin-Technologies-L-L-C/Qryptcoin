#pragma once

#include <cstddef>

#include "primitives/block.hpp"

namespace qryptcoin::consensus {

struct BlockWeight {
  std::size_t base_bytes{0};
  std::size_t witness_bytes{0};
  std::size_t weight{0};
  std::size_t dilithium_signature_bytes{0};
};

BlockWeight CalculateBlockWeight(const primitives::CBlock& block);
std::size_t AdaptiveBlockWeightLimit(const BlockWeight& weight);

}  // namespace qryptcoin::consensus
