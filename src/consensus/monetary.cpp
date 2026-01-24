#include "consensus/monetary.hpp"

namespace qryptcoin::consensus {

primitives::Amount CalculateBlockSubsidy(std::uint32_t height) {
  const auto halvings = height / kHalvingIntervalBlocks;
  if (halvings >= 64) {
    return 0;
  }

  primitives::Amount subsidy = kInitialSubsidy;
  subsidy >>= halvings;
  return subsidy;
}

}  // namespace qryptcoin::consensus
