#pragma once

#include "primitives/block.hpp"

namespace qryptcoin::consensus {

primitives::Hash256 ComputeBlockHash(const primitives::CBlockHeader& header);

}  // namespace qryptcoin::consensus

