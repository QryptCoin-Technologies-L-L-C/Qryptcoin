#pragma once

#include <vector>

#include "primitives/hash.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::primitives {

Hash256 ComputeMerkleRoot(const std::vector<CTransaction>& transactions);
Hash256 ComputeWitnessMerkleRoot(const std::vector<CTransaction>& transactions);

}  // namespace qryptcoin::primitives
