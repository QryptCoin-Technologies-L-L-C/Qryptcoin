#pragma once

#include "primitives/block.hpp"

namespace qryptcoin::primitives {

Hash256 ComputeTxId(const CTransaction& tx);
Hash256 ComputeWTxId(const CTransaction& tx);

}  // namespace qryptcoin::primitives
