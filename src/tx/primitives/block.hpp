#pragma once

#include <cstdint>
#include <vector>

#include "primitives/hash.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::primitives {

struct CBlockHeader {
  std::uint32_t version{1};
  Hash256 previous_block_hash{};
  Hash256 merkle_root{};
  std::uint64_t timestamp{0};
  std::uint32_t difficulty_bits{0};
  // Consensus nonce is 32-bit; higher-width counters used by miners are
  // masked into this field before hashing/serialization.
  std::uint32_t nonce{0};
};

struct CBlock {
  CBlockHeader header{};
  std::vector<CTransaction> transactions{};
};

}  // namespace qryptcoin::primitives
