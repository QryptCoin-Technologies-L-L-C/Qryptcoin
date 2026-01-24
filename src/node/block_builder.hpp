#pragma once

#include <array>
#include <optional>
#include <string>

#include "crypto/p2qh_descriptor.hpp"
#include "node/chain_state.hpp"
#include "primitives/block.hpp"

namespace qryptcoin::node {

struct BlockTemplate {
  primitives::CBlock block;
  std::array<std::uint8_t, 32> target{};
  std::uint32_t height{0};
};

bool BuildBlockTemplate(const ChainState& chain, const crypto::P2QHDescriptor& reward,
                        BlockTemplate* out, std::string* error);

}  // namespace qryptcoin::node

