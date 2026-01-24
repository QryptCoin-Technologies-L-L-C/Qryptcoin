#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "primitives/block.hpp"

namespace qryptcoin::node {

// Locate the extra-nonce slot inside the coinbase unlocking descriptor.
// The layout is [height (canonical varint) || extra_nonce (uint64_t LE) ...].
// Returns std::nullopt if the coinbase does not follow this convention.
std::optional<std::size_t> FindCoinbaseExtraNonceOffset(const primitives::CBlock& block);

// Write the given extra-nonce into the coinbase unlocking descriptor at
// the specified offset. The caller must ensure that offset points to a
// 64-bit field within the descriptor.
void SetCoinbaseExtraNonce(primitives::CBlock* block, std::size_t offset,
                           std::uint64_t extra_nonce);

}  // namespace qryptcoin::node
