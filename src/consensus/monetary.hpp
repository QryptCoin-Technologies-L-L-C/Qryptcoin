#pragma once

#include <cstdint>

#include "primitives/amount.hpp"

namespace qryptcoin::consensus {

inline constexpr std::uint32_t kTargetBlockSpacingSeconds = 600;
inline constexpr std::uint32_t kHalvingIntervalBlocks = 210'000;
inline constexpr std::uint32_t kCoinbaseMaturity = 100;
inline constexpr primitives::Amount kInitialSubsidy = 50ULL * primitives::kMiksPerQRY;

primitives::Amount CalculateBlockSubsidy(std::uint32_t height);

}  // namespace qryptcoin::consensus

