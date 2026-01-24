#pragma once

#include <array>
#include <cstdint>

#include "primitives/hash.hpp"

namespace qryptcoin::consensus {

// Convert compact difficulty encoding into a 256-bit target interpreted
// as a big-endian unsigned integer.
std::array<std::uint8_t, 32> CompactToTarget(std::uint32_t bits);

// Encode a 256-bit big-endian target into compact difficulty bits, rejecting
// negative targets.
std::uint32_t TargetToCompact(const std::array<std::uint8_t, 32>& target);

// Check whether the given hash meets the supplied difficulty target.
bool HashMeetsTarget(const primitives::Hash256& hash,
                     const std::array<std::uint8_t, 32>& target);

// Compute the next compact difficulty value using the retarget schedule.
// previous_bits is the difficulty of the last block in
// the interval; first_timestamp and last_timestamp are the UNIX times of
// the first and last blocks in that interval. target_spacing is the
// desired block interval in seconds; adjustment_interval is the number of
// blocks per retarget window; pow_limit_bits caps the easiest allowed
// difficulty.
std::uint32_t CalculateNextWorkRequired(std::uint32_t previous_bits,
                                        std::uint32_t first_timestamp,
                                        std::uint32_t last_timestamp,
                                        std::uint32_t target_spacing,
                                        std::uint32_t adjustment_interval,
                                        std::uint32_t pow_limit_bits);

}  // namespace qryptcoin::consensus

