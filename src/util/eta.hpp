#pragma once

#include <cstdint>

namespace qryptcoin::util {

// Return the expected number of hashes required to find a block at the
// given compact difficulty bits value. This mirrors the consensus logic
// used for block work (2^256 / (target + 1)) but returns a double for
// GUI / telemetry purposes.
double ExpectedHashesForBits(std::uint32_t bits);

// Convenience wrapper: given compact difficulty bits and the current
// hash rate in H/s, return the expected time to block in seconds.
double EstimatedSecondsToBlock(std::uint32_t bits, double hashrate_hps);

}  // namespace qryptcoin::util

