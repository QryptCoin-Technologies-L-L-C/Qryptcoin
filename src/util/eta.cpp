#include "util/eta.hpp"

#include <cmath>

namespace qryptcoin::util {

double ExpectedHashesForBits(std::uint32_t bits) {
  if (bits == 0) return 0.0;

  const std::uint32_t exponent = bits >> 24;
  const std::uint32_t mantissa = bits & 0x007fffff;
  if (mantissa == 0 || exponent == 0) {
    return 0.0;
  }

  // Compact encoding: target = mantissa * 2^(8*(exponent-3)).
  const double log2_mantissa = std::log2(static_cast<double>(mantissa));
  const double log2_target =
      log2_mantissa + 8.0 * (static_cast<double>(exponent) - 3.0);

  // Expected hashes ≈ 2^256 / target. The +1 in (target+1) from the exact
  // work formula is negligible at this scale, so we follow the consensus
  // shape while remaining in double precision.
  const double log2_expected = 256.0 - log2_target;
  if (!std::isfinite(log2_expected)) {
    return 0.0;
  }
  return std::exp2(log2_expected);
}

double EstimatedSecondsToBlock(std::uint32_t bits, double hashrate_hps) {
  if (hashrate_hps <= 0.0) {
    return 0.0;
  }
  const double expected_hashes = ExpectedHashesForBits(bits);
  if (expected_hashes <= 0.0) {
    return 0.0;
  }
  return expected_hashes / hashrate_hps;
}

}  // namespace qryptcoin::util
