#include <cmath>
#include <cstdlib>
#include <iostream>

#include "consensus/pow.hpp"
#include "util/eta.hpp"

using qryptcoin::consensus::CompactToTarget;
using qryptcoin::util::ExpectedHashesForBits;
using qryptcoin::util::EstimatedSecondsToBlock;

namespace {

long double ReferenceExpectedHashes(std::uint32_t bits) {
  auto target = CompactToTarget(bits);

  long double target_value = 0.0L;
  for (std::uint8_t byte : target) {
    target_value = target_value * 256.0L +
                   static_cast<long double>(byte);
  }
  if (target_value <= 0.0L) {
    return 0.0L;
  }

  const long double two_256 = std::ldexp(1.0L, 256);
  return two_256 / target_value;
}

bool NearlyEqualRelative(long double a, long double b,
                         long double max_rel_error) {
  if (a == b) {
    return true;
  }
  const long double diff = std::fabs(a - b);
  const long double denom = std::max(std::fabs(a), std::fabs(b));
  if (denom == 0.0L) {
    return diff < max_rel_error;
  }
  const long double rel = diff / denom;
  return rel <= max_rel_error;
}

}  // namespace

int main() {
  try {
    // A few representative compact difficulty values spanning low, medium,
    // and higher difficulty.
    const std::uint32_t samples[] = {
        0x1d00ffffu,  // common baseline target
        0x1e0ffff0u,
        0x1f00ffffu,
    };

    for (std::uint32_t bits : samples) {
      const double gui_hashes = ExpectedHashesForBits(bits);
      const long double ref_hashes = ReferenceExpectedHashes(bits);

      if (ref_hashes <= 0.0L && gui_hashes != 0.0) {
        std::cerr << "eta_tests: ExpectedHashesForBits(" << std::hex << bits
                  << std::dec << ") should be zero\n";
        return EXIT_FAILURE;
      }

      const long double gui_ld = static_cast<long double>(gui_hashes);
      if (!NearlyEqualRelative(gui_ld, ref_hashes, 1e-8L)) {
        std::cerr << "eta_tests: mismatch for bits 0x" << std::hex << bits
                  << std::dec << "\n  gui=" << gui_hashes
                  << "\n  ref=" << static_cast<double>(ref_hashes) << "\n";
        return EXIT_FAILURE;
      }

      // Check that EstimatedSecondsToBlock is consistent with the
      // expected-hashes calculation for a non-zero hash rate.
      const double hashrate = 1e6;  // 1 MH/s
      const double seconds = EstimatedSecondsToBlock(bits, hashrate);
      const double expected_seconds =
          gui_hashes > 0.0 ? gui_hashes / hashrate : 0.0;

      if (!std::isfinite(seconds) || seconds <= 0.0) {
        std::cerr << "eta_tests: non-finite ETA for bits 0x" << std::hex << bits
                  << std::dec << " hashrate=" << hashrate << "\n";
        return EXIT_FAILURE;
      }

      const double rel =
          std::fabs(seconds - expected_seconds) / expected_seconds;
      if (rel > 1e-8) {
        std::cerr << "eta_tests: seconds mismatch for bits 0x" << std::hex << bits
                  << std::dec << "\n  eta=" << seconds
                  << "\n  expected=" << expected_seconds << "\n";
        return EXIT_FAILURE;
      }
    }

    // Edge cases: zero bits or zero hash rate should not produce
    // infinities or negative values.
    if (EstimatedSecondsToBlock(0u, 1e6) != 0.0) {
      std::cerr << "eta_tests: non-zero ETA for bits=0\n";
      return EXIT_FAILURE;
    }
    if (EstimatedSecondsToBlock(0x1d00ffffu, 0.0) != 0.0) {
      std::cerr << "eta_tests: non-zero ETA for hashrate=0\n";
      return EXIT_FAILURE;
    }

  } catch (const std::exception& ex) {
    std::cerr << "eta_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "eta_tests unknown exception\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
