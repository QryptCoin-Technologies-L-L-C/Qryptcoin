#include <cstdlib>
#include <iostream>

#include "policy/fee_estimator.hpp"

using qryptcoin::policy::RollingFeeEstimator;

int main() {
  try {
    {
      // With no samples the estimator must fall back to the mempool floor.
      RollingFeeEstimator est(0.95, 32);
      const double floor = 0.0;
      const double fee = est.EstimateFeeRate(/*target_blocks=*/3, floor);
      if (fee != floor) {
        std::cerr << "Estimator with no samples should return floor (0.0), got "
                  << fee << "\n";
        return EXIT_FAILURE;
      }
    }

    {
      // Mixture of slow low-fee confirmations and fast high-fee ones.
      RollingFeeEstimator est(0.95, 64);
      // A single slow confirmation at 1 Miks/vB that takes many blocks.
      est.AddConfirmation(/*fee_rate_miks_per_vb=*/1.0, /*confirm_blocks=*/6);
      double fee_slow = est.EstimateFeeRate(/*target_blocks=*/1, /*floor=*/0.0);
      if (fee_slow != 0.0) {
        std::cerr << "Estimator should fall back to floor when only slow samples exist\n";
        return EXIT_FAILURE;
      }

      // Several fast confirmations at 10 Miks/vB within 1 block.
      for (int i = 0; i < 5; ++i) {
        est.AddConfirmation(/*fee_rate_miks_per_vb=*/10.0, /*confirm_blocks=*/1);
      }
      double fee_fast = est.EstimateFeeRate(/*target_blocks=*/1, /*floor=*/0.0);
      if (fee_fast < 5.0 || fee_fast > 11.0) {
        std::cerr << "Estimator did not converge near high-fee samples, got "
                  << fee_fast << "\n";
        return EXIT_FAILURE;
      }

      // For looser targets the estimator should not require a *higher* fee.
      double fee_loose = est.EstimateFeeRate(/*target_blocks=*/6, /*floor=*/0.0);
      if (fee_loose > fee_fast + 1e-6) {
        std::cerr << "Estimator returned higher fee for larger target: "
                  << "tight=" << fee_fast << " loose=" << fee_loose << "\n";
        return EXIT_FAILURE;
      }
    }

    {
      // The estimator must never suggest a fee below the current mempool floor.
      RollingFeeEstimator est(0.95, 16);
      est.AddConfirmation(/*fee_rate_miks_per_vb=*/1.0, /*confirm_blocks=*/1);
      const double floor = 5.0;
      const double fee = est.EstimateFeeRate(/*target_blocks=*/1, floor);
      if (fee < floor - 1e-9) {
        std::cerr << "Estimator returned fee below mempool floor: fee=" << fee
                  << " floor=" << floor << "\n";
        return EXIT_FAILURE;
      }
    }

    {
      // Check that decay allows newer low-fee confirmations to pull estimates
      // down over time.
      RollingFeeEstimator est(0.5, 64);
      est.AddConfirmation(/*fee_rate_miks_per_vb=*/50.0, /*confirm_blocks=*/1);
      double initial = est.EstimateFeeRate(/*target_blocks=*/1, /*floor=*/0.0);
      if (initial < 25.0) {
        std::cerr << "Initial estimate unexpectedly low: " << initial << "\n";
        return EXIT_FAILURE;
      }

      for (int i = 0; i < 20; ++i) {
        est.AddConfirmation(/*fee_rate_miks_per_vb=*/2.0, /*confirm_blocks=*/1);
      }
      double decayed = est.EstimateFeeRate(/*target_blocks=*/1, /*floor=*/0.0);
      if (decayed >= initial) {
        std::cerr << "Estimator did not decay towards lower fees: initial=" << initial
                  << " decayed=" << decayed << "\n";
        return EXIT_FAILURE;
      }
    }

  } catch (const std::exception& ex) {
    std::cerr << "fee_estimator_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "fee_estimator_tests unknown exception\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

