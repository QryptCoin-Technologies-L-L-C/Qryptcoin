#pragma once

#include <cstdint>
#include <vector>

namespace qryptcoin::policy {

// Rolling fee estimator implemented from scratch for QryptCoin. It keeps a
// bounded set of recent
// (fee_rate, confirmation_delay) samples and answers queries for the fee rate
// required to confirm within a target number of blocks.
//
// Fee rates are expressed in Miks per virtual byte.
class RollingFeeEstimator {
 public:
  RollingFeeEstimator(double decay, std::size_t max_samples);

  // Record a transaction that confirmed after |confirm_blocks| blocks at the
  // given fee rate (Miks/vB).
  void AddConfirmation(double fee_rate_miks_per_vb, std::uint32_t confirm_blocks);

  // Estimate the fee rate required to confirm within |target_blocks|. If there
  // is not enough data, returns |mempool_min_fee_miks_per_vb| as a conservative
  // fallback.
  double EstimateFeeRate(std::uint32_t target_blocks,
                         double mempool_min_fee_miks_per_vb) const;

  // Update configuration at runtime (used by operator CLI flags).
  void Configure(double decay, std::size_t max_samples);

 private:
  struct Sample {
    double fee_rate;
    std::uint32_t confirm_blocks;
    double weight;
  };

  void ApplyDecayLocked();

  double decay_{0.95};
  std::size_t max_samples_{512};
  std::vector<Sample> samples_;
};

}  // namespace qryptcoin::policy
