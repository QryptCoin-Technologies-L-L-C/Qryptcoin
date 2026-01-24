#include "policy/fee_estimator.hpp"

#include <algorithm>
#include <cmath>

namespace qryptcoin::policy {

RollingFeeEstimator::RollingFeeEstimator(double decay, std::size_t max_samples)
    : decay_(decay), max_samples_(max_samples) {}

void RollingFeeEstimator::Configure(double decay, std::size_t max_samples) {
  if (decay > 0.0 && decay < 1.0) {
    decay_ = decay;
  }
  if (max_samples > 0) {
    max_samples_ = max_samples;
  }
}

void RollingFeeEstimator::ApplyDecayLocked() {
  if (samples_.empty()) {
    return;
  }
  for (auto& s : samples_) {
    s.weight *= decay_;
  }
  // Drop samples that contribute negligible weight.
  const double kMinWeight = 1e-3;
  samples_.erase(std::remove_if(samples_.begin(), samples_.end(),
                                [kMinWeight](const Sample& s) {
                                  return s.weight < kMinWeight;
                                }),
                 samples_.end());
}

void RollingFeeEstimator::AddConfirmation(double fee_rate_miks_per_vb,
                                          std::uint32_t confirm_blocks) {
  if (fee_rate_miks_per_vb <= 0.0 || confirm_blocks == 0) {
    return;
  }
  ApplyDecayLocked();
  Sample s;
  s.fee_rate = fee_rate_miks_per_vb;
  s.confirm_blocks = confirm_blocks;
  s.weight = 1.0;
  samples_.push_back(s);
  if (samples_.size() > max_samples_) {
    // Remove the smallest-weight samples first.
    std::stable_sort(samples_.begin(), samples_.end(),
                     [](const Sample& a, const Sample& b) {
                       return a.weight > b.weight;
                     });
    samples_.resize(max_samples_);
  }
}

double RollingFeeEstimator::EstimateFeeRate(
    std::uint32_t target_blocks, double mempool_min_fee_miks_per_vb) const {
  if (target_blocks == 0) {
    target_blocks = 1;
  }
  if (samples_.empty()) {
    return mempool_min_fee_miks_per_vb;
  }
  // Work on a copy so we can sort without mutating the internal order.
  std::vector<Sample> sorted = samples_;
  std::sort(sorted.begin(), sorted.end(),
            [](const Sample& a, const Sample& b) {
              return a.fee_rate > b.fee_rate;
            });

  double total_weight = 0.0;
  for (const auto& s : sorted) {
    total_weight += s.weight;
  }
  if (total_weight <= 0.0) {
    return mempool_min_fee_miks_per_vb;
  }

  // We look for the lowest fee rate such that at least 80% of the weight
  // confirms within the requested target.
  constexpr double kTargetFraction = 0.8;
  double best_fee = -1.0;

  double good_weight = 0.0;
  double cumulative_weight = 0.0;
  for (const auto& s : sorted) {
    cumulative_weight += s.weight;
    if (s.confirm_blocks <= target_blocks) {
      good_weight += s.weight;
    }
    double fraction = good_weight / total_weight;
    if (fraction >= kTargetFraction) {
      best_fee = s.fee_rate;
      break;
    }
  }

  if (best_fee <= 0.0) {
    // Not enough successful confirmations at this target; fall back.
    return mempool_min_fee_miks_per_vb;
  }
  // Never suggest a fee below the current mempool floor.
  if (best_fee < mempool_min_fee_miks_per_vb) {
    return mempool_min_fee_miks_per_vb;
  }
  return best_fee;
}

}  // namespace qryptcoin::policy

