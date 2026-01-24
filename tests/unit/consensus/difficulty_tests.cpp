#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#include "consensus/pow.hpp"
#include "primitives/hash.hpp"

using namespace qryptcoin;

namespace {

int CompareTargets(const std::array<std::uint8_t, 32>& a,
                   const std::array<std::uint8_t, 32>& b) {
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

bool TestNoChangeWhenTimespanMatchesTarget() {
  const std::uint32_t previous_bits = 0x1f00ffffu;
  const std::uint32_t target_spacing = 600;
  const std::uint32_t interval = 10;
  const std::uint32_t pow_limit_bits = 0x207fffffu;

  const std::uint32_t target_timespan = target_spacing * interval;
  const std::uint32_t first_time = 1'000'000u;
  const std::uint32_t last_time = first_time + target_timespan;

  const std::uint32_t next_bits = consensus::CalculateNextWorkRequired(
      previous_bits, first_time, last_time, target_spacing, interval, pow_limit_bits);
  if (next_bits != previous_bits) {
    std::cerr << "Expected difficulty to remain unchanged when timespan == target\n";
    return false;
  }
  return true;
}

bool TestAdjustmentClampedForFastAndSlowBlocks() {
  const std::uint32_t previous_bits = 0x1f00ffffu;
  const std::uint32_t target_spacing = 600;
  const std::uint32_t interval = 10;
  const std::uint32_t pow_limit_bits = 0x207fffffu;

  const std::uint32_t target_timespan = target_spacing * interval;
  const std::uint32_t first_time = 2'000'000u;

  // Extremely fast blocks: actual_timespan << target_timespan, but the
  // retarget logic should clamp to target_timespan / 4.
  const std::uint32_t very_fast_last =
      first_time + target_timespan / 16;  // will be clamped
  const std::uint32_t fast_bits = consensus::CalculateNextWorkRequired(
      previous_bits, first_time, very_fast_last, target_spacing, interval, pow_limit_bits);

  auto prev_target = consensus::CompactToTarget(previous_bits);
  auto fast_target = consensus::CompactToTarget(fast_bits);
  if (CompareTargets(fast_target, prev_target) >= 0) {
    std::cerr << "Expected fast-block adjustment to produce a stricter (smaller) target\n";
    return false;
  }

  // Extremely slow blocks: actual_timespan >> target_timespan, but the
  // retarget logic should clamp to target_timespan * 4. The resulting
  // target should be easier (larger) than the previous one but still
  // not exceed the configured pow limit.
  const std::uint32_t very_slow_last =
      first_time + target_timespan * 16;  // will be clamped
  const std::uint32_t slow_bits = consensus::CalculateNextWorkRequired(
      previous_bits, first_time, very_slow_last, target_spacing, interval, pow_limit_bits);

  auto slow_target = consensus::CompactToTarget(slow_bits);
  auto limit_target = consensus::CompactToTarget(pow_limit_bits);

  if (CompareTargets(slow_target, prev_target) <= 0) {
    std::cerr << "Expected slow-block adjustment to produce an easier (larger) target\n";
    return false;
  }
  if (CompareTargets(slow_target, limit_target) > 0) {
    std::cerr << "Slow-block adjustment exceeded pow_limit target\n";
    return false;
  }
  return true;
}

bool TestNeverEasierThanPowLimit() {
  // When previous_bits already equals the pow limit and the measured
  // timespan suggests further easing, the next difficulty must stay
  // pinned at the pow-limit target (i.e. never easier).
  const std::uint32_t pow_limit_bits = 0x207fffffu;
  const std::uint32_t previous_bits = pow_limit_bits;
  const std::uint32_t target_spacing = 600;
  const std::uint32_t interval = 10;
  const std::uint32_t target_timespan = target_spacing * interval;

  const std::uint32_t first_time = 3'000'000u;
  const std::uint32_t last_time =
      first_time + target_timespan * 8;  // would suggest easing further

  const std::uint32_t next_bits = consensus::CalculateNextWorkRequired(
      previous_bits, first_time, last_time, target_spacing, interval, pow_limit_bits);
  auto next_target = consensus::CompactToTarget(next_bits);
  auto limit_target = consensus::CompactToTarget(pow_limit_bits);
  if (CompareTargets(next_target, limit_target) != 0) {
    std::cerr << "previous_bits=0x" << std::hex << previous_bits
              << " pow_limit_bits=0x" << pow_limit_bits
              << " next_bits=0x" << next_bits << std::dec << "\n";
    std::cerr << "Expected difficulty to remain pinned at pow-limit target\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!TestNoChangeWhenTimespanMatchesTarget()) {
    return EXIT_FAILURE;
  }
  if (!TestAdjustmentClampedForFastAndSlowBlocks()) {
    return EXIT_FAILURE;
  }
  if (!TestNeverEasierThanPowLimit()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
