#include "consensus/pow.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace qryptcoin::consensus {

namespace {

int CompareTargets(const std::array<std::uint8_t, 32>& a,
                   const std::array<std::uint8_t, 32>& b) {
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

void MultiplyTargetBy(std::array<std::uint8_t, 32>* target, std::uint32_t factor) {
  if (!target) return;
  std::uint64_t carry = 0;
  for (int i = static_cast<int>(target->size()) - 1; i >= 0; --i) {
    const std::uint64_t value =
        static_cast<std::uint64_t>((*target)[static_cast<std::size_t>(i)]) *
            static_cast<std::uint64_t>(factor) +
        carry;
    (*target)[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value & 0xFFu);
    carry = value >> 8;
  }
}

void DivideTargetBy(std::array<std::uint8_t, 32>* target, std::uint32_t divisor) {
  if (!target || divisor == 0) return;
  std::uint64_t remainder = 0;
  for (std::size_t i = 0; i < target->size(); ++i) {
    std::uint64_t value = (remainder << 8) | (*target)[i];
    (*target)[i] = static_cast<std::uint8_t>(value / divisor);
    remainder = value % divisor;
  }
}

}  // namespace

std::uint32_t TargetToCompact(const std::array<std::uint8_t, 32>& target) {
  // Find the first non-zero byte.
  std::size_t first = 0;
  while (first < target.size() && target[first] == 0) {
    ++first;
  }
  if (first == target.size()) {
    return 0;
  }
  int nSize = static_cast<int>(target.size() - first);
  std::uint32_t b0 = 0, b1 = 0, b2 = 0;
  if (nSize >= 3) {
    b0 = target[first];
    b1 = target[first + 1];
    b2 = target[first + 2];
  } else if (nSize == 2) {
    b1 = target[first];
    b2 = target[first + 1];
  } else if (nSize == 1) {
    b2 = target[first];
  }
  std::uint32_t mantissa = (b0 << 16) | (b1 << 8) | b2;
  if (mantissa & 0x00800000u) {
    mantissa >>= 8;
    ++nSize;
  }
  mantissa &= 0x007fffffu;
  return (static_cast<std::uint32_t>(nSize) << 24) | mantissa;
}

std::array<std::uint8_t, 32> CompactToTarget(std::uint32_t bits) {
  std::array<std::uint8_t, 32> target{};
  std::uint32_t exponent = bits >> 24;
  std::uint32_t mantissa = bits & 0x007fffff;
  std::vector<std::uint8_t> mant(3);
  mant[0] = static_cast<std::uint8_t>((mantissa >> 16) & 0xFFu);
  mant[1] = static_cast<std::uint8_t>((mantissa >> 8) & 0xFFu);
  mant[2] = static_cast<std::uint8_t>(mantissa & 0xFFu);
  int shift = static_cast<int>(exponent) - 3;
  int byte_index = 31 - shift;
  if (byte_index < -2) byte_index = -2;
  for (int i = 0; i < 3; ++i) {
    int idx = byte_index - i;
    if (idx >= 0 && idx < 32) {
      target[static_cast<std::size_t>(idx)] = mant[2 - i];
    }
  }
  return target;
}

bool HashMeetsTarget(const primitives::Hash256& hash,
                     const std::array<std::uint8_t, 32>& target) {
  for (std::size_t i = 0; i < hash.size(); ++i) {
    if (hash[i] < target[i]) return true;
    if (hash[i] > target[i]) return false;
  }
  return true;
}

std::uint32_t CalculateNextWorkRequired(std::uint32_t previous_bits,
                                        std::uint32_t first_timestamp,
                                        std::uint32_t last_timestamp,
                                        std::uint32_t target_spacing,
                                        std::uint32_t adjustment_interval,
                                        std::uint32_t pow_limit_bits) {
  if (adjustment_interval == 0 || target_spacing == 0) {
    return previous_bits;
  }
  const std::uint64_t target_timespan =
      static_cast<std::uint64_t>(target_spacing) *
      static_cast<std::uint64_t>(adjustment_interval);
  std::uint64_t actual_timespan = target_timespan;
  if (last_timestamp > first_timestamp) {
    actual_timespan = static_cast<std::uint64_t>(last_timestamp - first_timestamp);
  }
  const std::uint64_t min_timespan = target_timespan / 4;
  const std::uint64_t max_timespan = target_timespan * 4;
  if (actual_timespan < min_timespan) {
    actual_timespan = min_timespan;
  } else if (actual_timespan > max_timespan) {
    actual_timespan = max_timespan;
  }
  // If we are already at the easiest allowed difficulty and the
  // observed timespan would normally suggest making blocks easier,
  // keep the difficulty pinned at the pow limit instead of attempting
  // to scale the target further.
  if (previous_bits == pow_limit_bits && actual_timespan >= target_timespan) {
    return pow_limit_bits;
  }

  auto target = CompactToTarget(previous_bits);
  MultiplyTargetBy(&target, static_cast<std::uint32_t>(actual_timespan));
  DivideTargetBy(&target, static_cast<std::uint32_t>(target_timespan));

  auto pow_limit = CompactToTarget(pow_limit_bits);
  if (CompareTargets(target, pow_limit) > 0) {
    target = pow_limit;
  }
  return TargetToCompact(target);
}

}  // namespace qryptcoin::consensus

