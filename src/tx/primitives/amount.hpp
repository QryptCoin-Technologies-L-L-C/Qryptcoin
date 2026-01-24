#pragma once

#include <cstdint>

namespace qryptcoin::primitives {

using Amount = std::uint64_t;  // Amounts denominated in Miks (1e-8 QRY).

inline constexpr Amount kMiksPerQRY = 100'000'000ULL;
inline constexpr Amount kMaxMoney = 21'000'000ULL * kMiksPerQRY;

inline constexpr bool MoneyRange(Amount value) noexcept { return value <= kMaxMoney; }

inline bool CheckedAdd(Amount a, Amount b, Amount* out) noexcept {
  if (!MoneyRange(a) || !MoneyRange(b)) {
    return false;
  }
  if (a > kMaxMoney - b) {
    return false;
  }
  if (out) {
    *out = a + b;
  }
  return true;
}

inline bool CheckedSub(Amount a, Amount b, Amount* out) noexcept {
  if (!MoneyRange(a) || !MoneyRange(b)) {
    return false;
  }
  if (b > a) {
    return false;
  }
  if (out) {
    *out = a - b;
  }
  return true;
}

inline bool CheckedMul(Amount a, std::uint64_t b, Amount* out) noexcept {
  if (!MoneyRange(a)) {
    return false;
  }
  if (b == 0) {
    if (out) {
      *out = 0;
    }
    return true;
  }
  if (a > kMaxMoney / b) {
    return false;
  }
  if (out) {
    *out = static_cast<Amount>(a * b);
  }
  return true;
}

}  // namespace qryptcoin::primitives
