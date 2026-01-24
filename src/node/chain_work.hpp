#pragma once

#include <array>
#include <cstdint>
#include <limits>
#include <span>

namespace qryptcoin::node {

class ChainWork {
 public:
  ChainWork() = default;
  explicit ChainWork(std::uint64_t value) { limbs_[0] = value; }

  static ChainWork Zero() { return ChainWork(); }

  static ChainWork Max() {
    ChainWork work;
    work.limbs_.fill(std::numeric_limits<std::uint64_t>::max());
    return work;
  }

  static ChainWork FromBigEndian(std::span<const std::uint8_t, 32> bytes) {
    ChainWork work;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      const std::uint8_t byte = bytes[bytes.size() - 1 - i];
      const std::size_t limb = i / 8;
      const std::size_t shift = (i % 8) * 8;
      work.limbs_[limb] |= static_cast<std::uint64_t>(byte) << shift;
    }
    return work;
  }

  bool IsZero() const {
    for (auto limb : limbs_) {
      if (limb != 0) return false;
    }
    return true;
  }

  ChainWork& operator+=(const ChainWork& other) {
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < limbs_.size(); ++i) {
      const std::uint64_t sum = limbs_[i] + other.limbs_[i];
      const std::uint64_t carry1 = sum < limbs_[i] ? 1 : 0;
      const std::uint64_t sum2 = sum + carry;
      const std::uint64_t carry2 = sum2 < sum ? 1 : 0;
      limbs_[i] = sum2;
      carry = carry1 | carry2;
    }
    return *this;
  }

  ChainWork& operator-=(const ChainWork& other) {
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < limbs_.size(); ++i) {
      const std::uint64_t diff = limbs_[i] - other.limbs_[i];
      const std::uint64_t borrow1 = limbs_[i] < other.limbs_[i] ? 1 : 0;
      const std::uint64_t diff2 = diff - borrow;
      const std::uint64_t borrow2 = diff < borrow ? 1 : 0;
      limbs_[i] = diff2;
      borrow = borrow1 | borrow2;
    }
    return *this;
  }

  friend ChainWork operator+(ChainWork lhs, const ChainWork& rhs) {
    lhs += rhs;
    return lhs;
  }

  friend ChainWork operator-(ChainWork lhs, const ChainWork& rhs) {
    lhs -= rhs;
    return lhs;
  }

  friend bool operator==(const ChainWork& lhs, const ChainWork& rhs) {
    return lhs.limbs_ == rhs.limbs_;
  }

  friend bool operator!=(const ChainWork& lhs, const ChainWork& rhs) {
    return !(lhs == rhs);
  }

  friend bool operator<(const ChainWork& lhs, const ChainWork& rhs) {
    for (std::size_t i = lhs.limbs_.size(); i-- > 0;) {
      if (lhs.limbs_[i] < rhs.limbs_[i]) return true;
      if (lhs.limbs_[i] > rhs.limbs_[i]) return false;
    }
    return false;
  }

  friend bool operator>(const ChainWork& lhs, const ChainWork& rhs) { return rhs < lhs; }

  friend bool operator<=(const ChainWork& lhs, const ChainWork& rhs) { return !(rhs < lhs); }

  friend bool operator>=(const ChainWork& lhs, const ChainWork& rhs) { return !(lhs < rhs); }

  void ShiftLeft1() {
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < limbs_.size(); ++i) {
      const std::uint64_t next = limbs_[i] >> 63;
      limbs_[i] = (limbs_[i] << 1) | carry;
      carry = next;
    }
  }

  bool TestBit(int bit) const {
    if (bit < 0 || bit >= 256) return false;
    const std::size_t limb = static_cast<std::size_t>(bit) / 64;
    const std::size_t offset = static_cast<std::size_t>(bit) % 64;
    return (limbs_[limb] >> offset) & 1ULL;
  }

  void SetBit(int bit) {
    if (bit < 0 || bit >= 256) return;
    const std::size_t limb = static_cast<std::size_t>(bit) / 64;
    const std::size_t offset = static_cast<std::size_t>(bit) % 64;
    limbs_[limb] |= (std::uint64_t{1} << offset);
  }

 private:
  std::array<std::uint64_t, 4> limbs_{};

  friend ChainWork Divide(const ChainWork& dividend, const ChainWork& divisor);
};

inline ChainWork Divide(const ChainWork& dividend, const ChainWork& divisor) {
  if (divisor.IsZero()) {
    return ChainWork::Zero();
  }
  ChainWork quotient;
  ChainWork remainder;
  for (int bit = 255; bit >= 0; --bit) {
    remainder.ShiftLeft1();
    if (dividend.TestBit(bit)) {
      remainder.limbs_[0] |= 1ULL;
    }
    if (remainder >= divisor) {
      remainder -= divisor;
      quotient.SetBit(bit);
    }
  }
  return quotient;
}

}  // namespace qryptcoin::node
