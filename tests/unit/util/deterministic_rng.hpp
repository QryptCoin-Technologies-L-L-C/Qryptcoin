#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>

#include "crypto/deterministic_rng.hpp"

namespace qryptcoin::test {

class ScopedDeterministicRng {
 public:
  explicit ScopedDeterministicRng(std::uint64_t seed) {
    std::array<std::uint8_t, 32> material{};
    for (std::size_t i = 0; i < material.size(); i += sizeof(seed)) {
      std::uint64_t value = seed + static_cast<std::uint64_t>(i);
      for (std::size_t j = 0; j < sizeof(seed) && (i + j) < material.size(); ++j) {
        material[i + j] = static_cast<std::uint8_t>((value >> (j * 8)) & 0xFF);
      }
    }
    rng_ = std::make_unique<crypto::DeterministicOqsRng>(
        std::span<const std::uint8_t>(material.data(), material.size()));
  }

  ScopedDeterministicRng(const ScopedDeterministicRng&) = delete;
  ScopedDeterministicRng& operator=(const ScopedDeterministicRng&) = delete;
  ScopedDeterministicRng(ScopedDeterministicRng&&) = delete;
  ScopedDeterministicRng& operator=(ScopedDeterministicRng&&) = delete;
  ~ScopedDeterministicRng() = default;

 private:
  std::unique_ptr<crypto::DeterministicOqsRng> rng_;
};

}  // namespace qryptcoin::test
