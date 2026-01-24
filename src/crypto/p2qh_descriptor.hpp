#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "crypto/crypto_suite.hpp"
#include "primitives/hash.hpp"

namespace qryptcoin::crypto {

struct P2QHDescriptor {
  std::uint8_t version{0x01};
  SignatureAlgorithm algorithm{SignatureAlgorithm::kDilithium};
  std::uint8_t params_id{0x01};
  std::uint16_t reserved{0x0000};
  primitives::Hash256 program{};
};

inline constexpr std::size_t kP2QHDescriptorSize = 1 + 1 + 1 + 2 + 32;

struct P2QHRevealData {
  std::uint8_t version{0x01};
  SignatureAlgorithm algorithm{SignatureAlgorithm::kDilithium};
  std::uint8_t params_id{0x01};
  std::uint16_t reserved{0x0000};
  std::vector<std::uint8_t> mldsa_public_key;
};

std::array<std::uint8_t, kP2QHDescriptorSize> SerializeP2QHDescriptor(const P2QHDescriptor& descriptor);
std::vector<std::uint8_t> BuildP2QHLockingDescriptor(const P2QHDescriptor& descriptor);
std::uint8_t EncodeSignatureAlgorithm(SignatureAlgorithm algorithm);
SignatureAlgorithm DecodeSignatureAlgorithm(std::uint8_t encoded);
bool AlgorithmRequiresDilithium(SignatureAlgorithm algorithm);

std::vector<std::uint8_t> BuildP2QHReveal(std::span<const std::uint8_t> mldsa_public_key);
P2QHDescriptor DescriptorFromReveal(std::span<const std::uint8_t> reveal);
bool ParseP2QHReveal(std::span<const std::uint8_t> reveal, P2QHRevealData* out);

}  // namespace qryptcoin::crypto
