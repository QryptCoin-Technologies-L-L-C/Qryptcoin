#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "crypto/p2qh_descriptor.hpp"
#include "crypto/payment_code.hpp"

namespace qryptcoin::crypto {

struct StealthDerivationV1 {
  std::array<std::uint8_t, 4> counter{};
  std::array<std::uint8_t, 32> key_seed{};
  std::vector<std::uint8_t> reveal;
  crypto::P2QHDescriptor descriptor;
};

// Deterministically derive a one-time P2QH descriptor from:
// - shared_secret: 32-byte ML-KEM shared secret (sender/recipient)
// - recipient_code: PaymentCodeV2 of the recipient
// - ciphertext: ML-KEM ciphertext (carried on-chain)
//
// The returned `key_seed` can be stored by the recipient to regenerate the
// one-time Dilithium keypair needed to spend the output.
bool DeriveStealthOutputV1(std::span<const std::uint8_t> shared_secret,
                           const PaymentCodeV2& recipient_code,
                           std::span<const std::uint8_t> ciphertext,
                           StealthDerivationV1* out,
                           std::string* error = nullptr);

}  // namespace qryptcoin::crypto

