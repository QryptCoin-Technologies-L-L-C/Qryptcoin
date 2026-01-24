#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <oqs/oqs.h>

#include "crypto/crypto_suite.hpp"

namespace qryptcoin::crypto {

inline constexpr std::string_view kConsensusKyberId = OQS_KEM_alg_ml_kem_768;

class QPqDilithiumKey {
 public:
  QPqDilithiumKey() = default;
  ~QPqDilithiumKey();
  QPqDilithiumKey(const QPqDilithiumKey&) = delete;
  QPqDilithiumKey& operator=(const QPqDilithiumKey&) = delete;
  QPqDilithiumKey(QPqDilithiumKey&&) noexcept;
  QPqDilithiumKey& operator=(QPqDilithiumKey&&) noexcept;

  static QPqDilithiumKey Generate();
  static QPqDilithiumKey Import(std::span<const std::uint8_t> secret_key,
                                std::span<const std::uint8_t> public_key);

  std::vector<std::uint8_t> Sign(std::span<const std::uint8_t> message) const;
  bool Verify(std::span<const std::uint8_t> message,
              std::span<const std::uint8_t> signature) const;

  std::span<const std::uint8_t> PublicKey() const noexcept { return public_key_; }
  std::span<const std::uint8_t> SecretKey() const noexcept { return secret_key_; }

 private:
  QPqDilithiumKey(std::vector<std::uint8_t> secret_key, std::vector<std::uint8_t> public_key);

  std::vector<std::uint8_t> secret_key_;
  std::vector<std::uint8_t> public_key_;
};

struct KyberEncapsulationResult {
  std::vector<std::uint8_t> ciphertext;
  std::vector<std::uint8_t> shared_secret;
};

class QPqKyberKEM {
 public:
  QPqKyberKEM() = default;
  ~QPqKyberKEM();
  QPqKyberKEM(const QPqKyberKEM&) = delete;
  QPqKyberKEM& operator=(const QPqKyberKEM&) = delete;
  QPqKyberKEM(QPqKyberKEM&&) noexcept;
  QPqKyberKEM& operator=(QPqKyberKEM&&) noexcept;

  static QPqKyberKEM Generate();
  static KyberEncapsulationResult Encapsulate(std::span<const std::uint8_t> peer_public_key);

  std::vector<std::uint8_t> Decapsulate(std::span<const std::uint8_t> ciphertext) const;

  std::span<const std::uint8_t> PublicKey() const noexcept { return public_key_; }
  std::span<const std::uint8_t> SecretKey() const noexcept { return secret_key_; }

 private:
  QPqKyberKEM(std::vector<std::uint8_t> secret_key, std::vector<std::uint8_t> public_key);

  std::vector<std::uint8_t> secret_key_;
  std::vector<std::uint8_t> public_key_;
};

std::size_t DilithiumPublicKeySize();
std::size_t DilithiumSecretKeySize();
std::size_t DilithiumSignatureSize();
bool VerifySignature(SignatureAlgorithm algorithm, std::span<const std::uint8_t> message,
                     std::span<const std::uint8_t> signature,
                     std::span<const std::uint8_t> public_key);
std::size_t KyberPublicKeySize();
std::size_t KyberCiphertextSize();
std::size_t KyberSharedSecretSize();

}  // namespace qryptcoin::crypto
