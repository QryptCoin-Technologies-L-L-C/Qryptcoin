#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace qryptcoin::util {

constexpr std::size_t kChaCha20Poly1305KeySize = 32;
constexpr std::size_t kChaCha20Poly1305NonceSize = 12;
constexpr std::size_t kChaCha20Poly1305TagSize = 16;

std::vector<std::uint8_t> ChaCha20Poly1305Encrypt(std::span<const std::uint8_t> key,
                                                  std::span<const std::uint8_t> nonce,
                                                  std::span<const std::uint8_t> aad,
                                                  std::span<const std::uint8_t> plaintext);
bool ChaCha20Poly1305Decrypt(std::span<const std::uint8_t> key,
                             std::span<const std::uint8_t> nonce,
                             std::span<const std::uint8_t> aad,
                             std::span<const std::uint8_t> ciphertext,
                             std::vector<std::uint8_t>* plaintext);

}  // namespace qryptcoin::util

