#pragma once

#include <cstddef>

namespace qryptcoin::crypto {

// Consensus-fixed ML-DSA-65 (Dilithium3) parameter sizes.
inline constexpr std::size_t kMldsa65PublicKeyBytes = 1952;
inline constexpr std::size_t kMldsa65SecretKeyBytes = 4032;
inline constexpr std::size_t kMldsa65SignatureBytes = 3309;

// Protocol-fixed ML-KEM-768 (Kyber768) parameter sizes.
inline constexpr std::size_t kMlkem768PublicKeyBytes = 1184;
inline constexpr std::size_t kMlkem768SecretKeyBytes = 2400;
inline constexpr std::size_t kMlkem768CiphertextBytes = 1088;
inline constexpr std::size_t kMlkem768SharedSecretBytes = 32;

}  // namespace qryptcoin::crypto
