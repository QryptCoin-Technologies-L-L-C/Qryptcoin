#include "crypto/p2qh_descriptor.hpp"

#include <algorithm>
#include <stdexcept>

#include "crypto/hash.hpp"
#include "crypto/pq_params.hpp"

namespace qryptcoin::crypto {

std::uint8_t EncodeSignatureAlgorithm(SignatureAlgorithm algo) {
  // Single on-chain signature scheme: ML-DSA-65.
  switch (algo) {
    case SignatureAlgorithm::kDilithium:
      return 0x01;
  }
  return 0xFF;
}

SignatureAlgorithm DecodeSignatureAlgorithm(std::uint8_t encoded) {
  // ML-DSA-65 only.
  switch (encoded) {
    case 0x01:
      return SignatureAlgorithm::kDilithium;
    default:
      throw std::invalid_argument("Unknown or unsupported signature algorithm id");
  }
}

bool AlgorithmRequiresDilithium(SignatureAlgorithm /*algorithm*/) {
  return true;
}

std::array<std::uint8_t, kP2QHDescriptorSize> SerializeP2QHDescriptor(
    const P2QHDescriptor& descriptor) {
  std::array<std::uint8_t, kP2QHDescriptorSize> buffer{};
  buffer[0] = descriptor.version;
  buffer[1] = EncodeSignatureAlgorithm(descriptor.algorithm);
  buffer[2] = descriptor.params_id;
  buffer[3] = static_cast<std::uint8_t>(descriptor.reserved & 0xFF);
  buffer[4] = static_cast<std::uint8_t>((descriptor.reserved >> 8) & 0xFF);
  std::copy(descriptor.program.begin(), descriptor.program.end(), buffer.begin() + 5);
  return buffer;
}

std::vector<std::uint8_t> BuildP2QHLockingDescriptor(const P2QHDescriptor& descriptor) {
  const auto serialized = SerializeP2QHDescriptor(descriptor);
  return {serialized.begin(), serialized.end()};
}

std::vector<std::uint8_t> BuildP2QHReveal(std::span<const std::uint8_t> mldsa_public_key) {
  constexpr std::size_t expected_pk_len = kMldsa65PublicKeyBytes;
  if (mldsa_public_key.size_bytes() != expected_pk_len) {
    throw std::invalid_argument("ML-DSA public key size mismatch");
  }
  std::vector<std::uint8_t> reveal;
  reveal.reserve(7 + expected_pk_len);
  reveal.push_back(0x01);  // reveal version
  reveal.push_back(EncodeSignatureAlgorithm(SignatureAlgorithm::kDilithium));
  reveal.push_back(0x01);  // params_id (Dilithium3 fixed)
  reveal.push_back(0x00);  // reserved (LE u16)
  reveal.push_back(0x00);
  const std::uint16_t len = static_cast<std::uint16_t>(expected_pk_len);
  reveal.push_back(static_cast<std::uint8_t>(len & 0xFF));
  reveal.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
  reveal.insert(reveal.end(), mldsa_public_key.begin(), mldsa_public_key.end());
  return reveal;
}

bool ParseP2QHReveal(std::span<const std::uint8_t> reveal, P2QHRevealData* out) {
  if (reveal.size() < 7 || out == nullptr) {
    return false;
  }
  P2QHRevealData data{};
  data.version = reveal[0];
  try {
    data.algorithm = DecodeSignatureAlgorithm(reveal[1]);
  } catch (const std::exception&) {
    return false;
  }
  data.params_id = reveal[2];
  data.reserved =
      static_cast<std::uint16_t>(reveal[3]) | (static_cast<std::uint16_t>(reveal[4]) << 8);
  if (data.version != 0x01 || data.params_id != 0x01 || data.reserved != 0) {
    return false;
  }
  const std::uint16_t pk_len =
      static_cast<std::uint16_t>(reveal[5]) | (static_cast<std::uint16_t>(reveal[6]) << 8);
  constexpr std::size_t expected_pk_len = kMldsa65PublicKeyBytes;
  if (pk_len != expected_pk_len) {
    return false;
  }
  if (reveal.size() != 7 + expected_pk_len) {
    return false;
  }
  data.mldsa_public_key.assign(reveal.begin() + 7, reveal.end());
  *out = std::move(data);
  return true;
}

P2QHDescriptor DescriptorFromReveal(std::span<const std::uint8_t> reveal) {
  P2QHRevealData parsed{};
  if (!ParseP2QHReveal(reveal, &parsed)) {
    throw std::invalid_argument("Invalid P2QH reveal payload");
  }
  P2QHDescriptor descriptor{};
  descriptor.version = parsed.version;
  descriptor.algorithm = parsed.algorithm;
  descriptor.params_id = parsed.params_id;
  descriptor.reserved = parsed.reserved;
  auto hash_vec = Sha3_256Vector(reveal);
  std::copy(hash_vec.begin(), hash_vec.end(), descriptor.program.begin());
  return descriptor;
}

}  // namespace qryptcoin::crypto
