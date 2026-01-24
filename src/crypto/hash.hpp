#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace qryptcoin::crypto {

using Sha3_256Hash = std::array<std::uint8_t, 32>;
using Sha3_512Hash = std::array<std::uint8_t, 64>;
using Sha256Hash = std::array<std::uint8_t, 32>;

Sha3_256Hash Sha3_256(std::span<const std::uint8_t> data);
Sha3_512Hash Sha3_512(std::span<const std::uint8_t> data);
Sha3_256Hash DoubleSha3_256(std::span<const std::uint8_t> data);

// Standard FIPS-180-4 SHA-256 used for proof-of-work and other double-hash
// constructions in the protocol.
Sha256Hash Sha256(std::span<const std::uint8_t> data);
Sha256Hash DoubleSha256(std::span<const std::uint8_t> data);

std::vector<std::uint8_t> Sha3_256Vector(std::span<const std::uint8_t> data);

}  // namespace qryptcoin::crypto
