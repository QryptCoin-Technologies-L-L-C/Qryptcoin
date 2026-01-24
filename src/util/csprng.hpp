#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace qryptcoin::util {

// Fills `out` with cryptographically secure random bytes.
bool FillSecureRandomBytes(std::span<std::uint8_t> out, std::string* error = nullptr);

// Convenience helper that aborts the process if secure randomness is unavailable.
void FillSecureRandomBytesOrAbort(std::span<std::uint8_t> out);

// Convenience helper that returns `size` secure random bytes (aborts on failure).
std::vector<std::uint8_t> SecureRandomBytes(std::size_t size);

}  // namespace qryptcoin::util

