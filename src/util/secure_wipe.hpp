#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace qryptcoin::util {

// Securely overwrite memory so the compiler cannot optimize the wipe away.
void SecureWipe(void* data, std::size_t size) noexcept;

inline void SecureWipe(std::span<std::uint8_t> data) noexcept {
  SecureWipe(data.data(), data.size());
}

inline void SecureWipe(std::vector<std::uint8_t>& data) noexcept {
  SecureWipe(data.data(), data.size());
  std::vector<std::uint8_t>().swap(data);
}

inline void SecureWipe(std::string& data) noexcept {
  SecureWipe(data.data(), data.size());
  std::string().swap(data);
}

template <typename T, std::size_t N>
inline void SecureWipe(std::array<T, N>& data) noexcept {
  SecureWipe(data.data(), data.size() * sizeof(T));
}

}  // namespace qryptcoin::util

