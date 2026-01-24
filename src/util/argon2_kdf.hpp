#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace qryptcoin::util {

struct Argon2idParams {
  std::uint32_t t_cost;        // iterations
  std::uint32_t m_cost_kib;    // memory in KiB
  std::uint32_t parallelism;   // lanes
};

// Recommended default parameters for desktop usage.
Argon2idParams DefaultArgon2idParams();

// Derive a 32-byte key using Argon2id. Returns true on success.
bool DeriveKeyArgon2id(const std::string& password,
                       std::span<const std::uint8_t> salt,
                       const Argon2idParams& params,
                       std::vector<std::uint8_t>* key_out);

}  // namespace qryptcoin::util

