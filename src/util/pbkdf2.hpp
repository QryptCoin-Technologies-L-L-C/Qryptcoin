#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace qryptcoin::util {

// Derive a key using PBKDF2-HMAC-SHA512 as specified in RFC 8018.
// - password: UTF-8 password
// - salt: arbitrary salt bytes
// - iterations: number of iterations (c >= 1)
// - dk_len: length of derived key in bytes
//
// Returns dk_len bytes of key material.
std::vector<std::uint8_t> Pbkdf2HmacSha512(const std::string& password,
                                           std::span<const std::uint8_t> salt,
                                           std::uint32_t iterations,
                                           std::size_t dk_len);

}  // namespace qryptcoin::util

