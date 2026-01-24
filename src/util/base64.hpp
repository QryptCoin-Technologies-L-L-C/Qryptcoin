#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace qryptcoin::util {

std::string Base64Encode(std::span<const std::uint8_t> input);

// Strict-ish base64 decoder: rejects non-base64 characters, but ignores
// ASCII whitespace. Padding '=' is permitted.
bool Base64Decode(std::string_view input, std::vector<std::uint8_t>* out);

}  // namespace qryptcoin::util

