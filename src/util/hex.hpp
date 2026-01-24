#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace qryptcoin::util {

std::string HexEncode(std::span<const std::uint8_t> data);
std::string HexEncodeUpper(std::span<const std::uint8_t> data);
bool HexDecode(std::string_view hex, std::vector<std::uint8_t>* out);

}  // namespace qryptcoin::util

