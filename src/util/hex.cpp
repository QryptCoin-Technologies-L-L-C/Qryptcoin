#include "util/hex.hpp"

#include <cctype>

namespace qryptcoin::util {

namespace {

constexpr char kHexLower[] = "0123456789abcdef";
constexpr char kHexUpper[] = "0123456789ABCDEF";

std::string HexEncodeInternal(std::span<const std::uint8_t> data, const char* alphabet) {
  std::string out;
  out.resize(data.size() * 2);
  for (std::size_t i = 0; i < data.size(); ++i) {
    const auto byte = data[i];
    out[i * 2] = alphabet[(byte >> 4) & 0x0F];
    out[i * 2 + 1] = alphabet[byte & 0x0F];
  }
  return out;
}

}  // namespace

std::string HexEncode(std::span<const std::uint8_t> data) {
  return HexEncodeInternal(data, kHexLower);
}

std::string HexEncodeUpper(std::span<const std::uint8_t> data) {
  return HexEncodeInternal(data, kHexUpper);
}

bool HexDecode(std::string_view hex, std::vector<std::uint8_t>* out) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  out->clear();
  out->reserve(hex.size() / 2);
  auto from_hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    int hi = from_hex(hex[i]);
    int lo = from_hex(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      out->clear();
      return false;
    }
    out->push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return true;
}

}  // namespace qryptcoin::util

