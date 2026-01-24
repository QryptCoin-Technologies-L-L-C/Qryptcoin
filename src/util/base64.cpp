#include "util/base64.hpp"

#include <array>
#include <cctype>

namespace qryptcoin::util {

namespace {

constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr std::array<int, 256> BuildDecodeTable() {
  std::array<int, 256> table{};
  table.fill(-1);
  for (std::size_t i = 0; i < kAlphabet.size(); ++i) {
    table[static_cast<unsigned char>(kAlphabet[i])] = static_cast<int>(i);
  }
  table[static_cast<unsigned char>('=')] = -2;
  return table;
}

constexpr auto kDecodeTable = BuildDecodeTable();

}  // namespace

std::string Base64Encode(std::span<const std::uint8_t> input) {
  std::string encoded;
  encoded.reserve(((input.size() + 2) / 3) * 4);
  std::uint32_t val = 0;
  int valb = -6;
  for (std::uint8_t c : input) {
    val = (val << 8) | c;
    valb += 8;
    while (valb >= 0) {
      encoded.push_back(kAlphabet[(val >> valb) & 0x3f]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    encoded.push_back(kAlphabet[((val << 8) >> (valb + 8)) & 0x3f]);
  }
  while (encoded.size() % 4) {
    encoded.push_back('=');
  }
  return encoded;
}

bool Base64Decode(std::string_view input, std::vector<std::uint8_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  out->reserve((input.size() * 3) / 4);
  std::uint32_t val = 0;
  int valb = -8;
  bool saw_padding = false;

  for (unsigned char c : input) {
    if (std::isspace(c)) {
      continue;
    }
    const int decoded = kDecodeTable[c];
    if (decoded == -1) {
      return false;
    }
    if (decoded == -2) {
      saw_padding = true;
      continue;
    }
    if (saw_padding) {
      return false;
    }
    val = (val << 6) | static_cast<std::uint32_t>(decoded);
    valb += 6;
    if (valb >= 0) {
      out->push_back(static_cast<std::uint8_t>((val >> valb) & 0xff));
      valb -= 8;
    }
  }
  return true;
}

}  // namespace qryptcoin::util

