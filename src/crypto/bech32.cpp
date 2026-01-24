#include "crypto/bech32.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

namespace qryptcoin::crypto {

namespace {

constexpr std::array<char, 32> kCharset = {
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0',
    's', '3', 'j', 'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l'};

constexpr std::array<int, 128> CreateDecodeMap() {
  std::array<int, 128> map{};
  map.fill(-1);
  for (std::size_t i = 0; i < kCharset.size(); ++i) {
    map[static_cast<unsigned>(kCharset[i])] = static_cast<int>(i);
  }
  return map;
}

constexpr auto kDecodeMap = CreateDecodeMap();
constexpr std::uint32_t kBech32mConstant = 0x2bc830a3;

std::uint32_t Polymod(const std::vector<std::uint8_t>& values) {
  std::uint32_t chk = 1;
  for (std::uint8_t v : values) {
    std::uint8_t top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ v;
    if (top & 0x01) chk ^= 0x3b6a57b2;
    if (top & 0x02) chk ^= 0x26508e6d;
    if (top & 0x04) chk ^= 0x1ea119fa;
    if (top & 0x08) chk ^= 0x3d4233dd;
    if (top & 0x10) chk ^= 0x2a1462b3;
  }
  return chk;
}

std::vector<std::uint8_t> HrpExpand(std::string_view hrp) {
  std::vector<std::uint8_t> ret;
  ret.reserve(hrp.size() * 2 + 1);
  for (char c : hrp) {
    ret.push_back(static_cast<std::uint8_t>(std::tolower(static_cast<unsigned char>(c)) >> 5));
  }
  ret.push_back(0);
  for (char c : hrp) {
    ret.push_back(static_cast<std::uint8_t>(std::tolower(static_cast<unsigned char>(c)) & 0x1F));
  }
  return ret;
}

bool ConvertBits(std::vector<std::uint8_t>* out, int from_bits, int to_bits, bool pad,
                 std::span<const std::uint8_t> data) {
  std::uint32_t acc = 0;
  int bits = 0;
  const std::uint32_t maxv = (1u << to_bits) - 1;
  for (std::uint8_t value : data) {
    if (value >> from_bits) {
      return false;
    }
    acc = (acc << from_bits) | value;
    bits += from_bits;
    while (bits >= to_bits) {
      bits -= to_bits;
      out->push_back(static_cast<std::uint8_t>((acc >> bits) & maxv));
    }
  }
  if (pad) {
    if (bits) {
      out->push_back(static_cast<std::uint8_t>((acc << (to_bits - bits)) & maxv));
    }
  } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv)) {
    return false;
  }
  return true;
}

bool IsValidHrp(std::string_view hrp) {
  if (hrp.size() < 1 || hrp.size() > 83) {
    return false;
  }
  for (char c : hrp) {
    if (c < 0x21 || c > 0x7E) return false;
  }
  return true;
}

}  // namespace

std::string EncodeBech32m(std::string_view hrp, uint8_t witness_version,
                          std::span<const std::uint8_t> program) {
  if (!IsValidHrp(hrp)) {
    throw std::invalid_argument("Invalid HRP");
  }
  if (witness_version > 16) {
    throw std::invalid_argument("Invalid witness version");
  }
  std::vector<std::uint8_t> data;
  data.reserve(program.size() + 1);
  data.push_back(witness_version);
  std::vector<std::uint8_t> converted;
  if (!ConvertBits(&converted, 8, 5, true, program)) {
    throw std::invalid_argument("Invalid witness program");
  }
  data.insert(data.end(), converted.begin(), converted.end());

  auto hrp_expanded = HrpExpand(hrp);
  std::vector<std::uint8_t> values = hrp_expanded;
  values.insert(values.end(), data.begin(), data.end());
  values.insert(values.end(), 6, 0);
  std::uint32_t polymod = Polymod(values) ^ kBech32mConstant;
  std::string ret;
  ret.reserve(hrp.size() + data.size() + 8);
  ret.append(hrp);
  ret.push_back('1');
  for (std::uint8_t v : data) {
    ret.push_back(kCharset[v]);
  }
  for (int i = 0; i < 6; ++i) {
    ret.push_back(kCharset[(polymod >> (5 * (5 - i))) & 31]);
  }
  return ret;
}

bool DecodeBech32m(std::string_view address, std::string_view expected_hrp, uint8_t* witness_version,
                   std::vector<std::uint8_t>* program) {
  if (address.size() < 8 || address.size() > 90) {
    return false;
  }
  bool lower = false;
  bool upper = false;
  for (char c : address) {
    if (std::isupper(static_cast<unsigned char>(c))) upper = true;
    if (std::islower(static_cast<unsigned char>(c))) lower = true;
  }
  if (upper && lower) {
    return false;
  }
  auto pos = address.rfind('1');
  if (pos == std::string_view::npos || pos < expected_hrp.size() || pos + 7 > address.size()) {
    return false;
  }
  std::string_view hrp = address.substr(0, pos);
  std::string_view data_part = address.substr(pos + 1);
  if (!IsValidHrp(hrp)) {
    return false;
  }
  if (!expected_hrp.empty()) {
    if (hrp.size() != expected_hrp.size()) {
      return false;
    }
    if (!std::equal(hrp.begin(), hrp.end(), expected_hrp.begin(), expected_hrp.end(),
                    [](char a, char b) {
                      return std::tolower(static_cast<unsigned char>(a)) ==
                             std::tolower(static_cast<unsigned char>(b));
                    })) {
      return false;
    }
  }
  std::vector<std::uint8_t> data;
  data.reserve(data_part.size());
  for (char c : data_part) {
    if (static_cast<unsigned char>(c) > 127 || kDecodeMap[static_cast<unsigned>(c)] == -1) {
      return false;
    }
    data.push_back(static_cast<std::uint8_t>(kDecodeMap[static_cast<unsigned>(c)]));
  }
  if (data.size() < 7) {  // version + 6 checksum values
    return false;
  }
  std::vector<std::uint8_t> hrp_expanded = HrpExpand(hrp);
  std::vector<std::uint8_t> verify_values = hrp_expanded;
  verify_values.insert(verify_values.end(), data.begin(), data.end());
  if (Polymod(verify_values) != kBech32mConstant) {
    return false;
  }
  data.resize(data.size() - 6);  // drop checksum
  if (data.empty()) {
    return false;
  }
  *witness_version = data.front();
  if (*witness_version > 16) {
    return false;
  }
  std::vector<std::uint8_t> decoded;
  if (!ConvertBits(&decoded, 5, 8, false,
                   std::span<const std::uint8_t>(data.begin() + 1, data.end()))) {
    return false;
  }
  program->assign(decoded.begin(), decoded.end());
  return true;
}

}  // namespace qryptcoin::crypto
