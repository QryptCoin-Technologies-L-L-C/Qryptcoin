#include "crypto/payment_code_short.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "crypto/hash.hpp"

namespace qryptcoin::crypto {

namespace {

constexpr std::string_view kBase32Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

constexpr std::array<int, 128> BuildBase32DecodeMap() {
  std::array<int, 128> map{};
  map.fill(-1);
  for (std::size_t i = 0; i < kBase32Alphabet.size(); ++i) {
    map[static_cast<unsigned char>(kBase32Alphabet[i])] = static_cast<int>(i);
  }
  return map;
}

constexpr auto kBase32DecodeMap = BuildBase32DecodeMap();

bool IsAllLowercaseAscii(std::string_view text) {
  for (unsigned char c : text) {
    if (std::isupper(c)) {
      return false;
    }
    if (c < 0x21 || c > 0x7e) {
      return false;
    }
  }
  return true;
}

std::string Base32EncodeLower(std::span<const std::uint8_t> data) {
  std::string out;
  out.reserve((data.size() * 8 + 4) / 5);
  std::uint32_t buffer = 0;
  int bits = 0;
  for (std::uint8_t byte : data) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      const std::uint8_t value = static_cast<std::uint8_t>((buffer >> bits) & 0x1f);
      out.push_back(kBase32Alphabet[value]);
    }
  }
  if (bits != 0) {
    const std::uint8_t value = static_cast<std::uint8_t>((buffer << (5 - bits)) & 0x1f);
    out.push_back(kBase32Alphabet[value]);
  }
  return out;
}

bool Base32DecodeLower(std::string_view text, std::vector<std::uint8_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  if (text.empty()) {
    return false;
  }
  std::uint32_t buffer = 0;
  int bits = 0;
  out->reserve((text.size() * 5) / 8);
  for (unsigned char c : text) {
    if (c >= 128) {
      return false;
    }
    if (std::isupper(c)) {
      return false;
    }
    const int value = kBase32DecodeMap[c];
    if (value < 0) {
      return false;
    }
    buffer = (buffer << 5) | static_cast<std::uint32_t>(value);
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out->push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xff));
    }
  }
  if (bits == 0) {
    return true;
  }
  const std::uint32_t mask = (static_cast<std::uint32_t>(1u) << bits) - 1u;
  return (buffer & mask) == 0u;
}

}  // namespace

PaymentCodeShortId PaymentCodeShortId::FromPaymentCodeV2(const PaymentCodeV2& code) {
  const auto payload = SerializePaymentCodeV2(code);
  constexpr std::string_view kTag = "QRY-PAYCODE-SHORTID-V1";
  std::vector<std::uint8_t> preimage;
  preimage.reserve(kTag.size() + payload.size());
  preimage.insert(preimage.end(), kTag.begin(), kTag.end());
  preimage.insert(preimage.end(), payload.begin(), payload.end());
  const auto digest = Sha3_256(preimage);

  PaymentCodeShortId out{};
  std::copy_n(digest.begin(), out.id.size(), out.id.begin());
  return out;
}

std::string PaymentCodeShortIdHrp(std::string_view network_hrp) {
  std::string hrp(network_hrp);
  hrp.append("pid");
  return hrp;
}

std::string EncodePaymentCodeShortId(const PaymentCodeShortId& id, std::string_view network_hrp) {
  std::string out = PaymentCodeShortIdHrp(network_hrp);
  out.push_back('1');
  out += Base32EncodeLower(std::span<const std::uint8_t>(id.id.data(), id.id.size()));
  return out;
}

bool DecodePaymentCodeShortId(std::string_view text, std::string_view expected_network_hrp,
                              PaymentCodeShortId* out, std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) *error = "invalid output pointer";
    return false;
  }
  if (text.size() < 8) {
    if (error) *error = "short id too short";
    return false;
  }
  if (!IsAllLowercaseAscii(text)) {
    if (error) *error = "short id must be lowercase ASCII";
    return false;
  }
  const auto sep = text.find('1');
  if (sep == std::string_view::npos || sep == 0 || sep + 1 >= text.size()) {
    if (error) *error = "missing separator";
    return false;
  }
  const auto hrp = text.substr(0, sep);
  const auto expected_hrp = PaymentCodeShortIdHrp(expected_network_hrp);
  if (!expected_network_hrp.empty() && hrp != expected_hrp) {
    if (error) *error = "network prefix mismatch";
    return false;
  }
  const auto data = text.substr(sep + 1);
  std::vector<std::uint8_t> decoded;
  if (!Base32DecodeLower(data, &decoded)) {
    if (error) *error = "invalid base32 payload";
    return false;
  }
  if (decoded.size() != out->id.size()) {
    if (error) *error = "invalid decoded length";
    return false;
  }
  std::copy(decoded.begin(), decoded.end(), out->id.begin());
  return true;
}

}  // namespace qryptcoin::crypto

