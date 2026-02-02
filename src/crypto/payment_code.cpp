#include "crypto/payment_code.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <vector>

#include "crypto/hash.hpp"

namespace qryptcoin::crypto {

namespace {

constexpr std::array<std::uint8_t, 6> kMagicV1 = {'Q', 'R', 'Y', 'P', 'C', '1'};
constexpr std::uint8_t kVersionV1 = 0x01;
constexpr std::uint8_t kKdfIdSha3 = 0x01;

constexpr std::size_t kOffsetMagic = 0;
constexpr std::size_t kOffsetVersion = kOffsetMagic + kMagicV1.size();
constexpr std::size_t kOffsetNetwork = kOffsetVersion + 1;
constexpr std::size_t kOffsetKdf = kOffsetNetwork + 4;
constexpr std::size_t kOffsetScan = kOffsetKdf + 1;
constexpr std::size_t kOffsetSpend = kOffsetScan + 32;
constexpr std::size_t kOffsetChecksum = kOffsetSpend + 32;
static_assert(kOffsetChecksum + 4 == kPaymentCodeV1PayloadSize);

constexpr std::array<std::uint8_t, 6> kMagicV2 = {'Q', 'R', 'Y', 'P', 'C', '2'};
constexpr std::uint8_t kVersionV2 = 0x02;

constexpr std::size_t kOffsetV2Magic = 0;
constexpr std::size_t kOffsetV2Version = kOffsetV2Magic + kMagicV2.size();
constexpr std::size_t kOffsetV2Network = kOffsetV2Version + 1;
constexpr std::size_t kOffsetV2Scan = kOffsetV2Network + 4;
constexpr std::size_t kOffsetV2Spend = kOffsetV2Scan + kMlkem768PublicKeyBytes;
constexpr std::size_t kOffsetV2Checksum = kOffsetV2Spend + 32;
static_assert(kOffsetV2Checksum + 4 == kPaymentCodeV2PayloadSize);

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
  // RFC 4648 base32 without padding: allow leftover bits as long as they
  // are zero (canonical zero padding).
  const std::uint32_t mask = (static_cast<std::uint32_t>(1u) << bits) - 1u;
  return (buffer & mask) == 0u;
}

std::uint32_t ReadUint32LE(std::span<const std::uint8_t> data) {
  return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
         (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
}

void WriteUint32LE(std::uint32_t value, std::uint8_t* out) {
  out[0] = static_cast<std::uint8_t>(value & 0xff);
  out[1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
  out[2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
  out[3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
}

}  // namespace

std::array<std::uint8_t, kPaymentCodeV1PayloadSize> SerializePaymentCodeV1(
    const PaymentCodeV1& code) {
  std::array<std::uint8_t, kPaymentCodeV1PayloadSize> payload{};
  std::copy(kMagicV1.begin(), kMagicV1.end(), payload.begin() + kOffsetMagic);
  payload[kOffsetVersion] = kVersionV1;
  WriteUint32LE(code.network_id, payload.data() + kOffsetNetwork);
  payload[kOffsetKdf] = code.kdf_id;
  std::copy(code.scan_pubkey.begin(), code.scan_pubkey.end(), payload.begin() + kOffsetScan);
  std::copy(code.spend_root_commitment.begin(), code.spend_root_commitment.end(),
            payload.begin() + kOffsetSpend);
  const auto digest = Sha3_256(std::span<const std::uint8_t>(payload.data(), kOffsetChecksum));
  std::copy(digest.begin(), digest.begin() + 4, payload.begin() + kOffsetChecksum);
  return payload;
}

bool ParsePaymentCodeV1(std::span<const std::uint8_t> payload, PaymentCodeV1* out,
                        std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) *error = "invalid output pointer";
    return false;
  }
  if (payload.size() != kPaymentCodeV1PayloadSize) {
    if (error) *error = "invalid payload length";
    return false;
  }
  if (!std::equal(kMagicV1.begin(), kMagicV1.end(), payload.begin() + kOffsetMagic)) {
    if (error) *error = "invalid magic";
    return false;
  }
  if (payload[kOffsetVersion] != kVersionV1) {
    if (error) *error = "unsupported version";
    return false;
  }
  const auto network_id = ReadUint32LE(payload.subspan(kOffsetNetwork, 4));
  const auto kdf_id = payload[kOffsetKdf];
  if (kdf_id != kKdfIdSha3) {
    if (error) *error = "unsupported kdf_id";
    return false;
  }
  const auto digest = Sha3_256(payload.subspan(0, kOffsetChecksum));
  if (!std::equal(digest.begin(), digest.begin() + 4, payload.begin() + kOffsetChecksum)) {
    if (error) *error = "checksum mismatch";
    return false;
  }
  out->network_id = network_id;
  out->kdf_id = kdf_id;
  std::copy(payload.begin() + kOffsetScan, payload.begin() + kOffsetScan + 32,
            out->scan_pubkey.begin());
  std::copy(payload.begin() + kOffsetSpend, payload.begin() + kOffsetSpend + 32,
            out->spend_root_commitment.begin());
  return true;
}

std::array<std::uint8_t, kPaymentCodeV2PayloadSize> SerializePaymentCodeV2(
    const PaymentCodeV2& code) {
  std::array<std::uint8_t, kPaymentCodeV2PayloadSize> payload{};
  std::copy(kMagicV2.begin(), kMagicV2.end(), payload.begin() + kOffsetV2Magic);
  payload[kOffsetV2Version] = kVersionV2;
  WriteUint32LE(code.network_id, payload.data() + kOffsetV2Network);
  std::copy(code.scan_pubkey.begin(), code.scan_pubkey.end(), payload.begin() + kOffsetV2Scan);
  std::copy(code.spend_root_commitment.begin(), code.spend_root_commitment.end(),
            payload.begin() + kOffsetV2Spend);
  const auto digest = Sha3_256(std::span<const std::uint8_t>(payload.data(), kOffsetV2Checksum));
  std::copy(digest.begin(), digest.begin() + 4, payload.begin() + kOffsetV2Checksum);
  return payload;
}

bool ParsePaymentCodeV2(std::span<const std::uint8_t> payload, PaymentCodeV2* out,
                        std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) *error = "invalid output pointer";
    return false;
  }
  if (payload.size() != kPaymentCodeV2PayloadSize) {
    if (error) *error = "invalid payload length";
    return false;
  }
  if (!std::equal(kMagicV2.begin(), kMagicV2.end(), payload.begin() + kOffsetV2Magic)) {
    if (error) *error = "invalid magic";
    return false;
  }
  if (payload[kOffsetV2Version] != kVersionV2) {
    if (error) *error = "unsupported version";
    return false;
  }
  const auto digest = Sha3_256(payload.subspan(0, kOffsetV2Checksum));
  if (!std::equal(digest.begin(), digest.begin() + 4, payload.begin() + kOffsetV2Checksum)) {
    if (error) *error = "checksum mismatch";
    return false;
  }
  out->network_id = ReadUint32LE(payload.subspan(kOffsetV2Network, 4));
  std::copy(payload.begin() + kOffsetV2Scan,
            payload.begin() + kOffsetV2Scan + kMlkem768PublicKeyBytes,
            out->scan_pubkey.begin());
  std::copy(payload.begin() + kOffsetV2Spend, payload.begin() + kOffsetV2Spend + 32,
            out->spend_root_commitment.begin());
  return true;
}

std::string PaymentCodeHrp(std::string_view network_hrp) {
  std::string hrp(network_hrp);
  hrp.append("pay");
  return hrp;
}

std::string EncodePaymentCodeV1(const PaymentCodeV1& code, std::string_view network_hrp) {
  const auto payload = SerializePaymentCodeV1(code);
  std::string out = PaymentCodeHrp(network_hrp);
  out.push_back('1');
  out += Base32EncodeLower(payload);
  return out;
}

bool DecodePaymentCodeV1(std::string_view text, std::string_view expected_network_hrp,
                         PaymentCodeV1* out, std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) *error = "invalid output pointer";
    return false;
  }
  if (text.size() < 16) {
    if (error) *error = "payment code too short";
    return false;
  }
  if (!IsAllLowercaseAscii(text)) {
    if (error) *error = "payment code must be lowercase ASCII";
    return false;
  }
  const auto sep = text.find('1');
  if (sep == std::string_view::npos || sep == 0 || sep + 1 >= text.size()) {
    if (error) *error = "missing separator";
    return false;
  }
  const auto hrp = text.substr(0, sep);
  const auto expected_hrp = PaymentCodeHrp(expected_network_hrp);
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
  if (decoded.size() != kPaymentCodeV1PayloadSize) {
    if (error) *error = "invalid decoded payload size";
    return false;
  }
  PaymentCodeV1 parsed{};
  std::string parse_error;
  if (!ParsePaymentCodeV1(decoded, &parsed, &parse_error)) {
    if (error) *error = parse_error.empty() ? "invalid payment code payload" : parse_error;
    return false;
  }
  *out = parsed;
  return true;
}

std::string EncodePaymentCodeV2(const PaymentCodeV2& code, std::string_view network_hrp) {
  const auto payload = SerializePaymentCodeV2(code);
  std::string out = PaymentCodeHrp(network_hrp);
  out.push_back('1');
  out += Base32EncodeLower(payload);
  return out;
}

bool DecodePaymentCodeV2(std::string_view text, std::string_view expected_network_hrp,
                         PaymentCodeV2* out, std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) *error = "invalid output pointer";
    return false;
  }
  if (text.size() < 16) {
    if (error) *error = "payment code too short";
    return false;
  }
  if (!IsAllLowercaseAscii(text)) {
    if (error) *error = "payment code must be lowercase ASCII";
    return false;
  }
  const auto sep = text.find('1');
  if (sep == std::string_view::npos || sep == 0 || sep + 1 >= text.size()) {
    if (error) *error = "missing separator";
    return false;
  }
  const auto hrp = text.substr(0, sep);
  const auto expected_hrp = PaymentCodeHrp(expected_network_hrp);
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
  if (decoded.size() != kPaymentCodeV2PayloadSize) {
    if (error) *error = "invalid decoded payload size";
    return false;
  }
  PaymentCodeV2 parsed{};
  std::string parse_error;
  if (!ParsePaymentCodeV2(decoded, &parsed, &parse_error)) {
    if (error) *error = parse_error.empty() ? "invalid payment code payload" : parse_error;
    return false;
  }
  *out = parsed;
  return true;
}

}  // namespace qryptcoin::crypto

