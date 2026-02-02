#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "crypto/pq_params.hpp"

namespace qryptcoin::crypto {

struct PaymentCodeV1 {
  std::uint32_t network_id{0};
  std::uint8_t kdf_id{0x01};
  std::array<std::uint8_t, 32> scan_pubkey{};
  std::array<std::uint8_t, 32> spend_root_commitment{};
};

constexpr std::size_t kPaymentCodeV1PayloadSize = 80;

std::array<std::uint8_t, kPaymentCodeV1PayloadSize> SerializePaymentCodeV1(
    const PaymentCodeV1& code);
bool ParsePaymentCodeV1(std::span<const std::uint8_t> payload, PaymentCodeV1* out,
                        std::string* error = nullptr);

std::string PaymentCodeHrp(std::string_view network_hrp);
std::string EncodePaymentCodeV1(const PaymentCodeV1& code, std::string_view network_hrp);
bool DecodePaymentCodeV1(std::string_view text, std::string_view expected_network_hrp,
                         PaymentCodeV1* out, std::string* error = nullptr);

struct PaymentCodeV2 {
  std::uint32_t network_id{0};
  std::array<std::uint8_t, kMlkem768PublicKeyBytes> scan_pubkey{};
  std::array<std::uint8_t, 32> spend_root_commitment{};
};

constexpr std::size_t kPaymentCodeV2PayloadSize = 6 + 1 + 4 + kMlkem768PublicKeyBytes + 32 + 4;

std::array<std::uint8_t, kPaymentCodeV2PayloadSize> SerializePaymentCodeV2(
    const PaymentCodeV2& code);
bool ParsePaymentCodeV2(std::span<const std::uint8_t> payload, PaymentCodeV2* out,
                        std::string* error = nullptr);

std::string EncodePaymentCodeV2(const PaymentCodeV2& code, std::string_view network_hrp);
bool DecodePaymentCodeV2(std::string_view text, std::string_view expected_network_hrp,
                         PaymentCodeV2* out, std::string* error = nullptr);

}  // namespace qryptcoin::crypto

