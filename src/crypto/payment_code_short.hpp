#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "crypto/payment_code.hpp"

namespace qryptcoin::crypto {

struct PaymentCodeShortId {
  std::array<std::uint8_t, 16> id{};

  static PaymentCodeShortId FromPaymentCodeV2(const PaymentCodeV2& code);
};

std::string PaymentCodeShortIdHrp(std::string_view network_hrp);
std::string EncodePaymentCodeShortId(const PaymentCodeShortId& id, std::string_view network_hrp);
bool DecodePaymentCodeShortId(std::string_view text, std::string_view expected_network_hrp,
                              PaymentCodeShortId* out, std::string* error = nullptr);

}  // namespace qryptcoin::crypto

