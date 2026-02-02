#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>

#include "crypto/payment_code.hpp"
#include "crypto/payment_code_short.hpp"

int main() {
  qryptcoin::crypto::PaymentCodeV2 code{};
  code.network_id = 0x04030201u;
  for (std::size_t i = 0; i < code.scan_pubkey.size(); ++i) {
    code.scan_pubkey[i] = static_cast<std::uint8_t>(i & 0xFFu);
  }
  for (std::size_t i = 0; i < code.spend_root_commitment.size(); ++i) {
    code.spend_root_commitment[i] = static_cast<std::uint8_t>((0xA0u + i) & 0xFFu);
  }

  const auto short_id = qryptcoin::crypto::PaymentCodeShortId::FromPaymentCodeV2(code);
  const std::string encoded =
      qryptcoin::crypto::EncodePaymentCodeShortId(short_id, /*network_hrp=*/"qry");

  qryptcoin::crypto::PaymentCodeShortId decoded{};
  std::string error;
  if (!qryptcoin::crypto::DecodePaymentCodeShortId(encoded, /*expected_network_hrp=*/"qry",
                                                   &decoded, &error)) {
    std::cerr << "DecodePaymentCodeShortId failed: " << error << "\n";
    return EXIT_FAILURE;
  }
  if (decoded.id != short_id.id) {
    std::cerr << "Short id round-trip mismatch\n";
    return EXIT_FAILURE;
  }
  if (encoded.rfind("qrypid1", 0) != 0) {
    std::cerr << "Unexpected prefix for encoded short id: " << encoded << "\n";
    return EXIT_FAILURE;
  }

  qryptcoin::crypto::PaymentCodeShortId wrong_net{};
  if (qryptcoin::crypto::DecodePaymentCodeShortId(encoded, /*expected_network_hrp=*/"tqry",
                                                  &wrong_net, &error)) {
    std::cerr << "DecodePaymentCodeShortId unexpectedly accepted mismatched network prefix\n";
    return EXIT_FAILURE;
  }

  qryptcoin::crypto::PaymentCodeV2 mutated = code;
  mutated.spend_root_commitment[0] ^= 0x01;
  const auto mutated_id = qryptcoin::crypto::PaymentCodeShortId::FromPaymentCodeV2(mutated);
  if (mutated_id.id == short_id.id) {
    std::cerr << "Short id did not change after mutating payment code payload\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

