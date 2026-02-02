#include <array>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <string>

#include "config/network.hpp"
#include "crypto/payment_code.hpp"

int main() {
  try {
    using namespace qryptcoin;

    config::SelectNetwork(config::NetworkType::kMainnet);
    const auto& cfg = config::GetNetworkConfig();

    crypto::PaymentCodeV2 code{};
    code.network_id = 0x01020304;
    code.scan_pubkey.fill(0x11);
    code.spend_root_commitment.fill(0x22);

    const auto payload = crypto::SerializePaymentCodeV2(code);
    crypto::PaymentCodeV2 parsed{};
    std::string error;
    if (!crypto::ParsePaymentCodeV2(payload, &parsed, &error)) {
      std::cerr << "ParsePaymentCodeV2 failed: " << error << "\n";
      return EXIT_FAILURE;
    }
    if (parsed.network_id != code.network_id || parsed.scan_pubkey != code.scan_pubkey ||
        parsed.spend_root_commitment != code.spend_root_commitment) {
      std::cerr << "payment code v2 payload roundtrip mismatch\n";
      return EXIT_FAILURE;
    }

    const auto text = crypto::EncodePaymentCodeV2(code, cfg.bech32_hrp);
    const std::string expected_prefix = cfg.bech32_hrp + "pay1";
    if (text.rfind(expected_prefix, 0) != 0) {
      std::cerr << "unexpected payment code prefix: " << text << "\n";
      return EXIT_FAILURE;
    }

    crypto::PaymentCodeV2 decoded{};
    if (!crypto::DecodePaymentCodeV2(text, cfg.bech32_hrp, &decoded, &error)) {
      std::cerr << "DecodePaymentCodeV2 failed: " << error << "\n";
      return EXIT_FAILURE;
    }
    if (decoded.network_id != code.network_id || decoded.scan_pubkey != code.scan_pubkey ||
        decoded.spend_root_commitment != code.spend_root_commitment) {
      std::cerr << "payment code v2 decode mismatch\n";
      return EXIT_FAILURE;
    }

    std::string tampered = text;
    tampered.back() = tampered.back() == 'a' ? 'b' : 'a';
    if (crypto::DecodePaymentCodeV2(tampered, cfg.bech32_hrp, &decoded, &error)) {
      std::cerr << "expected tampered payment code v2 to fail\n";
      return EXIT_FAILURE;
    }

    std::string upper = text;
    upper[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(upper[0])));
    if (crypto::DecodePaymentCodeV2(upper, cfg.bech32_hrp, &decoded, &error)) {
      std::cerr << "expected mixed-case payment code v2 to fail\n";
      return EXIT_FAILURE;
    }

    config::SelectNetwork(config::NetworkType::kTestnet);
    const auto& cfg_test = config::GetNetworkConfig();
    if (crypto::DecodePaymentCodeV2(text, cfg_test.bech32_hrp, &decoded, &error)) {
      std::cerr << "expected network prefix mismatch to fail\n";
      return EXIT_FAILURE;
    }
  } catch (const std::exception& ex) {
    std::cerr << "payment_code_v2_tests: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
