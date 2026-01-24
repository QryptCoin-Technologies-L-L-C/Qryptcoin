#pragma once

#include <string_view>

namespace qryptcoin::crypto {

// Single consensus signature scheme: Dilithium3.
enum class SignatureAlgorithm {
  kDilithium,
};

struct CryptoSuiteDescriptor {
  SignatureAlgorithm algorithm;
  std::string_view signature_name;
  std::string_view hash_family;
};

CryptoSuiteDescriptor DefaultSignatureSuite();
std::string_view DefaultHandshakeKEM();
std::string_view DefaultHashFunction();

}  // namespace qryptcoin::crypto
