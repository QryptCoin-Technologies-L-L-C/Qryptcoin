#include "crypto/crypto_suite.hpp"

namespace qryptcoin::crypto {

CryptoSuiteDescriptor DefaultSignatureSuite() {
  return CryptoSuiteDescriptor{
      SignatureAlgorithm::kDilithium,
      "ML-DSA (Dilithium3)",
      DefaultHashFunction()};
}

std::string_view DefaultHandshakeKEM() { return "Kyber-768"; }

std::string_view DefaultHashFunction() { return "SHA3-256"; }

}  // namespace qryptcoin::crypto
