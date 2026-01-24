#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

extern "C" {
#include "randombytes.h"
}

#include "crypto/deterministic_rng.hpp"
#include "util/csprng.hpp"

namespace {

// Fallback system RNG used when no deterministic wallet-scoped RNG
// instance is active. This is only exercised in non-wallet contexts
// such as tests or tools that do not install DeterministicOqsRng.
void SystemRandomBytes(std::uint8_t* out, std::size_t len) {
  if (out == nullptr || len == 0) {
    return;
  }
  qryptcoin::util::FillSecureRandomBytesOrAbort(std::span<std::uint8_t>(out, len));
}

}  // namespace

extern "C" void randombytes(std::uint8_t* out, std::size_t outlen) {
  if (out == nullptr || outlen == 0) {
    return;
  }
  if (auto* rng = qryptcoin::crypto::DeterministicOqsRng::CurrentInstance()) {
    rng->Generate(out, outlen);
  } else {
    SystemRandomBytes(out, outlen);
  }
}
