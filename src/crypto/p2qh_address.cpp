#include "crypto/p2qh_address.hpp"

#include <algorithm>
#include <array>

#include "crypto/bech32.hpp"
#include "script/script.hpp"

namespace qryptcoin::crypto {

std::string EncodeP2QHAddress(const P2QHDescriptor& descriptor, std::string_view hrp) {
  return EncodeBech32m(hrp, 1,
                       std::span<const std::uint8_t>(descriptor.program.data(),
                                                     descriptor.program.size()));
}

bool DecodeP2QHAddress(std::string_view address, std::string_view expected_hrp,
                       P2QHDescriptor* descriptor) {
  uint8_t version = 0;
  std::vector<std::uint8_t> program;
  if (!DecodeBech32m(address, expected_hrp, &version, &program)) {
    return false;
  }
  if (version != 1 || program.size() != script::kP2QHWitnessProgramSize) {
    return false;
  }
  if (descriptor != nullptr) {
    descriptor->version = 0x01;
    descriptor->algorithm = SignatureAlgorithm::kDilithium;
    descriptor->params_id = 0x01;
    descriptor->reserved = 0;
    std::copy(program.begin(), program.end(), descriptor->program.begin());
  }
  return true;
}

}  // namespace qryptcoin::crypto
