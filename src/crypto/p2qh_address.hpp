#pragma once

#include <string>

#include "crypto/p2qh_descriptor.hpp"

namespace qryptcoin::crypto {

std::string EncodeP2QHAddress(const P2QHDescriptor& descriptor, std::string_view hrp);
bool DecodeP2QHAddress(std::string_view address, std::string_view expected_hrp,
                       P2QHDescriptor* descriptor);

}  // namespace qryptcoin::crypto

