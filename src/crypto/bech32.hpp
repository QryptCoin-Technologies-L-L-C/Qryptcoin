#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace qryptcoin::crypto {

std::string EncodeBech32m(std::string_view hrp, uint8_t witness_version,
                          std::span<const std::uint8_t> program);
bool DecodeBech32m(std::string_view address, std::string_view expected_hrp, uint8_t* witness_version,
                   std::vector<std::uint8_t>* program);

}  // namespace qryptcoin::crypto

