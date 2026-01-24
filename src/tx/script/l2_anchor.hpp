#pragma once

#include <array>
#include <cstdint>

#include "script/script.hpp"

namespace qryptcoin::script {

inline constexpr std::size_t kLayer2CommitmentSize = 32;

struct Layer2Commitment {
  std::uint16_t version{0};
  std::array<std::uint8_t, kLayer2CommitmentSize> commitment{};
};

ScriptPubKey CreateL2AnchorScript(const Layer2Commitment& anchor);
bool ParseL2Anchor(const ScriptPubKey& script, Layer2Commitment* out);

}  // namespace qryptcoin::script
