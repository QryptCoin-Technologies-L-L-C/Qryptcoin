#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace qryptcoin::script {

inline constexpr std::uint8_t kOp0 = 0x00;
inline constexpr std::uint8_t kOp1 = 0x51;
inline constexpr std::size_t kP2QHWitnessProgramSize = 32;

struct ScriptPubKey {
  std::vector<std::uint8_t> data;
};

bool ExtractWitnessProgram(const ScriptPubKey& script, std::array<std::uint8_t, kP2QHWitnessProgramSize>* program);

}  // namespace qryptcoin::script

