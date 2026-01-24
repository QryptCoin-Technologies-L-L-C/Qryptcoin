#include "script/script.hpp"

#include <algorithm>

namespace qryptcoin::script {

bool ExtractWitnessProgram(const ScriptPubKey& script,
                           std::array<std::uint8_t, kP2QHWitnessProgramSize>* program) {
  if (script.data.size() != 2 + kP2QHWitnessProgramSize || script.data.empty()) {
    return false;
  }
  if (script.data[0] != kOp1) {
    return false;
  }
  if (script.data[1] != kP2QHWitnessProgramSize) {
    return false;
  }
  if (program != nullptr) {
    std::copy(script.data.begin() + 2, script.data.end(), program->begin());
  }
  return true;
}

}  // namespace qryptcoin::script
