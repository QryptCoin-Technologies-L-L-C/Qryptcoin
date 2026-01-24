#include "script/l2_anchor.hpp"

#include <algorithm>

namespace qryptcoin::script {

ScriptPubKey CreateL2AnchorScript(const Layer2Commitment& anchor) {
  ScriptPubKey script{};
  script.data.reserve(1 + 2 + 1 + anchor.commitment.size());
  script.data.push_back(kOp0);
  script.data.push_back(static_cast<std::uint8_t>(anchor.version & 0xFF));
  script.data.push_back(static_cast<std::uint8_t>((anchor.version >> 8) & 0xFF));
  script.data.push_back(static_cast<std::uint8_t>(anchor.commitment.size()));
  script.data.insert(script.data.end(), anchor.commitment.begin(), anchor.commitment.end());
  return script;
}

bool ParseL2Anchor(const ScriptPubKey& script, Layer2Commitment* out) {
  if (script.data.size() != 1 + 2 + 1 + kLayer2CommitmentSize) {
    return false;
  }
  if (script.data[0] != kOp0) {
    return false;
  }
  if (script.data[3] != kLayer2CommitmentSize) {
    return false;
  }
  if (out) {
    Layer2Commitment anchor{};
    anchor.version = static_cast<std::uint16_t>(script.data[1]) |
                     (static_cast<std::uint16_t>(script.data[2]) << 8);
    std::copy_n(script.data.begin() + 4, kLayer2CommitmentSize, anchor.commitment.begin());
    *out = anchor;
  }
  return true;
}

}  // namespace qryptcoin::script
