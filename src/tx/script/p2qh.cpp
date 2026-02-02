#include "script/p2qh.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <vector>

#include "crypto/pq_engine.hpp"
#include "primitives/hash.hpp"

namespace qryptcoin::script {

ScriptPubKey CreateP2QHScript(const crypto::P2QHDescriptor& descriptor) {
  ScriptPubKey script{};
  script.data.reserve(2 + primitives::Hash256{}.size());
  script.data.push_back(kOp1);
  script.data.push_back(static_cast<std::uint8_t>(kP2QHWitnessProgramSize));
  script.data.insert(script.data.end(), descriptor.program.begin(), descriptor.program.end());
  return script;
}

namespace {

bool EnsureWitnessProgramMatches(const ScriptPubKey& script,
                                 const crypto::P2QHDescriptor& descriptor) {
  std::array<std::uint8_t, kP2QHWitnessProgramSize> program{};
  if (!ExtractWitnessProgram(script, &program)) {
    return false;
  }
  return std::equal(program.begin(), program.end(), descriptor.program.begin());
}

}  // namespace

bool VerifyP2QHWitness(const ScriptPubKey& script,
                       const std::vector<primitives::WitnessStackItem>& witness_stack,
                       std::span<const std::uint8_t> message, std::string* error) {
  if (witness_stack.empty()) {
    if (error) *error = "empty witness stack";
    return false;
  }
  const auto& reveal = witness_stack.front().data;
  crypto::P2QHRevealData reveal_data{};
  if (!crypto::ParseP2QHReveal(reveal, &reveal_data)) {
    if (error) *error = "invalid descriptor reveal";
    return false;
  }
  crypto::P2QHDescriptor descriptor = crypto::DescriptorFromReveal(reveal);
  if (!EnsureWitnessProgramMatches(script, descriptor)) {
    if (error) *error = "descriptor commitment mismatch";
    return false;
  }
  // Dilithium-only policy: witnesses must contain at least one PQ
  // signature following the descriptor reveal. Additional witness
  // items are allowed for future extensions, but must be committed
  // by the signature digest (enforced at the consensus layer).
  if (witness_stack.size() < 2) {
    if (error) *error = "witness stack too small";
    return false;
  }
  const auto& sig = witness_stack[1].data;
  if (!crypto::VerifySignature(crypto::SignatureAlgorithm::kDilithium, message, sig,
                               reveal_data.mldsa_public_key)) {
    if (error) *error = "Dilithium signature failure";
    return false;
  }
  return true;
}

}  // namespace qryptcoin::script
