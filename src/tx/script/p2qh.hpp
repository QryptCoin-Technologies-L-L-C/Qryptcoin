#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include "crypto/p2qh_descriptor.hpp"
#include "primitives/transaction.hpp"
#include "script/script.hpp"

namespace qryptcoin::script {

ScriptPubKey CreateP2QHScript(const crypto::P2QHDescriptor& descriptor);
bool VerifyP2QHWitness(const ScriptPubKey& script, const std::vector<primitives::WitnessStackItem>& witness_stack,
                       std::span<const std::uint8_t> message, std::string* error);

}  // namespace qryptcoin::script

