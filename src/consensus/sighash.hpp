#pragma once

#include <array>
#include <cstddef>
#include <span>

#include "consensus/utxo.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::consensus {

std::array<std::uint8_t, 32> ComputeSighash(const primitives::CTransaction& tx,
                                            std::size_t input_index, const Coin& spent_coin);

// Compute the exact 32-byte message that P2QH inputs sign.
//
// For legacy P2QH witnesses that contain exactly:
//   witness[0] = REVEAL_V1
//   witness[1] = SIG
// the signed message is the base sighash.
//
// For extended witnesses with additional stack items (witness[2+]),
// the signed message commits to those extension bytes so they are not
// malleable by third parties.
std::array<std::uint8_t, 32> ComputeP2QHSignatureMessage(
    const std::array<std::uint8_t, 32>& base_sighash,
    std::span<const primitives::WitnessStackItem> witness_stack);

}  // namespace qryptcoin::consensus
