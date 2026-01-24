#pragma once

#include <array>
#include <cstddef>

#include "consensus/utxo.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::consensus {

std::array<std::uint8_t, 32> ComputeSighash(const primitives::CTransaction& tx,
                                            std::size_t input_index, const Coin& spent_coin);

}  // namespace qryptcoin::consensus

