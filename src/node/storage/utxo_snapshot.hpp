#pragma once

#include <string>

#include "consensus/utxo.hpp"

namespace qryptcoin::storage {

bool SaveUTXOSnapshot(const consensus::UTXOSet& view, const std::string& path);
bool LoadUTXOSnapshot(consensus::UTXOSet* view, const std::string& path);

}  // namespace qryptcoin::storage

