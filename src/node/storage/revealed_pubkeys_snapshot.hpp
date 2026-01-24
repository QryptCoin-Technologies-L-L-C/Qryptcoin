#pragma once

#include <string>

#include "consensus/revealed_pubkeys.hpp"

namespace qryptcoin::storage {

bool SaveRevealedPubkeysSnapshot(const consensus::RevealedPubkeySet& set, const std::string& path);
bool LoadRevealedPubkeysSnapshot(consensus::RevealedPubkeySet* set, const std::string& path);

}  // namespace qryptcoin::storage

