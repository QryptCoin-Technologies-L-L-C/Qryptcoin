#pragma once

#include <string>
#include <unordered_map>

#include "primitives/amount.hpp"
#include "primitives/hash.hpp"

namespace qryptcoin::storage {

struct Hash256Hasher {
  std::size_t operator()(const primitives::Hash256& hash) const noexcept {
    std::size_t result = 0;
    for (auto byte : hash) {
      result = (result * 131) ^ static_cast<std::size_t>(byte);
    }
    return result;
  }
};

using TxFeeMap =
    std::unordered_map<primitives::Hash256, primitives::Amount, Hash256Hasher>;

bool SaveTxFeeSnapshot(const TxFeeMap& fees, const std::string& path);
bool LoadTxFeeSnapshot(TxFeeMap* fees, const std::string& path);

}  // namespace qryptcoin::storage

