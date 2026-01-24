#include "consensus/utxo.hpp"

namespace qryptcoin::consensus {

void UTXOSet::AddCoin(const primitives::COutPoint& outpoint, Coin coin) {
  coins_[outpoint] = std::move(coin);
}

const Coin* UTXOSet::GetCoin(const primitives::COutPoint& outpoint) const {
  const auto it = coins_.find(outpoint);
  if (it == coins_.end()) {
    return nullptr;
  }
  return &it->second;
}

Coin* UTXOSet::GetCoinMutable(const primitives::COutPoint& outpoint) {
  auto it = coins_.find(outpoint);
  if (it == coins_.end()) {
    return nullptr;
  }
  return &it->second;
}

bool UTXOSet::SpendCoin(const primitives::COutPoint& outpoint) {
  return coins_.erase(outpoint) > 0;
}

}  // namespace qryptcoin::consensus
