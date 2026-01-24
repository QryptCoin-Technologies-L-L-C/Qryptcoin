#pragma once

#include <unordered_map>

#include "primitives/transaction.hpp"

namespace qryptcoin::consensus {

struct Coin {
  primitives::CTxOut out;
  std::uint32_t height{0};
  bool coinbase{false};
};

struct OutPointHasher {
  std::size_t operator()(const primitives::COutPoint& outpoint) const noexcept {
    std::size_t result = 0;
    for (auto byte : outpoint.txid) {
      result = (result * 131) ^ static_cast<std::size_t>(byte);
    }
    result ^= static_cast<std::size_t>(outpoint.index) + 0x9e3779b97f4a7c15ULL + (result << 6) +
              (result >> 2);
    return result;
  }
};

class UTXOSet {
 public:
  void AddCoin(const primitives::COutPoint& outpoint, Coin coin);
  const Coin* GetCoin(const primitives::COutPoint& outpoint) const;
  Coin* GetCoinMutable(const primitives::COutPoint& outpoint);
  bool SpendCoin(const primitives::COutPoint& outpoint);
  std::size_t Size() const noexcept { return coins_.size(); }
  template <typename Fn>
  void ForEach(Fn&& fn) const {
    for (const auto& [outpoint, coin] : coins_) {
      if (!fn(outpoint, coin)) break;
    }
  }

  void Reserve(std::size_t entries) {
    coins_.reserve(entries);
  }

 private:
  std::unordered_map<primitives::COutPoint, Coin, OutPointHasher> coins_;
};

}  // namespace qryptcoin::consensus
