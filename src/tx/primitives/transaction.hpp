#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <vector>

#include "primitives/amount.hpp"
#include "primitives/hash.hpp"

namespace qryptcoin::primitives {

struct COutPoint {
  Hash256 txid{};
  std::uint32_t index{0};
  bool operator==(const COutPoint& other) const = default;

  [[nodiscard]] bool IsNull() const noexcept {
    return std::all_of(txid.begin(), txid.end(), [](std::uint8_t b) { return b == 0; }) &&
           index == std::numeric_limits<std::uint32_t>::max();
  }

  static COutPoint Null() {
    COutPoint out{};
    out.index = std::numeric_limits<std::uint32_t>::max();
    return out;
  }
};

struct WitnessStackItem {
  std::vector<std::uint8_t> data;
};

struct CTxIn {
  COutPoint prevout{};
  std::vector<std::uint8_t> unlocking_descriptor{};  // Encoded Dilithium signature payload.
  std::vector<WitnessStackItem> witness_stack{};
  std::uint32_t sequence{0xFFFFFFFF};
};

struct CTxOut {
  Amount value{0};  // In Miks.
  std::vector<std::uint8_t> locking_descriptor{};  // ScriptPubKey bytes (P2QH or extensions).
};

struct CTransaction {
  std::uint32_t version{1};
  std::vector<CTxIn> vin{};
  std::vector<CTxOut> vout{};
  std::uint32_t lock_time{0};

  [[nodiscard]] bool IsCoinbase() const noexcept {
    return vin.size() == 1 && vin.front().prevout.IsNull();
  }
};

}  // namespace qryptcoin::primitives
