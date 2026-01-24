#pragma once

#include <cstddef>
#include <unordered_set>

#include "primitives/hash.hpp"

namespace qryptcoin::consensus {

struct Hash256Hasher {
  std::size_t operator()(const primitives::Hash256& hash) const noexcept {
    std::size_t result = 0;
    for (auto byte : hash) {
      result = (result * 131) ^ static_cast<std::size_t>(byte);
    }
    return result;
  }
};

class RevealedPubkeySet {
 public:
  bool Contains(const primitives::Hash256& hash) const;
  bool Insert(const primitives::Hash256& hash);
  bool Erase(const primitives::Hash256& hash);
  void Clear();
  std::size_t Size() const noexcept { return set_.size(); }
  void Reserve(std::size_t entries) { set_.reserve(entries); }

  template <typename Fn>
  void ForEach(Fn&& fn) const {
    for (const auto& hash : set_) {
      if (!fn(hash)) {
        break;
      }
    }
  }

 private:
  std::unordered_set<primitives::Hash256, Hash256Hasher> set_;
};

}  // namespace qryptcoin::consensus

