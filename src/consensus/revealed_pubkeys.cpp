#include "consensus/revealed_pubkeys.hpp"

namespace qryptcoin::consensus {

bool RevealedPubkeySet::Contains(const primitives::Hash256& hash) const {
  return set_.find(hash) != set_.end();
}

bool RevealedPubkeySet::Insert(const primitives::Hash256& hash) {
  return set_.insert(hash).second;
}

bool RevealedPubkeySet::Erase(const primitives::Hash256& hash) {
  return set_.erase(hash) > 0;
}

void RevealedPubkeySet::Clear() {
  set_.clear();
}

}  // namespace qryptcoin::consensus

