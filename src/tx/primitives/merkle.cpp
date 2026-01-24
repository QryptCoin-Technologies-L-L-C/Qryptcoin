#include "primitives/merkle.hpp"

#include <vector>

#include "crypto/hash.hpp"
#include "primitives/txid.hpp"

namespace qryptcoin::primitives {

Hash256 ComputeMerkleRoot(const std::vector<CTransaction>& transactions) {
  if (transactions.empty()) {
    Hash256 hash{};
    return hash;
  }
  std::vector<Hash256> layer;
  layer.reserve(transactions.size());
  for (const auto& tx : transactions) {
    layer.push_back(ComputeTxId(tx));
  }
  while (layer.size() > 1) {
    std::vector<Hash256> next;
    for (std::size_t i = 0; i < layer.size(); i += 2) {
      Hash256 left = layer[i];
      Hash256 right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];
      std::vector<std::uint8_t> buffer;
      buffer.reserve(left.size() + right.size());
      buffer.insert(buffer.end(), left.begin(), left.end());
      buffer.insert(buffer.end(), right.begin(), right.end());
      auto hash = crypto::DoubleSha3_256(buffer);
      Hash256 out{};
      std::copy(hash.begin(), hash.end(), out.begin());
      next.push_back(out);
    }
    layer = std::move(next);
  }
  return layer.front();
}

Hash256 ComputeWitnessMerkleRoot(const std::vector<CTransaction>& transactions) {
  if (transactions.empty()) {
    Hash256 hash{};
    return hash;
  }
  std::vector<Hash256> layer;
  layer.reserve(transactions.size());
  for (std::size_t index = 0; index < transactions.size(); ++index) {
    if (index == 0 && transactions[index].IsCoinbase()) {
      // Witness merkle tree: the coinbase wtxid is treated as 32 bytes of zero.
      // This allows the coinbase to commit to the witness tree without creating a
      // circular dependency on its own contents.
      Hash256 zero{};
      layer.push_back(zero);
      continue;
    }
    layer.push_back(ComputeWTxId(transactions[index]));
  }
  while (layer.size() > 1) {
    std::vector<Hash256> next;
    for (std::size_t i = 0; i < layer.size(); i += 2) {
      Hash256 left = layer[i];
      Hash256 right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];
      std::vector<std::uint8_t> buffer;
      buffer.reserve(left.size() + right.size());
      buffer.insert(buffer.end(), left.begin(), left.end());
      buffer.insert(buffer.end(), right.begin(), right.end());
      auto hash = crypto::DoubleSha3_256(buffer);
      Hash256 out{};
      std::copy(hash.begin(), hash.end(), out.begin());
      next.push_back(out);
    }
    layer = std::move(next);
  }
  return layer.front();
}

}  // namespace qryptcoin::primitives
