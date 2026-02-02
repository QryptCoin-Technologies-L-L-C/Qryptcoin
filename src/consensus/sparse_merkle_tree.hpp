#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "primitives/hash.hpp"

namespace qryptcoin::consensus {

struct SMTProof {
  primitives::Hash256 key{};
  std::vector<primitives::Hash256> siblings;
  std::vector<std::uint8_t> path_bits;  // 0 = left, 1 = right (root->leaf)
};

class SparseMerkleTree {
 public:
  SparseMerkleTree();

  primitives::Hash256 Root() const;
  bool Insert(const primitives::Hash256& key);
  bool Erase(const primitives::Hash256& key);
  bool Contains(const primitives::Hash256& key) const;

  SMTProof ProveMembership(const primitives::Hash256& key) const;
  SMTProof ProveNonMembership(const primitives::Hash256& key) const;

  static bool VerifyMembershipProof(const SMTProof& proof, const primitives::Hash256& root);
  static bool VerifyNonMembershipProof(const SMTProof& proof, const primitives::Hash256& root);

  bool InsertBatch(const std::vector<primitives::Hash256>& keys);
  bool EraseBatch(const std::vector<primitives::Hash256>& keys);

 private:
  struct NodeId {
    std::uint16_t depth{0};  // 0..256
    primitives::Hash256 prefix{};
    bool operator==(const NodeId& other) const = default;
  };

  struct NodeIdHasher {
    std::size_t operator()(const NodeId& id) const noexcept;
  };

  static bool GetBit(const primitives::Hash256& key, std::uint16_t bit_index);
  static primitives::Hash256 PrefixForDepth(const primitives::Hash256& key, std::uint16_t depth);
  static void ToggleBit(primitives::Hash256* prefix, std::uint16_t bit_index);
  static primitives::Hash256 LeafHashPresent(const primitives::Hash256& key);
  static primitives::Hash256 LeafHashEmpty();
  static primitives::Hash256 InternalHash(const primitives::Hash256& left,
                                          const primitives::Hash256& right);
  static const std::array<primitives::Hash256, 257>& DefaultHashes();

  primitives::Hash256 NodeHashOrDefault(const NodeId& id) const;
  void SetNodeHash(const NodeId& id, const primitives::Hash256& hash);

  static primitives::Hash256 ComputeRootFromProof(const primitives::Hash256& key,
                                                  const primitives::Hash256& leaf_hash,
                                                  const std::vector<primitives::Hash256>& siblings);

  std::unordered_map<NodeId, primitives::Hash256, NodeIdHasher> nodes_;
};

}  // namespace qryptcoin::consensus

