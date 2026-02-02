#include "consensus/sparse_merkle_tree.hpp"

#include <algorithm>
#include <span>
#include <string_view>
#include <vector>

#include "crypto/hash.hpp"

namespace qryptcoin::consensus {

namespace {

primitives::Hash256 Sha3ToHash256(const crypto::Sha3_256Hash& hash) {
  primitives::Hash256 out{};
  std::copy(hash.begin(), hash.end(), out.begin());
  return out;
}

primitives::Hash256 TaggedHash(std::string_view tag,
                               std::span<const std::uint8_t> a = {},
                               std::span<const std::uint8_t> b = {}) {
  std::vector<std::uint8_t> preimage;
  preimage.reserve(tag.size() + a.size() + b.size());
  preimage.insert(preimage.end(), tag.begin(), tag.end());
  preimage.insert(preimage.end(), a.begin(), a.end());
  preimage.insert(preimage.end(), b.begin(), b.end());
  return Sha3ToHash256(crypto::Sha3_256(preimage));
}

}  // namespace

SparseMerkleTree::SparseMerkleTree() = default;

std::size_t SparseMerkleTree::NodeIdHasher::operator()(const NodeId& id) const noexcept {
  std::size_t result = static_cast<std::size_t>(id.depth);
  for (auto byte : id.prefix) {
    result = (result * 131) ^ static_cast<std::size_t>(byte);
  }
  return result;
}

bool SparseMerkleTree::GetBit(const primitives::Hash256& key, std::uint16_t bit_index) {
  const std::uint16_t byte_index = bit_index / 8;
  const std::uint16_t bit_in_byte = static_cast<std::uint16_t>(7 - (bit_index % 8));
  const std::uint8_t mask = static_cast<std::uint8_t>(1u << bit_in_byte);
  return (key[byte_index] & mask) != 0;
}

primitives::Hash256 SparseMerkleTree::PrefixForDepth(const primitives::Hash256& key,
                                                     std::uint16_t depth) {
  primitives::Hash256 out{};
  if (depth == 0) {
    return out;
  }
  out = key;
  if (depth >= 256) {
    return out;
  }
  const std::size_t byte = depth / 8;
  const std::size_t bits = depth % 8;
  if (byte < out.size()) {
    if (bits != 0) {
      const std::uint8_t mask = static_cast<std::uint8_t>(0xFFu << (8 - bits));
      out[byte] &= mask;
      for (std::size_t i = byte + 1; i < out.size(); ++i) {
        out[i] = 0;
      }
    } else {
      for (std::size_t i = byte; i < out.size(); ++i) {
        out[i] = 0;
      }
    }
  }
  return out;
}

void SparseMerkleTree::ToggleBit(primitives::Hash256* prefix, std::uint16_t bit_index) {
  if (!prefix) {
    return;
  }
  const std::uint16_t byte_index = bit_index / 8;
  const std::uint16_t bit_in_byte = static_cast<std::uint16_t>(7 - (bit_index % 8));
  const std::uint8_t mask = static_cast<std::uint8_t>(1u << bit_in_byte);
  (*prefix)[byte_index] ^= mask;
}

primitives::Hash256 SparseMerkleTree::LeafHashPresent(const primitives::Hash256& key) {
  constexpr std::string_view kTag = "QRY-SMT-LEAF-PRESENT";
  return TaggedHash(kTag, std::span<const std::uint8_t>(key.data(), key.size()));
}

primitives::Hash256 SparseMerkleTree::LeafHashEmpty() {
  constexpr std::string_view kTag = "QRY-SMT-LEAF-EMPTY";
  return TaggedHash(kTag);
}

primitives::Hash256 SparseMerkleTree::InternalHash(const primitives::Hash256& left,
                                                   const primitives::Hash256& right) {
  constexpr std::string_view kTag = "QRY-SMT-NODE";
  return TaggedHash(kTag, std::span<const std::uint8_t>(left.data(), left.size()),
                    std::span<const std::uint8_t>(right.data(), right.size()));
}

const std::array<primitives::Hash256, 257>& SparseMerkleTree::DefaultHashes() {
  static const auto hashes = []() {
    std::array<primitives::Hash256, 257> out{};
    out[256] = LeafHashEmpty();
    for (int depth = 255; depth >= 0; --depth) {
      out[static_cast<std::size_t>(depth)] =
          InternalHash(out[static_cast<std::size_t>(depth + 1)],
                       out[static_cast<std::size_t>(depth + 1)]);
    }
    return out;
  }();
  return hashes;
}

primitives::Hash256 SparseMerkleTree::NodeHashOrDefault(const NodeId& id) const {
  auto it = nodes_.find(id);
  if (it == nodes_.end()) {
    return DefaultHashes()[id.depth];
  }
  return it->second;
}

void SparseMerkleTree::SetNodeHash(const NodeId& id, const primitives::Hash256& hash) {
  const auto& defaults = DefaultHashes();
  if (hash == defaults[id.depth]) {
    nodes_.erase(id);
    return;
  }
  nodes_[id] = hash;
}

primitives::Hash256 SparseMerkleTree::Root() const {
  NodeId root_id{};
  root_id.depth = 0;
  root_id.prefix.fill(0);
  return NodeHashOrDefault(root_id);
}

bool SparseMerkleTree::Contains(const primitives::Hash256& key) const {
  NodeId leaf{};
  leaf.depth = 256;
  leaf.prefix = key;
  return nodes_.find(leaf) != nodes_.end();
}

bool SparseMerkleTree::Insert(const primitives::Hash256& key) {
  if (Contains(key)) {
    return false;
  }
  const auto& defaults = DefaultHashes();
  NodeId leaf{};
  leaf.depth = 256;
  leaf.prefix = key;
  primitives::Hash256 current = LeafHashPresent(key);
  SetNodeHash(leaf, current);

  for (std::uint16_t depth = 256; depth >= 1; --depth) {
    NodeId node{};
    node.depth = depth;
    node.prefix = PrefixForDepth(key, depth);
    primitives::Hash256 sibling_prefix = node.prefix;
    ToggleBit(&sibling_prefix, static_cast<std::uint16_t>(depth - 1));
    NodeId sibling{depth, sibling_prefix};
    const primitives::Hash256 sibling_hash = NodeHashOrDefault(sibling);

    const bool is_right = GetBit(key, static_cast<std::uint16_t>(depth - 1));
    const primitives::Hash256 left = is_right ? sibling_hash : current;
    const primitives::Hash256 right = is_right ? current : sibling_hash;

    const primitives::Hash256 parent_hash = InternalHash(left, right);
    NodeId parent{};
    parent.depth = static_cast<std::uint16_t>(depth - 1);
    parent.prefix = PrefixForDepth(key, parent.depth);

    if (parent_hash == defaults[parent.depth]) {
      nodes_.erase(parent);
    } else {
      nodes_[parent] = parent_hash;
    }
    current = parent_hash;
  }
  return true;
}

bool SparseMerkleTree::Erase(const primitives::Hash256& key) {
  if (!Contains(key)) {
    return false;
  }

  const auto& defaults = DefaultHashes();
  NodeId leaf{};
  leaf.depth = 256;
  leaf.prefix = key;
  nodes_.erase(leaf);

  primitives::Hash256 current = defaults[256];
  for (std::uint16_t depth = 256; depth >= 1; --depth) {
    NodeId node{};
    node.depth = depth;
    node.prefix = PrefixForDepth(key, depth);
    primitives::Hash256 sibling_prefix = node.prefix;
    ToggleBit(&sibling_prefix, static_cast<std::uint16_t>(depth - 1));
    NodeId sibling{depth, sibling_prefix};
    const primitives::Hash256 sibling_hash = NodeHashOrDefault(sibling);

    const bool is_right = GetBit(key, static_cast<std::uint16_t>(depth - 1));
    const primitives::Hash256 left = is_right ? sibling_hash : current;
    const primitives::Hash256 right = is_right ? current : sibling_hash;

    const primitives::Hash256 parent_hash = InternalHash(left, right);
    NodeId parent{};
    parent.depth = static_cast<std::uint16_t>(depth - 1);
    parent.prefix = PrefixForDepth(key, parent.depth);
    if (parent_hash == defaults[parent.depth]) {
      nodes_.erase(parent);
    } else {
      nodes_[parent] = parent_hash;
    }
    current = parent_hash;
  }

  return true;
}

SMTProof SparseMerkleTree::ProveMembership(const primitives::Hash256& key) const {
  SMTProof proof{};
  proof.key = key;
  proof.siblings.reserve(256);
  proof.path_bits.reserve(256);
  for (std::uint16_t depth = 1; depth <= 256; ++depth) {
    proof.path_bits.push_back(GetBit(key, static_cast<std::uint16_t>(depth - 1)) ? 1u : 0u);
  }
  for (std::uint16_t depth = 256; depth >= 1; --depth) {
    primitives::Hash256 prefix = PrefixForDepth(key, depth);
    ToggleBit(&prefix, static_cast<std::uint16_t>(depth - 1));
    NodeId sibling{depth, prefix};
    proof.siblings.push_back(NodeHashOrDefault(sibling));
  }
  return proof;
}

SMTProof SparseMerkleTree::ProveNonMembership(const primitives::Hash256& key) const {
  return ProveMembership(key);
}

primitives::Hash256 SparseMerkleTree::ComputeRootFromProof(
    const primitives::Hash256& key,
    const primitives::Hash256& leaf_hash,
    const std::vector<primitives::Hash256>& siblings) {
  primitives::Hash256 current = leaf_hash;
  if (siblings.size() != 256) {
    primitives::Hash256 zero{};
    zero.fill(0);
    return zero;
  }
  for (std::size_t i = 0; i < siblings.size(); ++i) {
    const std::uint16_t depth = static_cast<std::uint16_t>(256 - i);
    const bool is_right = GetBit(key, static_cast<std::uint16_t>(depth - 1));
    const primitives::Hash256 left = is_right ? siblings[i] : current;
    const primitives::Hash256 right = is_right ? current : siblings[i];
    current = InternalHash(left, right);
  }
  return current;
}

bool SparseMerkleTree::VerifyMembershipProof(const SMTProof& proof, const primitives::Hash256& root) {
  const auto leaf = LeafHashPresent(proof.key);
  return ComputeRootFromProof(proof.key, leaf, proof.siblings) == root;
}

bool SparseMerkleTree::VerifyNonMembershipProof(const SMTProof& proof, const primitives::Hash256& root) {
  const auto leaf = DefaultHashes()[256];
  return ComputeRootFromProof(proof.key, leaf, proof.siblings) == root;
}

bool SparseMerkleTree::InsertBatch(const std::vector<primitives::Hash256>& keys) {
  bool ok = true;
  for (const auto& key : keys) {
    ok &= Insert(key);
  }
  return ok;
}

bool SparseMerkleTree::EraseBatch(const std::vector<primitives::Hash256>& keys) {
  bool ok = true;
  for (const auto& key : keys) {
    ok &= Erase(key);
  }
  return ok;
}

}  // namespace qryptcoin::consensus
