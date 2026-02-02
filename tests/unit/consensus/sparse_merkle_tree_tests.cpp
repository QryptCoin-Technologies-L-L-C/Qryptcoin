#include <array>
#include <cstdlib>
#include <iostream>

#include "consensus/sparse_merkle_tree.hpp"

int main() {
  using qryptcoin::consensus::SMTProof;
  using qryptcoin::consensus::SparseMerkleTree;
  using qryptcoin::primitives::Hash256;

  SparseMerkleTree tree;
  const Hash256 empty_root = tree.Root();

  Hash256 key1{};
  key1.fill(0x11);
  Hash256 key2{};
  key2.fill(0x22);

  // Empty tree: non-membership proofs must verify, membership proofs must fail.
  const SMTProof nm0 = tree.ProveNonMembership(key1);
  if (nm0.siblings.size() != 256 || nm0.path_bits.size() != 256) {
    std::cerr << "unexpected proof sizing for empty tree\n";
    return EXIT_FAILURE;
  }
  if (!SparseMerkleTree::VerifyNonMembershipProof(nm0, empty_root)) {
    std::cerr << "non-membership proof failed for empty tree\n";
    return EXIT_FAILURE;
  }
  const SMTProof mem0 = tree.ProveMembership(key1);
  if (SparseMerkleTree::VerifyMembershipProof(mem0, empty_root)) {
    std::cerr << "membership proof unexpectedly verified for empty tree\n";
    return EXIT_FAILURE;
  }

  // Insert and verify membership/non-membership.
  if (!tree.Insert(key1) || !tree.Contains(key1)) {
    std::cerr << "failed to insert key1\n";
    return EXIT_FAILURE;
  }
  const Hash256 root1 = tree.Root();
  if (root1 == empty_root) {
    std::cerr << "root did not change after insertion\n";
    return EXIT_FAILURE;
  }

  const SMTProof mem1 = tree.ProveMembership(key1);
  if (!SparseMerkleTree::VerifyMembershipProof(mem1, root1)) {
    std::cerr << "membership proof failed for inserted key\n";
    return EXIT_FAILURE;
  }

  const SMTProof nm1 = tree.ProveNonMembership(key2);
  if (!SparseMerkleTree::VerifyNonMembershipProof(nm1, root1)) {
    std::cerr << "non-membership proof failed for absent key\n";
    return EXIT_FAILURE;
  }

  // Remove and confirm we return to the empty root.
  if (!tree.Erase(key1) || tree.Contains(key1)) {
    std::cerr << "failed to erase key1\n";
    return EXIT_FAILURE;
  }
  const Hash256 root2 = tree.Root();
  if (root2 != empty_root) {
    std::cerr << "root mismatch after erase\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

