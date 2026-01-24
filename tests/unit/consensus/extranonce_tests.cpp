#include <cstdint>
#include <filesystem>
#include <iostream>
#include <span>
#include <string>
#include <cstring>

#include "config/network.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "node/block_builder.hpp"
#include "node/chain_state.hpp"
#include "node/mining_extranonce.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"

using namespace qryptcoin;

namespace {

bool TestExtraNonceMutatesMerkle() {
  config::SelectNetwork(config::NetworkType::kRegtest);

  // Bootstrap a tiny regtest chain so BuildBlockTemplate can construct
  // a tip-relative coinbase transaction.
  auto temp_root = std::filesystem::temp_directory_path() / "qryptcoin-extranonce-test";
  std::filesystem::remove_all(temp_root);
  std::filesystem::create_directories(temp_root);

  node::ChainState chain((temp_root / "blocks.dat").string(),
                         (temp_root / "utxo.dat").string());
  std::string init_error;
  if (!chain.Initialize(&init_error)) {
    std::cerr << "extranonce_tests: chain init failed: " << init_error << "\n";
    return false;
  }

  // Build a Dilithium3 P2QH descriptor for the coinbase reward output.
  crypto::QPqDilithiumKey key = crypto::QPqDilithiumKey::Generate();
  auto pk = key.PublicKey();
  auto reveal = crypto::BuildP2QHReveal(pk);
  crypto::P2QHDescriptor descriptor = crypto::DescriptorFromReveal(reveal);

  node::BlockTemplate templ;
  std::string tmpl_error;
  if (!node::BuildBlockTemplate(chain, descriptor, &templ, &tmpl_error)) {
    std::cerr << "extranonce_tests: BuildBlockTemplate failed: " << tmpl_error << "\n";
    return false;
  }

  if (templ.block.transactions.empty() ||
      templ.block.transactions.front().vin.empty()) {
    std::cerr << "extranonce_tests: template missing coinbase input\n";
    return false;
  }

  const auto& coinbase_in = templ.block.transactions.front().vin.front();
  const auto& desc = coinbase_in.unlocking_descriptor;
  const std::size_t extra_size = sizeof(std::uint64_t);
  auto extra_offset_opt = qryptcoin::node::FindCoinbaseExtraNonceOffset(templ.block);
  if (!extra_offset_opt.has_value()) {
    std::cerr << "extranonce_tests: failed to locate coinbase extra-nonce offset\n";
    return false;
  }
  const std::size_t extra_offset = *extra_offset_opt;
  if (desc.size() < extra_offset + extra_size) {
    std::cerr << "extranonce_tests: unlocking_descriptor too small: "
              << desc.size() << " bytes\n";
    return false;
  }

  std::size_t cursor = 0;
  std::uint64_t encoded_height = 0;
  if (!primitives::serialize::ReadVarInt(desc, &cursor, &encoded_height) ||
      encoded_height != static_cast<std::uint64_t>(templ.height) ||
      cursor != extra_offset) {
    std::cerr << "extranonce_tests: height prefix mismatch (got "
              << encoded_height << ", expected " << templ.height << ")\n";
    return false;
  }

  const auto orig_merkle = templ.block.header.merkle_root;

  // Mutate only the extra-nonce field in the coinbase unlocking descriptor
  // and recompute the Merkle root. The root must change while the rest of
  // the block body remains identical.
  primitives::CBlock mutated = templ.block;
  auto mutated_offset_opt = qryptcoin::node::FindCoinbaseExtraNonceOffset(mutated);
  if (!mutated_offset_opt.has_value()) {
    std::cerr << "extranonce_tests: failed to locate mutated extra-nonce offset\n";
    return false;
  }
  const std::size_t mutated_extra_offset = *mutated_offset_opt;
  qryptcoin::node::SetCoinbaseExtraNonce(&mutated, mutated_extra_offset, 1);

  // Height encoding must remain intact after miner-side extra-nonce updates.
  const auto& mut_desc = mutated.transactions.front().vin.front().unlocking_descriptor;
  std::size_t mutated_cursor = 0;
  std::uint64_t mutated_height = 0;
  if (!primitives::serialize::ReadVarInt(mut_desc, &mutated_cursor, &mutated_height) ||
      mutated_height != static_cast<std::uint64_t>(templ.height) ||
      mutated_cursor != mutated_extra_offset) {
    std::cerr << "extranonce_tests: miner extra-nonce update corrupted height prefix\n";
    return false;
  }

  mutated.header.merkle_root =
      primitives::ComputeMerkleRoot(mutated.transactions);

  if (mutated.header.merkle_root == orig_merkle) {
    std::cerr << "extranonce_tests: Merkle root did not change after "
                 "extra-nonce mutation\n";
    return false;
  }

  // Changing only the header nonce must NOT affect the Merkle root.
  primitives::CBlock nonce_only = templ.block;
  nonce_only.header.nonce += 1;
  const auto merkle_after_nonce = nonce_only.header.merkle_root;
  if (merkle_after_nonce != orig_merkle) {
    std::cerr << "extranonce_tests: Merkle root changed when only header "
                 "nonce was updated\n";
    return false;
  }

  std::filesystem::remove_all(temp_root);
  return true;
}

}  // namespace

int main() {
  if (!TestExtraNonceMutatesMerkle()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
