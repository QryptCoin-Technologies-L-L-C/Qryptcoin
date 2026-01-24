#include <filesystem>
#include <iostream>
#include <limits>
#include <string>

#include "config/network.hpp"
#include "consensus/block_hash.hpp"
#include "consensus/params.hpp"
#include "consensus/pow.hpp"
#include "consensus/witness_commitment.hpp"
#include "node/chain_state.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "primitives/transaction.hpp"

using namespace qryptcoin;

namespace {

bool AlwaysFailSnapshot(const consensus::UTXOSet&, const std::string&) {
  return false;
}

primitives::CBlock MakeBlock(const primitives::Hash256& prev_hash,
                             std::uint32_t height,
                             std::uint32_t bits,
                             std::uint32_t timestamp) {
  primitives::CBlock block;
  block.header.version = 1;
  block.header.previous_block_hash = prev_hash;
  block.header.timestamp = timestamp;
  block.header.difficulty_bits = bits;
  block.header.nonce = 0;

  primitives::CTransaction coinbase;
  coinbase.version = 1;
  coinbase.vin.resize(1);
  coinbase.vin[0].prevout = primitives::COutPoint::Null();
  coinbase.vin[0].sequence = 0xFFFFFFFFu;
  primitives::serialize::WriteVarInt(&coinbase.vin[0].unlocking_descriptor, height);
  primitives::serialize::WriteUint64(&coinbase.vin[0].unlocking_descriptor, 0);
  coinbase.vin[0].unlocking_descriptor.insert(coinbase.vin[0].unlocking_descriptor.end(),
                                              consensus::kWitnessCommitmentTag.begin(),
                                              consensus::kWitnessCommitmentTag.end());
  coinbase.vin[0].unlocking_descriptor.resize(
      coinbase.vin[0].unlocking_descriptor.size() + primitives::Hash256{}.size());
  // Leave coinbase outputs empty; this test focuses on state/persistence flow.
  coinbase.vout.clear();

  block.transactions = {coinbase};
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  return block;
}

bool MineBlock(primitives::CBlock* block) {
  if (!block) return false;
  const auto target = consensus::CompactToTarget(block->header.difficulty_bits);
  for (std::uint32_t nonce = 0;; ++nonce) {
    block->header.nonce = nonce;
    const auto hash = consensus::ComputeBlockHash(block->header);
    if (consensus::HashMeetsTarget(hash, target)) {
      return true;
    }
    if (nonce == std::numeric_limits<std::uint32_t>::max()) {
      return false;
    }
  }
}

bool RunAtomicityTest() {
  config::SelectNetwork(config::NetworkType::kRegtest);
  const auto& params = consensus::Params(config::NetworkType::kRegtest);

  auto temp_root =
      std::filesystem::temp_directory_path() / "qryptcoin-chainstate-persistence-test";
  std::filesystem::remove_all(temp_root);
  std::filesystem::create_directories(temp_root);

  node::ChainState chain((temp_root / "blocks.dat").string(), (temp_root / "utxo.dat").string());
  chain.SetSnapshotSaverForTest(&AlwaysFailSnapshot);

  std::string error;
  if (!chain.Initialize(&error)) {
    std::cerr << "chain_state_persistence_tests: init failed: " << error << "\n";
    return false;
  }

  // Even if the snapshot write fails, the node should still start with a valid
  // in-memory UTXO set and mark persistence as dirty.
  const auto telem0 = chain.GetTelemetry();
  if (!telem0.utxo_snapshot_dirty || telem0.utxo_snapshot_failures == 0) {
    std::cerr << "chain_state_persistence_tests: expected snapshot failure telemetry after init\n";
    return false;
  }

  const std::uint32_t height = 1;
  const std::uint32_t bits = params.genesis_bits;
  const std::uint32_t ts = static_cast<std::uint32_t>(params.genesis_time + 1000u);
  primitives::CBlock block = MakeBlock(params.genesis_hash, height, bits, ts);
  if (!MineBlock(&block)) {
    std::cerr << "chain_state_persistence_tests: mining failed\n";
    return false;
  }
  std::string connect_error;
  if (!chain.ConnectBlock(block, &connect_error)) {
    std::cerr << "chain_state_persistence_tests: ConnectBlock failed: " << connect_error << "\n";
    return false;
  }
  if (chain.Height() != 1) {
    std::cerr << "chain_state_persistence_tests: expected height 1, got " << chain.Height() << "\n";
    return false;
  }

  const auto telem1 = chain.GetTelemetry();
  if (!telem1.utxo_snapshot_dirty) {
    std::cerr << "chain_state_persistence_tests: expected snapshot dirty after connect\n";
    return false;
  }
  if (telem1.utxo_snapshot_failures <= telem0.utxo_snapshot_failures) {
    std::cerr << "chain_state_persistence_tests: expected snapshot failure counter to increase\n";
    return false;
  }

  std::filesystem::remove_all(temp_root);
  return true;
}

}  // namespace

int main() {
  if (!RunAtomicityTest()) {
    return EXIT_FAILURE;
  }
  std::cout << "chain_state_persistence_tests: OK\n";
  return EXIT_SUCCESS;
}

