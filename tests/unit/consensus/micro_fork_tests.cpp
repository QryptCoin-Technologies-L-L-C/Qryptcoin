#include <filesystem>
#include <iostream>
#include <limits>
#include <string>

#include "config/network.hpp"
#include "consensus/block_hash.hpp"
#include "consensus/monetary.hpp"
#include "consensus/params.hpp"
#include "consensus/pow.hpp"
#include "consensus/witness_commitment.hpp"
#include "node/chain_state.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "primitives/transaction.hpp"

using namespace qryptcoin;

namespace {

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
  coinbase.vout.resize(1);
  coinbase.vout[0].value = consensus::CalculateBlockSubsidy(height);
  coinbase.vout[0].locking_descriptor.clear();

  block.transactions.clear();
  block.transactions.push_back(std::move(coinbase));
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

bool RunMicroForkTest() {
  config::SelectNetwork(config::NetworkType::kRegtest);
  const auto& params = consensus::Params(config::NetworkType::kRegtest);

  auto temp_root = std::filesystem::temp_directory_path() / "qryptcoin-microfork-test";
  std::filesystem::remove_all(temp_root);
  std::filesystem::create_directories(temp_root);

  node::ChainState chain((temp_root / "blocks.dat").string(),
                         (temp_root / "utxo.dat").string());
  std::string error;
  if (!chain.Initialize(&error)) {
    std::cerr << "micro_fork_tests: chain init failed: " << error << "\n";
    return false;
  }
  if (chain.BlockCount() != 1) {
    std::cerr << "micro_fork_tests: expected 1 block after genesis, got "
              << chain.BlockCount() << "\n";
    return false;
  }

  const primitives::Hash256 genesis_hash = params.genesis_hash;
  const std::uint32_t bits = params.genesis_bits;
  const std::uint32_t base_time =
      static_cast<std::uint32_t>(params.genesis_time + 1u);

  auto make_and_connect = [&](const primitives::Hash256& prev_hash,
                              std::uint32_t height,
                              std::uint32_t time_offset,
                              const char* label,
                              primitives::Hash256* out_hash) -> bool {
    primitives::CBlock block =
        MakeBlock(prev_hash, height, bits, base_time + time_offset);
    if (!MineBlock(&block)) {
      std::cerr << "micro_fork_tests: mining failed for " << label << "\n";
      return false;
    }
    std::string connect_error;
    if (!chain.ConnectBlock(block, &connect_error)) {
      std::cerr << "micro_fork_tests: ConnectBlock failed for " << label
                << ": " << connect_error << "\n";
      return false;
    }
    *out_hash = consensus::ComputeBlockHash(block.header);
    return true;
  };

  primitives::Hash256 hash_a1{};
  primitives::Hash256 hash_a2{};
  primitives::Hash256 hash_b1{};
  primitives::Hash256 hash_b2{};
  primitives::Hash256 hash_b3{};

  // Active branch A: genesis -> A1 -> A2.
  if (!make_and_connect(genesis_hash, 1, 1, "A1", &hash_a1)) {
    return false;
  }
  if (!make_and_connect(hash_a1, 2, 2, "A2", &hash_a2)) {
    return false;
  }

  const auto* tip_after_a2 = chain.Tip();
  if (!tip_after_a2 || tip_after_a2->hash != hash_a2) {
    std::cerr << "micro_fork_tests: unexpected tip after A2\n";
    return false;
  }

  // Competing branch B: genesis -> B1 -> B2 (same work as A2) then B3.
  if (!make_and_connect(genesis_hash, 1, 3, "B1", &hash_b1)) {
    return false;
  }
  if (!make_and_connect(hash_b1, 2, 4, "B2", &hash_b2)) {
    return false;
  }

  const auto* tip_after_b2 = chain.Tip();
  if (!tip_after_b2 || tip_after_b2->hash != hash_a2) {
    std::cerr << "micro_fork_tests: chain reorged when cumulative work was equal\n";
    return false;
  }

  const auto telemetry_before = chain.GetTelemetry();

  if (!make_and_connect(hash_b2, 3, 5, "B3", &hash_b3)) {
    return false;
  }

  const auto* tip_after_b3 = chain.Tip();
  if (!tip_after_b3 || tip_after_b3->hash != hash_b3) {
    std::cerr << "micro_fork_tests: chain did not reorg to higher-work branch\n";
    return false;
  }

  const auto telemetry_after = chain.GetTelemetry();
  if (telemetry_after.reorg_events <= telemetry_before.reorg_events) {
    std::cerr << "micro_fork_tests: expected reorg_events to increase\n";
    return false;
  }
  if (telemetry_after.max_reorg_depth < 2) {
    std::cerr << "micro_fork_tests: expected max_reorg_depth >= 2, got "
              << telemetry_after.max_reorg_depth << "\n";
    return false;
  }

  std::filesystem::remove_all(temp_root);
  return true;
}

}  // namespace

int main() {
  if (!RunMicroForkTest()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
