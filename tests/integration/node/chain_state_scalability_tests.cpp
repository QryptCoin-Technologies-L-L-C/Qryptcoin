#include <chrono>
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
  // Leave coinbase outputs empty so the UTXO set stays bounded in this test.
  coinbase.vout.clear();

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

bool RunChainStateScalabilityTest() {
  using clock = std::chrono::steady_clock;

  config::SelectNetwork(config::NetworkType::kRegtest);
  const auto& params = consensus::Params(config::NetworkType::kRegtest);

  auto temp_root = std::filesystem::temp_directory_path() / "qryptcoin-chainstate-scale-test";
  std::filesystem::remove_all(temp_root);
  std::filesystem::create_directories(temp_root);

  node::ChainState chain((temp_root / "blocks.dat").string(), (temp_root / "utxo.dat").string());
  std::string error;
  if (!chain.Initialize(&error)) {
    std::cerr << "chain_state_scalability_tests: chain init failed: " << error << "\n";
    return false;
  }

  constexpr std::size_t kBlocksToConnect = 5'000;
  constexpr std::size_t kSampleSize = 500;
  static_assert(kSampleSize * 2 < kBlocksToConnect, "sample size must be smaller than half");

  const std::uint32_t bits = params.genesis_bits;
  const std::uint32_t base_time = static_cast<std::uint32_t>(params.genesis_time + 1u);
  const std::uint32_t spacing = params.target_block_time_seconds + 1u;  // keep pow at limit
  primitives::Hash256 prev_hash = params.genesis_hash;

  clock::time_point first_start{};
  clock::time_point first_end{};
  clock::time_point last_start{};
  clock::time_point last_end{};

  for (std::size_t h = 1; h <= kBlocksToConnect; ++h) {
    const auto height = static_cast<std::uint32_t>(h);
    primitives::CBlock block =
        MakeBlock(prev_hash, height, bits, base_time + static_cast<std::uint32_t>(h * spacing));
    if (!MineBlock(&block)) {
      std::cerr << "chain_state_scalability_tests: mining failed at height " << height << "\n";
      return false;
    }
    if (h == 1) {
      first_start = clock::now();
    }
    if (h == kBlocksToConnect - kSampleSize + 1) {
      last_start = clock::now();
    }
    std::string connect_error;
    if (!chain.ConnectBlock(block, &connect_error)) {
      std::cerr << "chain_state_scalability_tests: ConnectBlock failed at height " << height
                << ": " << connect_error << "\n";
      return false;
    }
    prev_hash = consensus::ComputeBlockHash(block.header);
    if (h == kSampleSize) {
      first_end = clock::now();
    }
    if (h == kBlocksToConnect) {
      last_end = clock::now();
    }
  }

  if (chain.Height() != kBlocksToConnect) {
    std::cerr << "chain_state_scalability_tests: unexpected height " << chain.Height()
              << " after connect\n";
    return false;
  }

  const auto first_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(first_end - first_start).count();
  const auto last_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(last_end - last_start).count();
  if (first_ns <= 0 || last_ns <= 0) {
    std::cerr << "chain_state_scalability_tests: timing windows invalid\n";
    return false;
  }
  const double ratio = static_cast<double>(last_ns) / static_cast<double>(first_ns);
  // Connecting blocks should not slow down catastrophically as the chain grows
  // (e.g. from quadratic copying of active-chain state).
  if (ratio > 8.0) {
    std::cerr << "chain_state_scalability_tests: connect slowdown ratio too high: " << ratio
              << "\n";
    return false;
  }

  std::filesystem::remove_all(temp_root);
  return true;
}

}  // namespace

int main() {
  if (!RunChainStateScalabilityTest()) {
    return EXIT_FAILURE;
  }
  std::cout << "chain_state_scalability_tests: OK\n";
  return EXIT_SUCCESS;
}
