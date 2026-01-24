#include <cstdint>
#include <cstdlib>
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
#include "crypto/p2qh_descriptor.hpp"
#include "node/block_builder.hpp"
#include "node/chain_state.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "primitives/transaction.hpp"

using namespace qryptcoin;

namespace {

primitives::CBlock MakeBlock(const primitives::Hash256& prev_hash, std::uint32_t height,
                             std::uint32_t bits, std::uint32_t timestamp) {
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

bool TestGetBlockTemplateRetargetsDifficulty() {
  config::SelectNetwork(config::NetworkType::kRegtest);
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  const std::uint32_t interval = params.difficulty_adjustment_interval;
  if (interval < 2) {
    std::cerr << "block_template_difficulty_tests: invalid interval\n";
    return false;
  }

  auto temp_root =
      std::filesystem::temp_directory_path() / "qryptcoin-block-template-difficulty-test";
  std::filesystem::remove_all(temp_root);
  std::filesystem::create_directories(temp_root);

  node::ChainState chain((temp_root / "blocks.dat").string(), (temp_root / "utxo.dat").string());
  std::string init_error;
  if (!chain.Initialize(&init_error)) {
    std::cerr << "block_template_difficulty_tests: chain init failed: " << init_error << "\n";
    return false;
  }
  if (chain.BlockCount() != 1) {
    std::cerr << "block_template_difficulty_tests: expected 1 block after genesis, got "
              << chain.BlockCount() << "\n";
    return false;
  }

  const std::uint32_t genesis_bits = params.genesis_bits;
  const std::uint32_t base_time = static_cast<std::uint32_t>(params.genesis_time);
  primitives::Hash256 prev_hash = params.genesis_hash;

  for (std::uint32_t height = 1; height < interval; ++height) {
    primitives::CBlock block = MakeBlock(prev_hash, height, genesis_bits, base_time + height);
    if (!MineBlock(&block)) {
      std::cerr << "block_template_difficulty_tests: mining failed at height " << height << "\n";
      return false;
    }
    std::string connect_error;
    if (!chain.ConnectBlock(block, &connect_error)) {
      std::cerr << "block_template_difficulty_tests: ConnectBlock failed at height " << height
                << ": " << connect_error << "\n";
      return false;
    }
    prev_hash = consensus::ComputeBlockHash(block.header);
  }

  const auto* first = chain.GetByHeight(0);
  const auto* last = chain.GetByHeight(interval - 1);
  if (!first || !last) {
    std::cerr << "block_template_difficulty_tests: unable to fetch difficulty window\n";
    return false;
  }

  const std::uint32_t first_time = static_cast<std::uint32_t>(first->header.timestamp);
  const std::uint32_t last_time = static_cast<std::uint32_t>(last->header.timestamp);
  const std::uint32_t expected_bits = consensus::CalculateNextWorkRequired(
      genesis_bits, first_time, last_time, params.target_block_time_seconds, interval,
      params.pow_limit_bits);

  node::BlockTemplate templ;
  crypto::P2QHDescriptor reward{};
  std::string tmpl_error;
  if (!node::BuildBlockTemplate(chain, reward, &templ, &tmpl_error)) {
    std::cerr << "block_template_difficulty_tests: BuildBlockTemplate failed: " << tmpl_error
              << "\n";
    return false;
  }

  if (templ.height != interval) {
    std::cerr << "block_template_difficulty_tests: expected template height " << interval
              << ", got " << templ.height << "\n";
    return false;
  }

  if (templ.block.header.difficulty_bits != expected_bits) {
    std::cerr << "block_template_difficulty_tests: difficulty_bits mismatch at height "
              << templ.height << " (expected " << expected_bits << ", got "
              << templ.block.header.difficulty_bits << ")\n";
    return false;
  }

  // Mine and connect the retarget block at height=interval, then ensure
  // the subsequent template at height=interval+1 carries the new bits
  // forward unchanged.
  {
    primitives::CBlock retarget =
        MakeBlock(prev_hash, interval, expected_bits, base_time + interval);
    if (!MineBlock(&retarget)) {
      std::cerr << "block_template_difficulty_tests: mining failed at retarget height\n";
      return false;
    }
    std::string connect_error;
    if (!chain.ConnectBlock(retarget, &connect_error)) {
      std::cerr << "block_template_difficulty_tests: ConnectBlock failed at retarget height: "
                << connect_error << "\n";
      return false;
    }
    prev_hash = consensus::ComputeBlockHash(retarget.header);
  }

  node::BlockTemplate next_templ;
  if (!node::BuildBlockTemplate(chain, reward, &next_templ, &tmpl_error)) {
    std::cerr << "block_template_difficulty_tests: BuildBlockTemplate failed after retarget: "
              << tmpl_error << "\n";
    return false;
  }
  if (next_templ.height != interval + 1) {
    std::cerr << "block_template_difficulty_tests: expected template height " << (interval + 1)
              << ", got " << next_templ.height << "\n";
    return false;
  }
  if (next_templ.block.header.difficulty_bits != expected_bits) {
    std::cerr << "block_template_difficulty_tests: expected bits to persist after retarget\n";
    return false;
  }

  std::filesystem::remove_all(temp_root);
  return true;
}

}  // namespace

int main() {
  if (!TestGetBlockTemplateRetargetsDifficulty()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
