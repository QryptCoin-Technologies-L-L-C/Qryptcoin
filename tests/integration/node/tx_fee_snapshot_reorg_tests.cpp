#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "config/network.hpp"
#include "consensus/block_hash.hpp"
#include "consensus/monetary.hpp"
#include "consensus/params.hpp"
#include "consensus/pow.hpp"
#include "consensus/sighash.hpp"
#include "consensus/witness_commitment.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "node/chain_state.hpp"
#include "primitives/amount.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "primitives/transaction.hpp"
#include "primitives/txid.hpp"
#include "script/p2qh.hpp"
#include "tests/unit/util/deterministic_rng.hpp"

using namespace qryptcoin;

namespace {

using qryptcoin::test::ScopedDeterministicRng;

primitives::CTransaction BuildCoinbase(std::uint32_t height,
                                      primitives::Amount value,
                                      std::vector<std::uint8_t> locking_descriptor) {
  primitives::CTransaction tx;
  tx.version = 1;
  tx.vin.resize(1);
  tx.vin[0].prevout = primitives::COutPoint::Null();
  tx.vin[0].sequence = 0xFFFFFFFFu;
  primitives::serialize::WriteVarInt(&tx.vin[0].unlocking_descriptor, height);
  primitives::serialize::WriteUint64(&tx.vin[0].unlocking_descriptor, 0);
  tx.vin[0].unlocking_descriptor.insert(tx.vin[0].unlocking_descriptor.end(),
                                        consensus::kWitnessCommitmentTag.begin(),
                                        consensus::kWitnessCommitmentTag.end());
  tx.vin[0].unlocking_descriptor.resize(tx.vin[0].unlocking_descriptor.size() +
                                        primitives::Hash256{}.size());
  tx.vout.resize(1);
  tx.vout[0].value = value;
  tx.vout[0].locking_descriptor = std::move(locking_descriptor);
  return tx;
}

void SetCoinbaseWitnessCommitment(primitives::CTransaction* coinbase,
                                 std::uint32_t height,
                                 const primitives::Hash256& witness_root) {
  if (!coinbase || coinbase->vin.empty()) {
    return;
  }
  std::vector<std::uint8_t> rebuilt;
  primitives::serialize::WriteVarInt(&rebuilt, static_cast<std::uint64_t>(height));
  primitives::serialize::WriteUint64(&rebuilt, 0);
  rebuilt.insert(rebuilt.end(),
                 consensus::kWitnessCommitmentTag.begin(),
                 consensus::kWitnessCommitmentTag.end());
  rebuilt.insert(rebuilt.end(), witness_root.begin(), witness_root.end());
  coinbase->vin[0].unlocking_descriptor = std::move(rebuilt);
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

primitives::Hash256 HashBlock(const primitives::CBlock& block) {
  return consensus::ComputeBlockHash(block.header);
}

bool ConnectOrFail(node::ChainState* chain, const primitives::CBlock& block,
                   const char* label) {
  std::string error;
  if (!chain->ConnectBlock(block, &error)) {
    std::cerr << "tx_fee_snapshot_reorg_tests: ConnectBlock failed for " << label
              << ": " << error << "\n";
    return false;
  }
  return true;
}

primitives::CTransaction BuildSpendTx(const primitives::Hash256& prev_txid,
                                     std::uint32_t prev_index,
                                     const consensus::Coin& spent_coin,
                                     const crypto::QPqDilithiumKey& key,
                                     const std::vector<std::uint8_t>& reveal,
                                     const std::vector<std::uint8_t>& output_locking_descriptor,
                                     primitives::Amount fee_miks) {
  primitives::CTransaction spend;
  spend.version = 2;
  spend.lock_time = 0;
  spend.vin.resize(1);
  spend.vin[0].prevout.txid = prev_txid;
  spend.vin[0].prevout.index = prev_index;
  spend.vin[0].sequence = 0xFFFFFFFFu;
  spend.vout.resize(1);
  primitives::Amount output_value = 0;
  (void)primitives::CheckedSub(spent_coin.out.value, fee_miks, &output_value);
  spend.vout[0].value = output_value;
  spend.vout[0].locking_descriptor = output_locking_descriptor;

  const auto sighash = consensus::ComputeSighash(spend, 0, spent_coin);
  const auto sig = key.Sign(std::span<const std::uint8_t>(sighash.data(), sighash.size()));
  primitives::WitnessStackItem reveal_item{reveal};
  primitives::WitnessStackItem sig_item{sig};
  spend.vin[0].witness_stack = {reveal_item, sig_item};
  return spend;
}

bool RunTxFeeSnapshotReorgTest() {
  config::SelectNetwork(config::NetworkType::kRegtest);
  const auto& params = consensus::Params(config::NetworkType::kRegtest);

  const auto temp_root =
      std::filesystem::temp_directory_path() / "qryptcoin-tx-fee-snapshot-reorg";
  std::filesystem::remove_all(temp_root);
  std::filesystem::create_directories(temp_root);

  ScopedDeterministicRng rng(0xB0);
  const auto spend_key = crypto::QPqDilithiumKey::Generate();
  const auto reveal = crypto::BuildP2QHReveal(spend_key.PublicKey());
  const auto descriptor = crypto::DescriptorFromReveal(reveal);
  const auto spend_script = script::CreateP2QHScript(descriptor);

  const auto blocks_path = (temp_root / "blocks.dat").string();
  const auto utxo_path = (temp_root / "utxo.dat").string();

  node::ChainState chain(blocks_path, utxo_path);
  std::string init_error;
  if (!chain.Initialize(&init_error)) {
    std::cerr << "tx_fee_snapshot_reorg_tests: chain init failed: " << init_error << "\n";
    return false;
  }

  const std::uint32_t bits = params.pow_limit_bits;
  const std::uint32_t base_time = static_cast<std::uint32_t>(params.genesis_time + 1u);

  primitives::Hash256 prev_hash = params.genesis_hash;
  primitives::Hash256 hash_h101{};
  primitives::Hash256 coinbase1_txid{};

  // Build a chain long enough to spend the height-1 coinbase.
  for (std::uint32_t height = 1; height <= 101; ++height) {
    primitives::CBlock block;
    block.header.version = 1;
    block.header.previous_block_hash = prev_hash;
    block.header.timestamp = base_time + height;
    block.header.difficulty_bits = bits;
    block.header.nonce = 0;

    std::vector<std::uint8_t> locking_descriptor;
    if (height == 1) {
      locking_descriptor = spend_script.data;
    }
    primitives::CTransaction coinbase =
        BuildCoinbase(height, consensus::CalculateBlockSubsidy(height), locking_descriptor);
    block.transactions = {coinbase};

    const auto witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
    SetCoinbaseWitnessCommitment(&block.transactions.front(), height, witness_root);
    block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
    if (!MineBlock(&block)) {
      std::cerr << "tx_fee_snapshot_reorg_tests: mining failed at height " << height << "\n";
      return false;
    }
    if (!ConnectOrFail(&chain, block, "A")) {
      return false;
    }

    prev_hash = HashBlock(block);
    if (height == 1) {
      coinbase1_txid = primitives::ComputeTxId(block.transactions.front());
    }
    if (height == 101) {
      hash_h101 = prev_hash;
    }
  }

  consensus::Coin coinbase_coin;
  primitives::COutPoint outpoint;
  outpoint.txid = coinbase1_txid;
  outpoint.index = 0;
  if (!chain.GetCoin(outpoint, &coinbase_coin)) {
    std::cerr << "tx_fee_snapshot_reorg_tests: failed to fetch coinbase UTXO\n";
    return false;
  }

  const primitives::Amount expected_fee = 20'000;
  primitives::CTransaction spend_tx = BuildSpendTx(
      coinbase1_txid, 0, coinbase_coin, spend_key, reveal, spend_script.data, expected_fee);
  const auto spend_txid = primitives::ComputeTxId(spend_tx);

  // Extend chain A with a block that includes the spend.
  {
    const std::uint32_t height = 102;
    primitives::CBlock block;
    block.header.version = 1;
    block.header.previous_block_hash = prev_hash;
    block.header.timestamp = base_time + height;
    block.header.difficulty_bits = bits;
    block.header.nonce = 0;
    primitives::CTransaction coinbase =
        BuildCoinbase(height, consensus::CalculateBlockSubsidy(height), spend_script.data);
    block.transactions = {coinbase, spend_tx};
    const auto witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
    SetCoinbaseWitnessCommitment(&block.transactions.front(), height, witness_root);
    block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
    if (!MineBlock(&block)) {
      std::cerr << "tx_fee_snapshot_reorg_tests: mining failed at height " << height << "\n";
      return false;
    }
    if (!ConnectOrFail(&chain, block, "A102")) {
      return false;
    }
    prev_hash = HashBlock(block);
  }

  {
    primitives::Amount fee = 0;
    if (!chain.GetTxFee(spend_txid, &fee) || fee != expected_fee) {
      std::cerr << "tx_fee_snapshot_reorg_tests: expected fee present on chain A\n";
      return false;
    }
  }

  // Build a longer competing chain B from height 101 (excluding the spend).
  primitives::Hash256 b102_hash{};
  {
    const std::uint32_t height = 102;
    primitives::CBlock block;
    block.header.version = 1;
    block.header.previous_block_hash = hash_h101;
    block.header.timestamp = base_time + 5000u + height;
    block.header.difficulty_bits = bits;
    block.header.nonce = 0;
    primitives::CTransaction coinbase =
        BuildCoinbase(height, consensus::CalculateBlockSubsidy(height), spend_script.data);
    block.transactions = {coinbase};
    const auto witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
    SetCoinbaseWitnessCommitment(&block.transactions.front(), height, witness_root);
    block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
    if (!MineBlock(&block)) {
      std::cerr << "tx_fee_snapshot_reorg_tests: mining failed at height " << height << " (B102)\n";
      return false;
    }
    if (!ConnectOrFail(&chain, block, "B102")) {
      return false;
    }
    b102_hash = HashBlock(block);
  }
  {
    const std::uint32_t height = 103;
    primitives::CBlock block;
    block.header.version = 1;
    block.header.previous_block_hash = b102_hash;
    block.header.timestamp = base_time + 5000u + height;
    block.header.difficulty_bits = bits;
    block.header.nonce = 0;
    primitives::CTransaction coinbase =
        BuildCoinbase(height, consensus::CalculateBlockSubsidy(height), spend_script.data);
    block.transactions = {coinbase};
    const auto witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
    SetCoinbaseWitnessCommitment(&block.transactions.front(), height, witness_root);
    block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
    if (!MineBlock(&block)) {
      std::cerr << "tx_fee_snapshot_reorg_tests: mining failed at height " << height << " (B103)\n";
      return false;
    }
    if (!ConnectOrFail(&chain, block, "B103")) {
      return false;
    }
  }

  if (chain.Height() != 103) {
    std::cerr << "tx_fee_snapshot_reorg_tests: expected height 103 after reorg, got "
              << chain.Height() << "\n";
    return false;
  }

  {
    primitives::Amount fee = 0;
    if (chain.GetTxFee(spend_txid, &fee)) {
      std::cerr << "tx_fee_snapshot_reorg_tests: fee should be absent after reorg\n";
      return false;
    }
  }

  // Restart should preserve the active-chain view (snapshot is tied to the tip hash).
  node::ChainState chain2(blocks_path, utxo_path);
  std::string init2_error;
  if (!chain2.Initialize(&init2_error)) {
    std::cerr << "tx_fee_snapshot_reorg_tests: chain2 init failed: " << init2_error << "\n";
    return false;
  }
  if (chain2.Height() != 103) {
    std::cerr << "tx_fee_snapshot_reorg_tests: expected chain2 height 103, got "
              << chain2.Height() << "\n";
    return false;
  }
  {
    primitives::Amount fee = 0;
    if (chain2.GetTxFee(spend_txid, &fee)) {
      std::cerr << "tx_fee_snapshot_reorg_tests: chain2 should not contain fee for orphaned tx\n";
      return false;
    }
  }

  std::filesystem::remove_all(temp_root);
  return true;
}

}  // namespace

int main() {
  if (!RunTxFeeSnapshotReorgTest()) {
    return EXIT_FAILURE;
  }
  std::cout << "tx_fee_snapshot_reorg_tests: OK\n";
  return EXIT_SUCCESS;
}
