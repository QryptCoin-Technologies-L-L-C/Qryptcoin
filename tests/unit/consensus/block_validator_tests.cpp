#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "config/network.hpp"
#include "consensus/block_hash.hpp"
#include "consensus/block_validator.hpp"
#include "consensus/monetary.hpp"
#include "consensus/params.hpp"
#include "consensus/pow.hpp"
#include "consensus/sighash.hpp"
#include "consensus/witness_commitment.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "primitives/amount.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "primitives/transaction.hpp"
#include "script/p2qh.hpp"
#include "tests/unit/util/deterministic_rng.hpp"

using namespace qryptcoin;

primitives::CTransaction BuildCoinbase(std::uint32_t height, primitives::Amount value) {
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
  tx.vout[0].locking_descriptor.clear();
  return tx;
}

namespace {

using qryptcoin::test::ScopedDeterministicRng;

bool MineBlock(primitives::CBlock* block) {
  if (!block) return false;
  const auto target = consensus::CompactToTarget(block->header.difficulty_bits);
  for (std::uint32_t nonce = 0;; ++nonce) {
    block->header.nonce = nonce;
    const auto hash = consensus::ComputeBlockHash(block->header);
    if (consensus::HashMeetsTarget(hash, target)) {
      return true;
    }
  }
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

struct SpendContext {
  crypto::QPqDilithiumKey dilithium;
  crypto::P2QHDescriptor descriptor;
  std::vector<std::uint8_t> reveal;
  script::ScriptPubKey script;
};

SpendContext BuildSpendContext() {
  SpendContext ctx{
      .dilithium = crypto::QPqDilithiumKey::Generate(),
  };
  ctx.reveal = crypto::BuildP2QHReveal(ctx.dilithium.PublicKey());
  ctx.descriptor = crypto::DescriptorFromReveal(ctx.reveal);
  ctx.script = script::CreateP2QHScript(ctx.descriptor);
  return ctx;
}

bool SignSpend(const SpendContext& ctx,
               const consensus::Coin& coin,
               primitives::CTransaction* tx) {
  if (!tx || tx->vin.empty()) return false;
  const auto sighash = consensus::ComputeSighash(*tx, 0, coin);
  auto sig = ctx.dilithium.Sign(std::span<const std::uint8_t>(sighash.data(), sighash.size()));
  primitives::WitnessStackItem reveal_item{ctx.reveal};
  primitives::WitnessStackItem sig_item{sig};
  tx->vin[0].witness_stack = {reveal_item, sig_item};
  return true;
}

bool BuildWitnessBlock(primitives::CBlock* block,
                       consensus::UTXOSet* view,
                       std::uint32_t height,
                       bool add_coinbase_witness) {
  if (!block || !view) return false;

  ScopedDeterministicRng rng(0xC0FFEE1234567890ULL);
  auto ctx = BuildSpendContext();

  consensus::Coin coin;
  coin.out.value = 10 * primitives::kMiksPerQRY;
  coin.out.locking_descriptor = ctx.script.data;
  coin.coinbase = false;
  coin.height = 0;

  primitives::COutPoint prevout{};
  prevout.txid.fill(0x42);
  prevout.index = 0;
  view->AddCoin(prevout, coin);

  primitives::CTransaction spend;
  spend.version = 2;
  spend.vin.resize(1);
  spend.vin[0].prevout = prevout;
  spend.vin[0].sequence = 0xFFFFFFFFu;
  spend.vout.resize(1);
  spend.vout[0].value = 9 * primitives::kMiksPerQRY;
  spend.vout[0].locking_descriptor = ctx.script.data;
  if (!SignSpend(ctx, coin, &spend)) {
    return false;
  }

  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  primitives::CTransaction coinbase = BuildCoinbase(height, consensus::CalculateBlockSubsidy(height));
  if (add_coinbase_witness && !coinbase.vin.empty()) {
    primitives::WitnessStackItem item;
    item.data = {0xAA, 0xBB};
    coinbase.vin[0].witness_stack = {item};
  }

  block->transactions = {coinbase, spend};
  block->header.version = 1;
  block->header.previous_block_hash.fill(0);
  block->header.timestamp = 0;
  block->header.difficulty_bits = params.pow_limit_bits;
  block->header.nonce = 0;

  const auto witness_root = primitives::ComputeWitnessMerkleRoot(block->transactions);
  SetCoinbaseWitnessCommitment(&block->transactions.front(), height, witness_root);
  block->header.merkle_root = primitives::ComputeMerkleRoot(block->transactions);
  return MineBlock(block);
}

}  // namespace

bool TestGenesisValid() {
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  primitives::CBlock block = params.genesis_block;
  std::string error;
  if (!consensus::ValidateAndApplyBlock(block, 0, /*lock_time_cutoff_time=*/0,
                                        params.max_block_serialized_bytes,
                                        params.witness_commitment_activation_height,
                                        &view, &revealed_pubkeys, &error)) {
    std::cerr << "Genesis block failed validation: " << error << "\n";
    return false;
  }
  if (view.Size() == 0) {
    std::cerr << "Expected UTXO entries after genesis validation\n";
    return false;
  }
  return true;
}

bool TestWitnessCommitmentValid() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  primitives::CBlock block;
  if (!BuildWitnessBlock(&block, &view, /*height=*/1, /*add_coinbase_witness=*/false)) {
    std::cerr << "Failed to build witness test block\n";
    return false;
  }

  std::string error;
  if (!consensus::ValidateAndApplyBlock(block, /*height=*/1, /*lock_time_cutoff_time=*/0,
                                        params.max_block_serialized_bytes,
                                        params.witness_commitment_activation_height,
                                        &view, &revealed_pubkeys, &error)) {
    std::cerr << "Witness-committed block failed validation: " << error << "\n";
    return false;
  }
  return true;
}

bool TestWitnessCommitmentDetectsWitnessMalleation() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  primitives::CBlock block;
  if (!BuildWitnessBlock(&block, &view, /*height=*/1, /*add_coinbase_witness=*/false)) {
    std::cerr << "Failed to build witness malleation test block\n";
    return false;
  }

  // Mutate only the witness data of the non-coinbase transaction without
  // updating the coinbase commitment. The header Merkle root (base txids)
  // remains unchanged, but the witness commitment should reject the block.
  if (block.transactions.size() < 2 || block.transactions[1].vin.empty() ||
      block.transactions[1].vin[0].witness_stack.size() < 2) {
    std::cerr << "Witness malleation test block missing expected witness stack\n";
    return false;
  }
  block.transactions[1].vin[0].witness_stack[1].data.push_back(0x01);

  std::string error;
  if (consensus::ValidateAndApplyBlock(block, /*height=*/1, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected witness-malleated block to fail\n";
    return false;
  }
  if (error.find("witness commitment") == std::string::npos) {
    std::cerr << "Unexpected error for witness malleation test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestWitnessCommitmentMissingRejected() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  primitives::CBlock block;
  if (!BuildWitnessBlock(&block, &view, /*height=*/1, /*add_coinbase_witness=*/false)) {
    std::cerr << "Failed to build missing-commitment test block\n";
    return false;
  }

  // Strip the commitment from the coinbase while keeping the header merkle
  // root consistent with the modified coinbase txid.
  if (block.transactions.empty() || block.transactions.front().vin.empty()) {
    std::cerr << "Missing-commitment test block missing coinbase input\n";
    return false;
  }
  auto& desc = block.transactions.front().vin.front().unlocking_descriptor;
  desc.clear();
  primitives::serialize::WriteVarInt(&desc, static_cast<std::uint64_t>(1));
  primitives::serialize::WriteUint64(&desc, 0);
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  if (!MineBlock(&block)) {
    std::cerr << "Failed to re-mine missing-commitment test header\n";
    return false;
  }

  std::string error;
  if (consensus::ValidateAndApplyBlock(block, /*height=*/1, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected missing-commitment block to fail\n";
    return false;
  }
  if (error.find("witness commitment") == std::string::npos) {
    std::cerr << "Unexpected error for missing-commitment test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestWitnessCommitmentMultipleRejected() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  primitives::CBlock block;
  if (!BuildWitnessBlock(&block, &view, /*height=*/1, /*add_coinbase_witness=*/false)) {
    std::cerr << "Failed to build multiple-commitment test block\n";
    return false;
  }

  if (block.transactions.empty() || block.transactions.front().vin.empty()) {
    std::cerr << "Multiple-commitment test block missing coinbase input\n";
    return false;
  }
  auto& desc = block.transactions.front().vin.front().unlocking_descriptor;
  const auto witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
  desc.insert(desc.end(),
              consensus::kWitnessCommitmentTag.begin(),
              consensus::kWitnessCommitmentTag.end());
  desc.insert(desc.end(), witness_root.begin(), witness_root.end());
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  if (!MineBlock(&block)) {
    std::cerr << "Failed to re-mine multiple-commitment test header\n";
    return false;
  }

  std::string error;
  if (consensus::ValidateAndApplyBlock(block, /*height=*/1, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected multiple-commitment block to fail\n";
    return false;
  }
  if (error.find("witness commitment") == std::string::npos) {
    std::cerr << "Unexpected error for multiple-commitment test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestCoinbaseWitnessWtxidSpecialCase() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  primitives::CBlock block;
  if (!BuildWitnessBlock(&block, &view, /*height=*/1, /*add_coinbase_witness=*/true)) {
    std::cerr << "Failed to build coinbase-witness test block\n";
    return false;
  }

  // Remove the non-coinbase transaction, leaving only the coinbase. The
  // witness tree must still treat coinbase wtxid as zero, so the commitment
  // must be 32 bytes of zero even when the coinbase carries witness data.
  block.transactions.resize(1);
  const primitives::Hash256 witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
  if (witness_root != primitives::Hash256{}) {
    std::cerr << "Expected witness merkle root to be zero for coinbase-only block\n";
    return false;
  }
  SetCoinbaseWitnessCommitment(&block.transactions.front(), /*height=*/1, witness_root);
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  if (!MineBlock(&block)) {
    std::cerr << "Failed to mine coinbase-witness test header\n";
    return false;
  }

  std::string error;
  if (!consensus::ValidateAndApplyBlock(block, /*height=*/1, /*lock_time_cutoff_time=*/0,
                                        params.max_block_serialized_bytes,
                                        params.witness_commitment_activation_height,
                                        &view, &revealed_pubkeys, &error)) {
    std::cerr << "Coinbase-witness block failed validation: " << error << "\n";
    return false;
  }
  return true;
}

bool TestCoinbaseOutputOutOfRange() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  primitives::CBlock block;
  block.transactions = {BuildCoinbase(/*height=*/0, primitives::kMaxMoney + 1)};
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  block.header.version = 1;
  block.header.previous_block_hash.fill(0);
  block.header.timestamp = 0;
  block.header.nonce = 0;
  block.header.difficulty_bits = params.pow_limit_bits;
  if (!MineBlock(&block)) {
    std::cerr << "Failed to mine out-of-range coinbase header\n";
    return false;
  }

  std::string error;
  if (consensus::ValidateAndApplyBlock(block, 0, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected out-of-range coinbase to fail validation\n";
    return false;
  }
  if (error.find("coinbase output out of range") == std::string::npos) {
    std::cerr << "Unexpected error for coinbase out-of-range test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestInputOutOfRangeRejected() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  consensus::Coin coin;
  coin.out.value = primitives::kMaxMoney + 1;
  coin.out.locking_descriptor.clear();
  coin.coinbase = false;
  coin.height = 0;
  primitives::COutPoint prevout{};
  prevout.txid.fill(0x11);
  prevout.index = 0;
  view.AddCoin(prevout, coin);

  primitives::CTransaction tx;
  tx.version = 1;
  tx.vin.resize(1);
  tx.vin[0].prevout = prevout;
  tx.vin[0].sequence = 0xFFFFFFFFu;
  tx.vout.resize(1);
  tx.vout[0].value = 1;
  tx.vout[0].locking_descriptor.clear();

  primitives::CBlock block;
  block.transactions = {BuildCoinbase(/*height=*/1, consensus::CalculateBlockSubsidy(1)), tx};
  const auto witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
  SetCoinbaseWitnessCommitment(&block.transactions.front(), /*height=*/1, witness_root);
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  block.header.version = 1;
  block.header.previous_block_hash.fill(0);
  block.header.timestamp = 0;
  block.header.nonce = 0;
  block.header.difficulty_bits = params.pow_limit_bits;
  if (!MineBlock(&block)) {
    std::cerr << "Failed to mine out-of-range input test header\n";
    return false;
  }

  std::string error;
  if (consensus::ValidateAndApplyBlock(block, 1, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected out-of-range input to fail validation\n";
    return false;
  }
  if (error.find("input amount out of range") == std::string::npos) {
    std::cerr << "Unexpected error for input out-of-range test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestInvalidMerkleRoot() {
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  primitives::CBlock block = params.genesis_block;
  // Flip a bit in the Merkle root so that it no longer matches the
  // transactions vector while keeping everything else constant.
  block.header.merkle_root[0] ^= 0x01;
  std::string error;
  if (consensus::ValidateAndApplyBlock(block, 0, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected Merkle root mismatch to fail validation\n";
    return false;
  }
  if (error.find("merkle root mismatch") == std::string::npos) {
    std::cerr << "Unexpected error for Merkle test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestInvalidDifficultyTarget() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  primitives::CBlock block;
  block.header.version = 1;
  block.header.previous_block_hash.fill(0);
  block.header.timestamp = 0;
  // Force an invalid compact target encoding that maps to an all-zero
  // target, which should be rejected by consensus as nonsensical.
  block.header.difficulty_bits = 0;
  block.header.nonce = 0;
  block.transactions = {BuildCoinbase(/*height=*/1, consensus::CalculateBlockSubsidy(1))};
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  std::string error;
  // Use a non-genesis height so that proof-of-work and difficulty
  // checks are exercised in a non-bootstrap context.
  if (consensus::ValidateAndApplyBlock(block, 1, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected invalid difficulty target to fail validation\n";
    return false;
  }
  if (error.find("invalid difficulty target") == std::string::npos) {
    std::cerr << "Unexpected error for difficulty test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestBadCoinbaseStructure() {
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  primitives::CBlock block = params.genesis_block;
  // Violate the coinbase structure by adding a second coinbase-like
  // transaction at index 1.
  block.transactions.push_back(block.transactions.front());
  // Update the witness commitment and Merkle root so structural coinbase
  // checks are exercised instead of failing early on a header mismatch.
  const auto witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
  SetCoinbaseWitnessCommitment(&block.transactions.front(), /*height=*/0, witness_root);
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  if (!MineBlock(&block)) {
    std::cerr << "Failed to mine bad-coinbase-structure test header\n";
    return false;
  }
  std::string error;
  if (consensus::ValidateAndApplyBlock(block, 0, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected second coinbase to fail validation\n";
    return false;
  }
  if (error.find("additional coinbase") == std::string::npos) {
    std::cerr << "Unexpected error for coinbase test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestPubkeyReuseAcrossBlockTransactions() {
  const auto& params = consensus::Params(config::NetworkType::kRegtest);
  consensus::UTXOSet view;
  consensus::RevealedPubkeySet revealed_pubkeys;

  ScopedDeterministicRng rng(0x1122334455667788ULL);
  auto ctx = BuildSpendContext();

  consensus::Coin coin0;
  coin0.out.value = 10 * primitives::kMiksPerQRY;
  coin0.out.locking_descriptor = ctx.script.data;
  coin0.coinbase = false;
  coin0.height = 0;

  consensus::Coin coin1 = coin0;

  primitives::COutPoint prev0{};
  prev0.txid.fill(0x10);
  prev0.index = 0;
  primitives::COutPoint prev1{};
  prev1.txid.fill(0x11);
  prev1.index = 0;
  view.AddCoin(prev0, coin0);
  view.AddCoin(prev1, coin1);

  primitives::CTransaction spend0;
  spend0.version = 2;
  spend0.vin.resize(1);
  spend0.vin[0].prevout = prev0;
  spend0.vin[0].sequence = 0xFFFFFFFFu;
  spend0.vout.resize(1);
  spend0.vout[0].value = 9 * primitives::kMiksPerQRY;
  spend0.vout[0].locking_descriptor = ctx.script.data;
  if (!SignSpend(ctx, coin0, &spend0)) {
    std::cerr << "Failed to sign first spend for pubkey reuse block test\n";
    return false;
  }

  primitives::CTransaction spend1 = spend0;
  spend1.vin[0].prevout = prev1;
  if (!SignSpend(ctx, coin1, &spend1)) {
    std::cerr << "Failed to sign second spend for pubkey reuse block test\n";
    return false;
  }

  primitives::CBlock block;
  const std::uint32_t height = 1;
  primitives::CTransaction coinbase = BuildCoinbase(height, consensus::CalculateBlockSubsidy(height));
  block.transactions = {coinbase, spend0, spend1};
  block.header.version = 1;
  block.header.previous_block_hash.fill(0);
  block.header.timestamp = 0;
  block.header.difficulty_bits = params.pow_limit_bits;
  block.header.nonce = 0;

  const auto witness_root = primitives::ComputeWitnessMerkleRoot(block.transactions);
  SetCoinbaseWitnessCommitment(&block.transactions.front(), height, witness_root);
  block.header.merkle_root = primitives::ComputeMerkleRoot(block.transactions);
  if (!MineBlock(&block)) {
    std::cerr << "Failed to mine pubkey reuse test block\n";
    return false;
  }

  std::string error;
  if (consensus::ValidateAndApplyBlock(block, height, /*lock_time_cutoff_time=*/0,
                                       params.max_block_serialized_bytes,
                                       params.witness_commitment_activation_height,
                                       &view, &revealed_pubkeys, &error)) {
    std::cerr << "Expected block with repeated pubkey reveal to fail\n";
    return false;
  }
  if (error.find("public key already revealed") == std::string::npos) {
    std::cerr << "Unexpected error for pubkey reuse block test: " << error << "\n";
    return false;
  }
  return true;
}

int main() {
  if (!TestGenesisValid()) {
    return EXIT_FAILURE;
  }
  if (!TestWitnessCommitmentValid()) {
    return EXIT_FAILURE;
  }
  if (!TestWitnessCommitmentDetectsWitnessMalleation()) {
    return EXIT_FAILURE;
  }
  if (!TestWitnessCommitmentMissingRejected()) {
    return EXIT_FAILURE;
  }
  if (!TestWitnessCommitmentMultipleRejected()) {
    return EXIT_FAILURE;
  }
  if (!TestCoinbaseWitnessWtxidSpecialCase()) {
    return EXIT_FAILURE;
  }
  if (!TestCoinbaseOutputOutOfRange()) {
    return EXIT_FAILURE;
  }
  if (!TestInputOutOfRangeRejected()) {
    return EXIT_FAILURE;
  }
  if (!TestInvalidMerkleRoot()) {
    return EXIT_FAILURE;
  }
  if (!TestInvalidDifficultyTarget()) {
    return EXIT_FAILURE;
  }
  if (!TestBadCoinbaseStructure()) {
    return EXIT_FAILURE;
  }
  if (!TestPubkeyReuseAcrossBlockTransactions()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
