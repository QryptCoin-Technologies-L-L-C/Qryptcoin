#include "node/chain_state.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <unordered_set>
#include <span>
#include <utility>

#include "config/network.hpp"
#include "consensus/block_hash.hpp"
#include "consensus/block_validator.hpp"
#include "consensus/params.hpp"
#include "consensus/pow.hpp"
#include "consensus/tx_validator.hpp"
#include "storage/block_store.hpp"
#include "storage/revealed_pubkeys_snapshot.hpp"
#include "storage/utxo_snapshot.hpp"
#include "util/atomic_file.hpp"
#include "util/hex.hpp"

namespace qryptcoin::node {

namespace {

// Consensus-critical timestamp rules:
// - MedianTimePast is computed over the prior 11 blocks (or fewer near genesis).
// - Blocks must be strictly greater than MTP to resist time-warp attacks.
// - Blocks must not be too far in the future relative to local wall-clock.
constexpr std::size_t kMedianTimeSpan = 11;
constexpr std::uint64_t kMaxFutureBlockTimeSeconds = 2ull * 60ull * 60ull;  // 2 hours

std::filesystem::path SnapshotMetaPath(const std::string& snapshot_path) {
  return std::filesystem::path(snapshot_path).concat(".meta");
}

bool ReadSnapshotTipMeta(const std::string& snapshot_path,
                         std::uint32_t* out_height,
                         std::string* out_hash_hex) {
  std::ifstream in(SnapshotMetaPath(snapshot_path));
  if (!in.is_open()) {
    return false;
  }
  std::string height_line;
  std::string hash_line;
  if (!std::getline(in, height_line)) {
    return false;
  }
  if (!std::getline(in, hash_line)) {
    return false;
  }
  if (hash_line.empty()) {
    return false;
  }
  std::uint64_t height64 = 0;
  try {
    std::size_t consumed = 0;
    height64 = std::stoull(height_line, &consumed, 10);
    if (consumed == 0) {
      return false;
    }
  } catch (...) {
    return false;
  }
  if (out_height) {
    *out_height = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(height64, std::numeric_limits<std::uint32_t>::max()));
  }
  if (out_hash_hex) {
    *out_hash_hex = hash_line;
  }
  return true;
}

bool WriteSnapshotTipMeta(const std::string& snapshot_path,
                          std::uint32_t height,
                          const std::string& hash_hex,
                          std::string* error) {
  const std::string payload = std::to_string(height) + "\n" + hash_hex + "\n";
  return util::AtomicWriteFile(
      SnapshotMetaPath(snapshot_path),
      [&](std::ofstream& out) {
        out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        out.flush();
        return out.good();
      },
      error);
}

}  // namespace

ChainState::ChainState(std::string block_path, std::string utxo_path)
    : block_path_(std::move(block_path)), utxo_path_(std::move(utxo_path)) {
  revealed_pubkeys_path_ = utxo_path_ + ".pubkeys";
  snapshot_saver_ = &storage::SaveUTXOSnapshot;
}

void ChainState::SetSnapshotSaverForTest(SnapshotSaverFn saver) {
  std::unique_lock<std::shared_mutex> lock(mutex_);
  snapshot_saver_ = saver ? saver : &storage::SaveUTXOSnapshot;
}

bool ChainState::Initialize(std::string* error) {
  std::unique_lock<std::shared_mutex> lock(mutex_);
  if (!LoadBlocksLocked(error)) {
    return false;
  }
  if (block_index_.empty()) {
    if (!InitializeGenesisLocked(error)) {
      return false;
    }
  }
  if (!best_tip_) {
    if (error) *error = "no best tip available";
    return false;
  }
  return EnsureUtxoSnapshotLocked(error);
}

std::size_t ChainState::BlockCount() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return active_chain_.size();
}

bool ChainState::Empty() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return active_chain_.empty();
}

std::size_t ChainState::Height() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  if (active_chain_.empty()) return 0;
  return active_chain_.back()->height;
}

const BlockRecord* ChainState::Tip() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  if (active_chain_.empty()) return nullptr;
  return active_chain_.back();
}

const BlockRecord* ChainState::GetByHash(const std::string& hash_hex) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  auto it = block_index_.find(hash_hex);
  if (it == block_index_.end()) return nullptr;
  return it->second.get();
}

const BlockRecord* ChainState::GetByHeight(std::size_t height) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  if (height >= active_chain_.size()) return nullptr;
  return active_chain_[height];
}

std::size_t ChainState::UtxoEntries() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return utxo_.Size();
}

std::size_t ChainState::RevealedPubkeyEntries() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return revealed_pubkeys_.Size();
}

bool ChainState::CheckTransaction(const primitives::CTransaction& tx,
                                  std::string* error) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  if (!best_tip_) {
    if (error) {
      *error = "no active chain";
    }
    return false;
  }
  const auto spending_height = static_cast<std::uint32_t>(best_tip_->height + 1);
  const auto lock_time_cutoff_time = MedianTimePastForIndexLocked(active_chain_, active_chain_.size());
  return consensus::ValidateTransaction(tx, utxo_, revealed_pubkeys_, spending_height,
                                        lock_time_cutoff_time, nullptr, error);
}

consensus::UTXOSet ChainState::SnapshotUtxo() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return utxo_;
}

consensus::RevealedPubkeySet ChainState::SnapshotRevealedPubkeys() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return revealed_pubkeys_;
}

bool ChainState::GetCoin(const primitives::COutPoint& outpoint,
                         consensus::Coin* coin) const {
  if (!coin) {
    return false;
  }
  std::shared_lock<std::shared_mutex> lock(mutex_);
  const auto* found = utxo_.GetCoin(outpoint);
  if (!found) {
    return false;
  }
  *coin = *found;
  return true;
}

bool ChainState::GetCoinMetadata(const primitives::COutPoint& outpoint,
                                 std::uint32_t* height,
                                 bool* coinbase) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  const auto* coin = utxo_.GetCoin(outpoint);
  if (!coin) {
    return false;
  }
  if (height) {
    *height = coin->height;
  }
  if (coinbase) {
    *coinbase = coin->coinbase;
  }
  return true;
}

bool ChainState::ConnectBlock(const primitives::CBlock& block, std::string* error) {
  std::unique_lock<std::shared_mutex> lock(mutex_);
  BlockRecord* record = AddBlockRecordLocked(block.header, std::nullopt, error, false);
  if (!record) {
    if (error && *error == "unknown parent") {
      ++orphan_blocks_;
    }
    return false;
  }

  // If the block cannot become the best-work tip, keep it in memory (for
  // potential future reorgs) but avoid persisting unvalidated side-chain data
  // to disk.
  if (best_tip_ && record->chain_work <= best_chain_work_) {
    CacheBlockLocked(record->hash_hex, block);
    return true;
  }

  const auto& params = consensus::Params(config::GetNetworkConfig().type);

  auto capture_store_size = [&]() -> std::pair<std::uint64_t, bool> {
    std::uint64_t store_size_before = 0;
    bool have_store_size_before = true;
    std::error_code ec;
    if (std::filesystem::exists(block_path_, ec)) {
      store_size_before =
          static_cast<std::uint64_t>(std::filesystem::file_size(block_path_, ec));
      if (ec) {
        have_store_size_before = false;
      }
    } else if (ec) {
      have_store_size_before = false;
    }
    return {store_size_before, have_store_size_before};
  };

  auto rollback_store = [&](std::uint64_t size_before, bool have_size_before) {
    if (!have_size_before) {
      return;
    }
    std::error_code ec;
    std::filesystem::resize_file(block_path_, static_cast<std::uintmax_t>(size_before), ec);
    if (ec) {
      std::cerr << "[chain] warn: failed to rollback block store append: " << ec.message()
                << "\n";
    }
  };

  bool chain_changed = false;
  storage::BlockStore store(block_path_);

  // Fast-path: candidate extends the current active tip.
  if (!active_chain_.empty() && record->parent == active_chain_.back()) {
    std::string validation_error;
    std::uint64_t lock_time_cutoff_time = 0;
    if (!CheckNextBlockContextLocked(block.header, static_cast<std::uint32_t>(record->height),
                                     &lock_time_cutoff_time, &validation_error)) {
      block_index_.erase(record->hash_hex);
      RecalculateBestTipLocked();
      if (error) *error = "validation failed: " + validation_error;
      return false;
    }

    consensus::UTXOSet working = utxo_;
    consensus::RevealedPubkeySet working_pubkeys = revealed_pubkeys_;
    if (!consensus::ValidateAndApplyBlock(block, static_cast<std::uint32_t>(record->height),
                                          lock_time_cutoff_time, params.max_block_serialized_bytes,
                                          params.witness_commitment_activation_height,
                                          &working, &working_pubkeys, &validation_error)) {
      block_index_.erase(record->hash_hex);
      RecalculateBestTipLocked();
      if (error) *error = "validation failed: " + validation_error;
      return false;
    }

    const auto [store_size_before, have_store_size_before] = capture_store_size();
    std::uint64_t disk_offset = std::numeric_limits<std::uint64_t>::max();
    if (!store.Append(block, &disk_offset)) {
      block_index_.erase(record->hash_hex);
      RecalculateBestTipLocked();
      rollback_store(store_size_before, have_store_size_before);
      if (error) *error = "failed to append block";
      return false;
    }
    if (have_store_size_before) {
      record->disk_offset = store_size_before;
    } else if (disk_offset != std::numeric_limits<std::uint64_t>::max()) {
      record->disk_offset = disk_offset;
    }
    RemoveCachedBlockLocked(record->hash_hex);

    utxo_ = std::move(working);
    revealed_pubkeys_ = std::move(working_pubkeys);
    active_chain_.push_back(record);
    record->in_active_chain = true;
    best_tip_ = record;
    best_chain_work_ = record->chain_work;
    chain_changed = true;
  } else {
    // Reorg: rebuild and validate the candidate chain before writing to disk.
    std::vector<BlockRecord*> new_chain;
    BuildActiveChainLocked(record, &new_chain);
    consensus::UTXOSet rebuilt;
    consensus::RevealedPubkeySet rebuilt_pubkeys;
    for (std::size_t idx = 0; idx < new_chain.size(); ++idx) {
      std::string block_error;
      primitives::CBlock candidate_block;
      if (!LoadBlockDataLocked(new_chain[idx], new_chain[idx] == record ? &block : nullptr,
                               &candidate_block, &block_error)) {
        block_index_.erase(record->hash_hex);
        RecalculateBestTipLocked();
        if (error) *error = "validation failed: " + block_error;
        return false;
      }
      std::uint64_t lock_time_cutoff_time = 0;
      if (!CheckTimeForIndexLocked(new_chain, idx, &lock_time_cutoff_time, &block_error) ||
          !CheckDifficultyForIndexLocked(new_chain, idx, &block_error) ||
          !consensus::ValidateAndApplyBlock(candidate_block, static_cast<std::uint32_t>(idx),
                                            lock_time_cutoff_time,
                                            params.max_block_serialized_bytes,
                                            params.witness_commitment_activation_height,
                                            &rebuilt, &rebuilt_pubkeys, &block_error)) {
        block_index_.erase(record->hash_hex);
        RecalculateBestTipLocked();
        if (error) *error = "validation failed: " + block_error;
        return false;
      }
    }

    std::size_t common = 0;
    const std::size_t old_size = active_chain_.size();
    const std::size_t new_size = new_chain.size();
    const std::size_t limit = std::min(old_size, new_size);
    while (common < limit && active_chain_[common] == new_chain[common]) {
      ++common;
    }
    const std::size_t old_depth = old_size > common ? (old_size - common) : 0;
    if (old_depth > 0) {
      ++reorg_events_;
      if (old_depth > max_reorg_depth_) {
        max_reorg_depth_ = old_depth;
      }
    }

    const auto [store_size_before, have_store_size_before] = capture_store_size();
    std::vector<std::pair<BlockRecord*, std::uint64_t>> new_disk_offsets;
    new_disk_offsets.reserve(new_chain.size() - common);
    std::vector<std::string> cached_hashes_to_remove;
    cached_hashes_to_remove.reserve(new_chain.size() - common);
    for (std::size_t idx = common; idx < new_chain.size(); ++idx) {
      std::string block_error;
      primitives::CBlock append_block;
      if (!LoadBlockDataLocked(new_chain[idx], new_chain[idx] == record ? &block : nullptr,
                               &append_block, &block_error)) {
        rollback_store(store_size_before, have_store_size_before);
        block_index_.erase(record->hash_hex);
        RecalculateBestTipLocked();
        if (error) *error = "failed to load reorg blocks: " + block_error;
        return false;
      }
      std::uint64_t disk_offset = std::numeric_limits<std::uint64_t>::max();
      if (!store.Append(append_block, &disk_offset)) {
        rollback_store(store_size_before, have_store_size_before);
        block_index_.erase(record->hash_hex);
        RecalculateBestTipLocked();
        if (error) *error = "failed to append reorg blocks";
        return false;
      }
      if (!new_chain[idx]->disk_offset.has_value()) {
        if (disk_offset == std::numeric_limits<std::uint64_t>::max()) {
          rollback_store(store_size_before, have_store_size_before);
          block_index_.erase(record->hash_hex);
          RecalculateBestTipLocked();
          if (error) *error = "failed to track reorg block disk position";
          return false;
        }
        new_disk_offsets.emplace_back(new_chain[idx], disk_offset);
      }
      cached_hashes_to_remove.push_back(new_chain[idx]->hash_hex);
    }
    for (const auto& [node, offset] : new_disk_offsets) {
      if (node) {
        node->disk_offset = offset;
      }
    }
    for (const auto& hex : cached_hashes_to_remove) {
      RemoveCachedBlockLocked(hex);
    }

    ResetActiveFlagsLocked();
    active_chain_ = std::move(new_chain);
    for (auto* node : active_chain_) {
      node->in_active_chain = true;
    }
    utxo_ = std::move(rebuilt);
    revealed_pubkeys_ = std::move(rebuilt_pubkeys);
    best_tip_ = record;
    best_chain_work_ = record->chain_work;
    chain_changed = true;
  }

  if (chain_changed) {
    // Persistence is best-effort: once a block is connected, it remains
    // connected even if snapshot IO fails. Snapshot writes only accelerate
    // restarts and do not affect consensus correctness.
    bool utxo_snapshot_ok = snapshot_saver_ && snapshot_saver_(utxo_, utxo_path_);
    bool pubkeys_snapshot_ok =
        storage::SaveRevealedPubkeysSnapshot(revealed_pubkeys_, revealed_pubkeys_path_);

    if (!utxo_snapshot_ok) {
      ++utxo_snapshot_failures_;
      utxo_snapshot_dirty_ = true;
      std::cerr << "[chain] warn: failed to update UTXO snapshot; node will continue (restart may require reindex)\n";
    }
    if (!pubkeys_snapshot_ok) {
      ++revealed_pubkeys_snapshot_failures_;
      revealed_pubkeys_snapshot_dirty_ = true;
      std::cerr << "[chain] warn: failed to update revealed-pubkeys snapshot; node will continue (restart may require reindex)\n";
    }
    if (!utxo_snapshot_ok || !pubkeys_snapshot_ok) {
      utxo_snapshot_dirty_ = true;
      revealed_pubkeys_snapshot_dirty_ = true;
    }

    if (utxo_snapshot_ok && pubkeys_snapshot_ok) {
      bool pubkeys_meta_ok = false;
      std::string pubkeys_meta_error;
      if (!WriteSnapshotTipMeta(revealed_pubkeys_path_,
                                static_cast<std::uint32_t>(best_tip_->height),
                                best_tip_->hash_hex, &pubkeys_meta_error)) {
        ++revealed_pubkeys_snapshot_failures_;
        revealed_pubkeys_snapshot_dirty_ = true;
        std::cerr << "[chain] warn: failed to write revealed-pubkeys snapshot metadata: "
                  << pubkeys_meta_error << "\n";
      } else {
        pubkeys_meta_ok = true;
      }

      bool utxo_meta_ok = false;
      std::string utxo_meta_error;
      if (!WriteSnapshotTipMeta(utxo_path_, static_cast<std::uint32_t>(best_tip_->height),
                                best_tip_->hash_hex, &utxo_meta_error)) {
        ++utxo_snapshot_failures_;
        utxo_snapshot_dirty_ = true;
        std::cerr << "[chain] warn: failed to write UTXO snapshot metadata: " << utxo_meta_error
                  << "\n";
      } else {
        utxo_meta_ok = true;
      }

      if (utxo_meta_ok && pubkeys_meta_ok) {
        utxo_snapshot_dirty_ = false;
        revealed_pubkeys_snapshot_dirty_ = false;
      } else {
        utxo_snapshot_dirty_ = true;
        revealed_pubkeys_snapshot_dirty_ = true;
      }
    }
  }

  return true;
}

bool ChainState::ReadBlock(const BlockRecord& record, primitives::CBlock* block,
                           std::string* error) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return LoadBlockDataLocked(&record, nullptr, block, error);
}

ChainTelemetry ChainState::GetTelemetry() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  ChainTelemetry stats;
  stats.orphan_blocks = orphan_blocks_;
  stats.reorg_events = reorg_events_;
  stats.max_reorg_depth = max_reorg_depth_;
  stats.utxo_snapshot_failures = utxo_snapshot_failures_;
  stats.utxo_snapshot_dirty = utxo_snapshot_dirty_;
  stats.revealed_pubkeys_snapshot_failures = revealed_pubkeys_snapshot_failures_;
  stats.revealed_pubkeys_snapshot_dirty = revealed_pubkeys_snapshot_dirty_;
  return stats;
}

std::vector<ChainTipInfo> ChainState::GetChainTips() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  std::vector<ChainTipInfo> tips;
  if (block_index_.empty()) {
    return tips;
  }

  // Identify blocks that have no children (tips of all known branches).
  std::unordered_set<const BlockRecord*> has_child;
  has_child.reserve(block_index_.size());
  for (const auto& kv : block_index_) {
    const auto* record = kv.second.get();
    if (record && record->parent) {
      has_child.insert(record->parent);
    }
  }

  tips.reserve(block_index_.size());
  for (const auto& kv : block_index_) {
    const auto* record = kv.second.get();
    if (!record) continue;
    if (has_child.find(record) != has_child.end()) {
      continue;
    }
    ChainTipInfo info;
    info.hash_hex = record->hash_hex;
    info.height = record->height;
    info.in_active_chain = record->in_active_chain;
    info.is_best_tip = (record == best_tip_);

    // For side-chains, compute approximate branch length as the number
    // of consecutive blocks above the fork point that are not in the
    // active chain. This is used for observability only.
    if (!record->in_active_chain) {
      std::size_t branch = 0;
      const BlockRecord* cursor = record;
      while (cursor && !cursor->in_active_chain) {
        ++branch;
        cursor = cursor->parent;
      }
      info.branch_length = branch;
    } else {
      info.branch_length = 0;
    }
    tips.push_back(info);
  }

  std::sort(tips.begin(), tips.end(),
            [](const ChainTipInfo& a, const ChainTipInfo& b) {
              return a.height > b.height;
            });
  return tips;
}

bool ChainState::InitializeGenesisLocked(std::string* error) {
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  storage::BlockStore store(block_path_);
  std::uint64_t genesis_offset = std::numeric_limits<std::uint64_t>::max();
  if (!store.Append(params.genesis_block, &genesis_offset)) {
    if (error) *error = "failed to write genesis block";
    return false;
  }
  block_index_.clear();
  active_chain_.clear();
  best_tip_ = nullptr;
  best_chain_work_ = ChainWork::Zero();
  std::optional<std::uint64_t> disk_offset{0};
  if (genesis_offset != std::numeric_limits<std::uint64_t>::max()) {
    disk_offset = genesis_offset;
  }
  BlockRecord* record = AddBlockRecordLocked(params.genesis_block.header, disk_offset, error, false);
  if (!record) {
    return false;
  }
  if (!RebuildActiveChainLocked(record, error)) {
    return false;
  }
  return true;
}

bool ChainState::LoadBlocksLocked(std::string* error) {
  storage::BlockStore store(block_path_);
  block_index_.clear();
  active_chain_.clear();
  best_tip_ = nullptr;
  best_chain_work_ = ChainWork::Zero();
  if (!store.Exists()) {
    return true;
  }
  bool status = store.ForEach([&](const primitives::CBlock& block, std::size_t,
                                  std::uint64_t offset) {
    return AddBlockRecordLocked(block.header, offset, nullptr, true) != nullptr;
  });
  if (!status) {
    if (error) {
      *error = "failed to read block store";
    }
    return false;
  }
  // Sanity-check that the on-disk chain matches the selected network
  // by verifying that the configured genesis hash is present.
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  const std::string genesis_hex =
      util::HexEncode(std::span<const std::uint8_t>(params.genesis_hash.data(),
                                                    params.genesis_hash.size()));
  auto it = block_index_.find(genesis_hex);
  if (it == block_index_.end()) {
    if (error) {
      *error = "block store does not contain the expected genesis block for this network";
    }
    return false;
  }
  RecalculateBestTipLocked();
  return true;
}

bool ChainState::EnsureUtxoSnapshotLocked(std::string* error) {
  if (!best_tip_) {
    if (error) *error = "missing best tip";
    return false;
  }

  std::uint32_t snapshot_height = 0;
  std::string snapshot_hash;
  std::uint32_t pubkeys_height = 0;
  std::string pubkeys_hash;
  const bool utxo_loaded = storage::LoadUTXOSnapshot(&utxo_, utxo_path_);
  const bool pubkeys_loaded =
      storage::LoadRevealedPubkeysSnapshot(&revealed_pubkeys_, revealed_pubkeys_path_);
  const bool utxo_meta_loaded =
      utxo_loaded && ReadSnapshotTipMeta(utxo_path_, &snapshot_height, &snapshot_hash);
  const bool pubkeys_meta_loaded =
      pubkeys_loaded &&
      ReadSnapshotTipMeta(revealed_pubkeys_path_, &pubkeys_height, &pubkeys_hash);
  const bool snapshot_pair_loaded =
      utxo_loaded && pubkeys_loaded && utxo_meta_loaded && pubkeys_meta_loaded &&
      snapshot_height == pubkeys_height && snapshot_hash == pubkeys_hash;

  if (snapshot_pair_loaded && snapshot_height == best_tip_->height &&
      snapshot_hash == best_tip_->hash_hex) {
    ResetActiveFlagsLocked();
    active_chain_.clear();
    BuildActiveChainLocked(best_tip_, &active_chain_);
    for (auto* node : active_chain_) {
      node->in_active_chain = true;
    }
    return true;
  }

  // Snapshot is missing, stale, or has no metadata. Rebuild deterministically
  // from blocks.dat so the in-memory chain and UTXO set are consistent.
  std::string rebuild_error;
  if (!RebuildActiveChainLocked(best_tip_, &rebuild_error)) {
    // Recovery path: if snapshot metadata exists but the best-work tip is
    // invalid (e.g. an old build appended an invalid tail block), fall back
    // to the last snapshotted tip.
    if (utxo_meta_loaded) {
      auto it = block_index_.find(snapshot_hash);
      if (it != block_index_.end() && it->second.get() != best_tip_) {
        std::string fallback_error;
        if (RebuildActiveChainLocked(it->second.get(), &fallback_error)) {
          rebuild_error.clear();
        } else {
          rebuild_error = std::move(fallback_error);
        }
      }
    }
    if (!rebuild_error.empty()) {
      if (error) {
        *error = rebuild_error;
      }
      return false;
    }
  }

  bool utxo_snapshot_ok = snapshot_saver_ && snapshot_saver_(utxo_, utxo_path_);
  if (!utxo_snapshot_ok) {
    ++utxo_snapshot_failures_;
    utxo_snapshot_dirty_ = true;
    std::cerr << "[chain] warn: failed to persist UTXO snapshot after rebuild; node will continue\n";
  }

  bool pubkeys_snapshot_ok =
      storage::SaveRevealedPubkeysSnapshot(revealed_pubkeys_, revealed_pubkeys_path_);
  if (!pubkeys_snapshot_ok) {
    ++revealed_pubkeys_snapshot_failures_;
    revealed_pubkeys_snapshot_dirty_ = true;
    std::cerr << "[chain] warn: failed to persist revealed-pubkeys snapshot after rebuild; node will continue\n";
  }
  if (!utxo_snapshot_ok || !pubkeys_snapshot_ok) {
    utxo_snapshot_dirty_ = true;
    revealed_pubkeys_snapshot_dirty_ = true;
  }

  if (utxo_snapshot_ok && pubkeys_snapshot_ok) {
    bool pubkeys_meta_ok = false;
    std::string pubkeys_meta_error;
    if (!WriteSnapshotTipMeta(revealed_pubkeys_path_,
                              static_cast<std::uint32_t>(best_tip_->height),
                              best_tip_->hash_hex, &pubkeys_meta_error)) {
      ++revealed_pubkeys_snapshot_failures_;
      revealed_pubkeys_snapshot_dirty_ = true;
      std::cerr << "[chain] warn: failed to write revealed-pubkeys snapshot metadata: "
                << pubkeys_meta_error << "\n";
    } else {
      pubkeys_meta_ok = true;
    }

    bool utxo_meta_ok = false;
    std::string utxo_meta_error;
    if (!WriteSnapshotTipMeta(utxo_path_, static_cast<std::uint32_t>(best_tip_->height),
                              best_tip_->hash_hex, &utxo_meta_error)) {
      ++utxo_snapshot_failures_;
      utxo_snapshot_dirty_ = true;
      std::cerr << "[chain] warn: failed to write UTXO snapshot metadata: " << utxo_meta_error
                << "\n";
    } else {
      utxo_meta_ok = true;
    }

    if (utxo_meta_ok && pubkeys_meta_ok) {
      utxo_snapshot_dirty_ = false;
      revealed_pubkeys_snapshot_dirty_ = false;
    } else {
      utxo_snapshot_dirty_ = true;
      revealed_pubkeys_snapshot_dirty_ = true;
    }
  }
  return true;
}

bool ChainState::RebuildActiveChainLocked(BlockRecord* tip, std::string* error) {
  if (!tip) {
    if (error) *error = "no chain tip available";
    return false;
  }
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  std::vector<BlockRecord*> chain;
  BuildActiveChainLocked(tip, &chain);
  consensus::UTXOSet rebuilt;
  consensus::RevealedPubkeySet rebuilt_pubkeys;
  for (std::size_t idx = 0; idx < chain.size(); ++idx) {
    std::string block_error;
    std::uint64_t lock_time_cutoff_time = 0;
    if (!CheckTimeForIndexLocked(chain, idx, &lock_time_cutoff_time, &block_error)) {
      if (error) {
        std::ostringstream oss;
        oss << "block " << idx << " invalid: " << block_error;
        *error = oss.str();
      }
      return false;
    }
    if (!CheckDifficultyForIndexLocked(chain, idx, &block_error)) {
      if (error) {
        std::ostringstream oss;
        oss << "block " << idx << " invalid: " << block_error;
        *error = oss.str();
      }
      return false;
    }
    primitives::CBlock connect_block;
    if (!LoadBlockDataLocked(chain[idx], nullptr, &connect_block, &block_error)) {
      if (error) {
        std::ostringstream oss;
        oss << "block " << idx << " invalid: " << block_error;
        *error = oss.str();
      }
      return false;
    }
    if (!consensus::ValidateAndApplyBlock(connect_block, static_cast<std::uint32_t>(idx),
                                          lock_time_cutoff_time, params.max_block_serialized_bytes,
                                          params.witness_commitment_activation_height,
                                          &rebuilt, &rebuilt_pubkeys, &block_error)) {
      if (error) {
        std::ostringstream oss;
        oss << "block " << idx << " invalid: " << block_error;
        *error = oss.str();
      }
      return false;
    }
  }
  ResetActiveFlagsLocked();
  active_chain_ = chain;
  for (auto* node : active_chain_) {
    node->in_active_chain = true;
  }
  utxo_ = std::move(rebuilt);
  revealed_pubkeys_ = std::move(rebuilt_pubkeys);
  best_tip_ = tip;
  best_chain_work_ = tip->chain_work;
  return true;
}

bool ChainState::ApplyBlockToActiveChainLocked(BlockRecord* record, std::string* error) {
  if (!record) return false;
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  primitives::CBlock connect_block;
  std::string validation_error;
  std::uint64_t lock_time_cutoff_time = 0;
  if (!CheckNextBlockContextLocked(record->header, static_cast<std::uint32_t>(record->height),
                                   &lock_time_cutoff_time, &validation_error)) {
    if (error) *error = "validation failed: " + validation_error;
    return false;
  }
  if (!LoadBlockDataLocked(record, nullptr, &connect_block, &validation_error)) {
    if (error) *error = "validation failed: " + validation_error;
    return false;
  }
  consensus::UTXOSet working = utxo_;
  consensus::RevealedPubkeySet working_pubkeys = revealed_pubkeys_;
  if (!consensus::ValidateAndApplyBlock(connect_block, static_cast<std::uint32_t>(record->height),
                                        lock_time_cutoff_time, params.max_block_serialized_bytes,
                                        params.witness_commitment_activation_height,
                                        &working, &working_pubkeys, &validation_error)) {
    if (error) *error = "validation failed: " + validation_error;
    return false;
  }
  utxo_ = std::move(working);
  revealed_pubkeys_ = std::move(working_pubkeys);
  active_chain_.push_back(record);
  record->in_active_chain = true;
  best_tip_ = record;
  best_chain_work_ = record->chain_work;
  return true;
}

BlockRecord* ChainState::AddBlockRecordLocked(const primitives::CBlockHeader& header,
                                              std::optional<std::uint64_t> disk_offset,
                                              std::string* error,
                                              bool allow_duplicate) {
  const auto hash = consensus::ComputeBlockHash(header);
  const auto hash_hex =
      util::HexEncode(std::span<const std::uint8_t>(hash.data(), hash.size()));
  auto it = block_index_.find(hash_hex);
  if (it != block_index_.end()) {
    if (allow_duplicate) {
      if (disk_offset && !it->second->disk_offset) {
        it->second->disk_offset = disk_offset;
      }
      return it->second.get();
    }
    if (error) *error = "duplicate block";
    return nullptr;
  }
  std::string prev_hex =
      util::HexEncode(std::span<const std::uint8_t>(header.previous_block_hash.data(),
                                                    header.previous_block_hash.size()));
  bool is_genesis = std::all_of(header.previous_block_hash.begin(),
                                header.previous_block_hash.end(),
                                [](std::uint8_t byte) { return byte == 0; });
  BlockRecord* parent = nullptr;
  if (!is_genesis) {
    auto parent_it = block_index_.find(prev_hex);
    if (parent_it == block_index_.end()) {
      if (error) *error = "unknown parent";
      return nullptr;
    }
    parent = parent_it->second.get();
  }
  auto record = std::make_unique<BlockRecord>();
  record->header = header;
  record->hash = hash;
  record->hash_hex = hash_hex;
  record->parent = parent;
  record->height = parent ? parent->height + 1 : 0;
  record->chain_work =
      (parent ? parent->chain_work : ChainWork::Zero()) +
      ComputeBlockWork(header.difficulty_bits);
  record->in_active_chain = false;
  record->disk_offset = disk_offset;
  BlockRecord* ptr = record.get();
  block_index_[hash_hex] = std::move(record);
  return ptr;
}

bool ChainState::ActivateBestChainLocked(BlockRecord* candidate, std::string* error,
                                         bool* chain_changed) {
  if (!candidate || !chain_changed) return false;
  *chain_changed = false;
  if (!best_tip_) {
    if (!RebuildActiveChainLocked(candidate, error)) {
      return false;
    }
    *chain_changed = true;
    return true;
  }
  if (candidate->chain_work <= best_chain_work_) {
    return true;
  }
  if (!active_chain_.empty() && candidate->parent == active_chain_.back()) {
    if (!ApplyBlockToActiveChainLocked(candidate, error)) {
      return false;
    }
    *chain_changed = true;
    return true;
  }
  // Reorg: candidate attaches somewhere below the current tip.
  if (!active_chain_.empty()) {
    std::vector<BlockRecord*> new_chain;
    BuildActiveChainLocked(candidate, &new_chain);
    std::size_t common = 0;
    const std::size_t old_size = active_chain_.size();
    const std::size_t new_size = new_chain.size();
    const std::size_t limit = std::min(old_size, new_size);
    while (common < limit && active_chain_[common] == new_chain[common]) {
      ++common;
    }
    const std::size_t old_depth = old_size > common ? (old_size - common) : 0;
    if (old_depth > 0) {
      ++reorg_events_;
      if (old_depth > max_reorg_depth_) {
        max_reorg_depth_ = old_depth;
      }
    }
  }
  if (!RebuildActiveChainLocked(candidate, error)) {
    return false;
  }
  *chain_changed = true;
  return true;
}

void ChainState::BuildActiveChainLocked(BlockRecord* tip, std::vector<BlockRecord*>* out_chain) const {
  out_chain->clear();
  if (!tip) return;
  std::vector<BlockRecord*> stack;
  for (auto* cursor = tip; cursor != nullptr; cursor = cursor->parent) {
    stack.push_back(cursor);
  }
  while (!stack.empty()) {
    out_chain->push_back(stack.back());
    stack.pop_back();
  }
}

ChainWork ChainState::ComputeBlockWork(std::uint32_t bits) const {
  const auto target = consensus::CompactToTarget(bits);
  ChainWork target_value = ChainWork::FromBigEndian(target);
  if (target_value.IsZero()) {
    return ChainWork::Zero();
  }
  ChainWork denominator = target_value + ChainWork(1);
  return Divide(ChainWork::Max(), denominator);
}

bool ChainState::CheckDifficultyForIndexLocked(const std::vector<BlockRecord*>& chain,
                                               std::size_t index, std::string* error) const {
  if (index >= chain.size()) {
    if (error) *error = "invalid difficulty index";
    return false;
  }
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  if (index == 0) {
    const std::uint32_t expected = params.genesis_bits;
    const std::uint32_t actual = chain[0]->header.difficulty_bits;
    if (actual != expected) {
      if (error) *error = "genesis difficulty does not match chain parameters";
      return false;
    }
    return true;
  }

  if (params.difficulty_adjustment_activation_height != 0 &&
      index < params.difficulty_adjustment_activation_height) {
    const std::uint32_t expected = params.pow_limit_bits;
    const std::uint32_t actual = chain[index]->header.difficulty_bits;
    if (actual != expected) {
      if (error) {
        std::ostringstream oss;
        oss << "unexpected difficulty bits at height " << index << " during bootstrap (expected "
            << expected << ", got " << actual << ")";
        *error = oss.str();
      }
      return false;
    }
    return true;
  }

  if (params.difficulty_adjustment_interval == 0) {
    return true;
  }
  const std::uint32_t prev_bits = chain[index - 1]->header.difficulty_bits;
  std::uint32_t expected_bits = prev_bits;
  const std::uint32_t interval = params.difficulty_adjustment_interval;
  if (index % interval == 0) {
    const std::size_t last_index = index - 1;
    if (last_index + 1 >= interval) {
      const std::size_t first_index = last_index + 1 - interval;
      const auto first_time =
          static_cast<std::uint32_t>(chain[first_index]->header.timestamp);
      const auto last_time =
          static_cast<std::uint32_t>(chain[last_index]->header.timestamp);
      expected_bits = consensus::CalculateNextWorkRequired(
          prev_bits, first_time, last_time, params.target_block_time_seconds, interval,
          params.pow_limit_bits);
    }
  }
  const std::uint32_t actual_bits = chain[index]->header.difficulty_bits;
  if (actual_bits != expected_bits) {
    if (error) {
      std::ostringstream oss;
      oss << "unexpected difficulty bits at height " << index << " (expected " << expected_bits
          << ", got " << actual_bits << ")";
      *error = oss.str();
    }
    return false;
  }
  return true;
}

std::uint64_t ChainState::MedianTimePastForIndexLocked(const std::vector<BlockRecord*>& chain,
                                                       std::size_t index) const {
  if (index == 0 || chain.empty()) {
    return 0;
  }
  const std::size_t clamped_index = std::min(index, chain.size());
  const std::size_t sample_count = std::min<std::size_t>(clamped_index, kMedianTimeSpan);
  if (sample_count == 0) {
    return 0;
  }
  const std::size_t begin = clamped_index - sample_count;
  std::vector<std::uint64_t> times;
  times.reserve(sample_count);
  for (std::size_t i = begin; i < clamped_index; ++i) {
    times.push_back(chain[i]->header.timestamp);
  }
  std::sort(times.begin(), times.end());
  return times[times.size() / 2];
}

bool ChainState::CheckTimeForIndexLocked(const std::vector<BlockRecord*>& chain,
                                        std::size_t index,
                                        std::uint64_t* lock_time_cutoff_time,
                                        std::string* error) const {
  if (lock_time_cutoff_time) {
    *lock_time_cutoff_time = 0;
  }
  if (index >= chain.size()) {
    if (error) *error = "invalid time index";
    return false;
  }
  if (index == 0) {
    // Genesis time is fixed by chain parameters and is not subject to
    // contextual MTP/future-drift checks.
    return true;
  }
  const auto mtp = MedianTimePastForIndexLocked(chain, index);
  if (lock_time_cutoff_time) {
    *lock_time_cutoff_time = mtp;
  }
  const auto block_time = chain[index]->header.timestamp;
  if (block_time <= mtp) {
    if (error) {
      std::ostringstream oss;
      oss << "block timestamp too early (timestamp=" << block_time << ", mtp=" << mtp << ")";
      *error = oss.str();
    }
    return false;
  }
  const auto now = static_cast<std::uint64_t>(
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
  if (block_time > now + kMaxFutureBlockTimeSeconds) {
    if (error) {
      std::ostringstream oss;
      oss << "block timestamp too far in the future (timestamp=" << block_time
          << ", now=" << now << ", max_future=" << (now + kMaxFutureBlockTimeSeconds) << ")";
      *error = oss.str();
    }
    return false;
  }
  return true;
}

bool ChainState::CheckNextBlockContextLocked(const primitives::CBlockHeader& header,
                                            std::uint32_t height,
                                            std::uint64_t* lock_time_cutoff_time,
                                            std::string* error) const {
  if (lock_time_cutoff_time) {
    *lock_time_cutoff_time = 0;
  }
  if (height == 0) {
    // The genesis block's header is fixed by chain parameters and is validated
    // off-line when the parameters are generated.
    return true;
  }
  if (active_chain_.empty()) {
    if (error) *error = "missing active chain";
    return false;
  }
  if (active_chain_.back()->height + 1 != height) {
    if (error) *error = "unexpected next-block height";
    return false;
  }

  const auto mtp = MedianTimePastForIndexLocked(active_chain_, active_chain_.size());
  if (lock_time_cutoff_time) {
    *lock_time_cutoff_time = mtp;
  }
  const auto block_time = header.timestamp;
  if (block_time <= mtp) {
    if (error) {
      std::ostringstream oss;
      oss << "block timestamp too early (timestamp=" << block_time << ", mtp=" << mtp << ")";
      *error = oss.str();
    }
    return false;
  }
  const auto now = static_cast<std::uint64_t>(
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
  if (block_time > now + kMaxFutureBlockTimeSeconds) {
    if (error) {
      std::ostringstream oss;
      oss << "block timestamp too far in the future (timestamp=" << block_time
          << ", now=" << now << ", max_future=" << (now + kMaxFutureBlockTimeSeconds) << ")";
      *error = oss.str();
    }
    return false;
  }

  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  if (params.difficulty_adjustment_activation_height != 0 &&
      height < params.difficulty_adjustment_activation_height) {
    const std::uint32_t expected = params.pow_limit_bits;
    const std::uint32_t actual = header.difficulty_bits;
    if (actual != expected) {
      if (error) {
        std::ostringstream oss;
        oss << "unexpected difficulty bits at height " << height
            << " during bootstrap (expected " << expected << ", got " << actual << ")";
        *error = oss.str();
      }
      return false;
    }
    return true;
  }

  if (params.difficulty_adjustment_interval == 0) {
    return true;
  }
  const std::uint32_t prev_bits = active_chain_.back()->header.difficulty_bits;
  std::uint32_t expected_bits = prev_bits;
  const std::uint32_t interval = params.difficulty_adjustment_interval;
  if (height % interval == 0 && height >= interval) {
    const std::size_t first_index = static_cast<std::size_t>(height - interval);
    const std::size_t last_index = static_cast<std::size_t>(height - 1);
    if (last_index < active_chain_.size() && first_index < active_chain_.size()) {
      const auto first_time = static_cast<std::uint32_t>(active_chain_[first_index]->header.timestamp);
      const auto last_time = static_cast<std::uint32_t>(active_chain_[last_index]->header.timestamp);
      expected_bits = consensus::CalculateNextWorkRequired(
          prev_bits, first_time, last_time, params.target_block_time_seconds, interval,
          params.pow_limit_bits);
    }
  }
  const std::uint32_t actual_bits = header.difficulty_bits;
  if (actual_bits != expected_bits) {
    if (error) {
      std::ostringstream oss;
      oss << "unexpected difficulty bits at height " << height << " (expected " << expected_bits
          << ", got " << actual_bits << ")";
      *error = oss.str();
    }
    return false;
  }
  return true;
}

bool ChainState::LoadBlockDataLocked(const BlockRecord* record,
                                    const primitives::CBlock* override_block,
                                    primitives::CBlock* out,
                                    std::string* error) const {
  if (!record || !out) {
    if (error) *error = "invalid block lookup request";
    return false;
  }
  if (override_block) {
    const auto override_hash = consensus::ComputeBlockHash(override_block->header);
    if (override_hash == record->hash) {
      *out = *override_block;
      return true;
    }
  }
  if (record->disk_offset) {
    storage::BlockStore store(block_path_);
    primitives::CBlock block;
    if (!store.ReadAt(*record->disk_offset, &block)) {
      if (error) *error = "failed to read block from disk";
      return false;
    }
    *out = std::move(block);
    return true;
  }
  auto it = block_cache_.find(record->hash_hex);
  if (it == block_cache_.end()) {
    if (error) *error = "block data unavailable";
    return false;
  }
  *out = it->second;
  return true;
}

void ChainState::CacheBlockLocked(const std::string& hash_hex, const primitives::CBlock& block) {
  if (hash_hex.empty()) {
    return;
  }
  auto prune_fifo = [&]() {
    while (!block_cache_fifo_.empty() &&
           block_cache_.find(block_cache_fifo_.front()) == block_cache_.end()) {
      block_cache_fifo_.pop_front();
    }
  };
  prune_fifo();

  auto it = block_cache_.find(hash_hex);
  if (it != block_cache_.end()) {
    it->second = block;
    return;
  }

  while (block_cache_.size() >= kMaxCachedBlocks) {
    prune_fifo();
    if (block_cache_fifo_.empty()) {
      block_cache_.clear();
      break;
    }
    const std::string victim = block_cache_fifo_.front();
    block_cache_fifo_.pop_front();
    block_cache_.erase(victim);
  }

  block_cache_[hash_hex] = block;
  block_cache_fifo_.push_back(hash_hex);
}

void ChainState::RemoveCachedBlockLocked(const std::string& hash_hex) {
  if (hash_hex.empty()) {
    return;
  }
  block_cache_.erase(hash_hex);
}

void ChainState::ResetActiveFlagsLocked() {
  for (auto& entry : block_index_) {
    entry.second->in_active_chain = false;
  }
}

void ChainState::RecalculateBestTipLocked() {
  best_tip_ = nullptr;
  best_chain_work_ = ChainWork::Zero();
  for (const auto& entry : block_index_) {
    if (!best_tip_ || entry.second->chain_work > best_chain_work_) {
      best_tip_ = entry.second.get();
      best_chain_work_ = entry.second->chain_work;
    }
  }
}

}  // namespace qryptcoin::node
