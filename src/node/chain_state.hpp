#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "node/chain_work.hpp"

#include "config/network.hpp"
#include "consensus/revealed_pubkeys.hpp"
#include "consensus/utxo.hpp"
#include "primitives/block.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::node {

struct BlockRecord {
  primitives::CBlockHeader header{};
  primitives::Hash256 hash{};
  std::string hash_hex;
  std::size_t height{0};
  ChainWork chain_work{};
  BlockRecord* parent{nullptr};
  bool in_active_chain{false};
  std::optional<std::uint64_t> disk_offset{};
};

struct ChainTelemetry {
  std::uint64_t orphan_blocks{0};
  std::uint64_t reorg_events{0};
  std::uint64_t max_reorg_depth{0};
  std::uint64_t utxo_snapshot_failures{0};
  bool utxo_snapshot_dirty{false};
  std::uint64_t revealed_pubkeys_snapshot_failures{0};
  bool revealed_pubkeys_snapshot_dirty{false};
};

struct ChainTipInfo {
  std::string hash_hex;
  std::size_t height{0};
  bool in_active_chain{false};
  bool is_best_tip{false};
  std::size_t branch_length{0};
};

class ChainState {
 public:
  using SnapshotSaverFn = bool (*)(const consensus::UTXOSet& view, const std::string& path);

  ChainState(std::string block_path, std::string utxo_path);

  bool Initialize(std::string* error);

  std::size_t BlockCount() const;
  bool Empty() const;
  std::size_t Height() const;
  const BlockRecord* Tip() const;
  const BlockRecord* GetByHash(const std::string& hash_hex) const;
  const BlockRecord* GetByHeight(std::size_t height) const;
  std::size_t UtxoEntries() const;
  std::size_t RevealedPubkeyEntries() const;
  bool CheckTransaction(const primitives::CTransaction& tx, std::string* error) const;
  consensus::UTXOSet SnapshotUtxo() const;
  consensus::RevealedPubkeySet SnapshotRevealedPubkeys() const;
  bool GetCoin(const primitives::COutPoint& outpoint, consensus::Coin* coin) const;
  bool GetCoinMetadata(const primitives::COutPoint& outpoint,
                       std::uint32_t* height,
                       bool* coinbase) const;
  bool ConnectBlock(const primitives::CBlock& block, std::string* error);
  bool ReadBlock(const BlockRecord& record, primitives::CBlock* block, std::string* error) const;
  ChainTelemetry GetTelemetry() const;
  std::vector<ChainTipInfo> GetChainTips() const;

  // Test-only hook: override how UTXO snapshots are persisted so tests can
  // simulate IO failures without relying on filesystem behavior.
  void SetSnapshotSaverForTest(SnapshotSaverFn saver);

 private:
  bool LoadBlocksLocked(std::string* error);
  bool InitializeGenesisLocked(std::string* error);
  bool EnsureUtxoSnapshotLocked(std::string* error);
  bool RebuildActiveChainLocked(BlockRecord* tip, std::string* error);
  bool ApplyBlockToActiveChainLocked(BlockRecord* record, std::string* error);
  BlockRecord* AddBlockRecordLocked(const primitives::CBlockHeader& header,
                                    std::optional<std::uint64_t> disk_offset,
                                    std::string* error,
                                    bool allow_duplicate = false);
  bool ActivateBestChainLocked(BlockRecord* candidate, std::string* error, bool* chain_changed);
  void BuildActiveChainLocked(BlockRecord* tip, std::vector<BlockRecord*>* out_chain) const;
  ChainWork ComputeBlockWork(std::uint32_t bits) const;
  bool CheckDifficultyForIndexLocked(const std::vector<BlockRecord*>& chain,
                                     std::size_t index, std::string* error) const;
  std::uint64_t MedianTimePastForIndexLocked(const std::vector<BlockRecord*>& chain,
                                             std::size_t index) const;
  bool CheckTimeForIndexLocked(const std::vector<BlockRecord*>& chain,
                               std::size_t index,
                               std::uint64_t* lock_time_cutoff_time,
                               std::string* error) const;
  bool CheckNextBlockContextLocked(const primitives::CBlockHeader& header,
                                  std::uint32_t height,
                                  std::uint64_t* lock_time_cutoff_time,
                                  std::string* error) const;
  bool LoadBlockDataLocked(const BlockRecord* record,
                           const primitives::CBlock* override_block,
                           primitives::CBlock* out,
                           std::string* error) const;
  void CacheBlockLocked(const std::string& hash_hex, const primitives::CBlock& block);
  void RemoveCachedBlockLocked(const std::string& hash_hex);
  void ResetActiveFlagsLocked();
  void RecalculateBestTipLocked();

  std::string block_path_;
  std::string utxo_path_;
  std::vector<BlockRecord*> active_chain_;
  std::unordered_map<std::string, std::unique_ptr<BlockRecord>> block_index_;
  BlockRecord* best_tip_{nullptr};
  ChainWork best_chain_work_{};
  consensus::UTXOSet utxo_;
  consensus::RevealedPubkeySet revealed_pubkeys_;
  std::string revealed_pubkeys_path_;
  static constexpr std::size_t kMaxCachedBlocks = 1024;
  std::unordered_map<std::string, primitives::CBlock> block_cache_;
  std::deque<std::string> block_cache_fifo_;
  std::uint64_t orphan_blocks_{0};
  std::uint64_t reorg_events_{0};
  std::uint64_t max_reorg_depth_{0};
  std::uint64_t utxo_snapshot_failures_{0};
  bool utxo_snapshot_dirty_{false};
  std::uint64_t revealed_pubkeys_snapshot_failures_{0};
  bool revealed_pubkeys_snapshot_dirty_{false};
  SnapshotSaverFn snapshot_saver_{nullptr};
  mutable std::shared_mutex mutex_;
};

}  // namespace qryptcoin::node
