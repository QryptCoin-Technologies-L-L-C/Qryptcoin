#pragma once

#include <atomic>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>

#include "net/peer_manager.hpp"
#include "node/chain_state.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::node {

class BlockSyncManagerTestHelper;

class BlockSyncManager {
 public:
  struct SyncStats {
    std::size_t best_header_height{0};
    std::size_t pending_blocks{0};
    std::uint64_t getheaders_sent{0};
    std::uint64_t headers_received{0};
    std::uint64_t inventories_received{0};
    std::uint64_t blocks_connected{0};
    std::uint64_t stalls_detected{0};
    std::uint64_t frame_payload_drops{0};
    // Header sync instrumentation
    std::uint64_t headers_pruned_total{0};
    std::uint64_t headers_dropped_duplicate{0};
    std::uint64_t getheaders_paused_backpressure{0};
    std::uint64_t header_highwater_events{0};
    std::size_t pending_headers{0};
    // New gauges
    std::size_t headers_gap{0};  // best header height minus chain height
    std::size_t active_outbound_peers{0};
    std::size_t frontier_height{0};
    std::size_t inflight_blocks{0};
    std::size_t requestable_blocks{0};
    std::size_t orphan_pool_size{0};
    // New counters
    std::uint64_t block_stall_recoveries{0};
    std::uint64_t inflight_block_timeouts{0};
    std::uint64_t unsolicited_headers_ignored{0};
    std::uint64_t parent_ready_blocked{0};
    std::uint64_t scheduler_no_requestable_cycles{0};
    std::uint64_t stall_breaker_activations{0};
  };

  struct PeerSyncStats {
    std::uint64_t peer_id{0};
    std::size_t inflight_blocks{0};
    std::size_t stall_count{0};
    std::uint64_t last_response_ms{0};
  };

  using TransactionHandler =
      std::function<bool(const primitives::CTransaction&, std::string* reject_reason)>;
  using TxCommitmentHandler =
      std::function<void(const primitives::Hash256& commitment, std::uint64_t peer_id)>;
  using HasTransactionFn = std::function<bool(const primitives::Hash256&)>;
  using GetTransactionBytesFn =
      std::function<bool(const primitives::Hash256&, std::vector<std::uint8_t>*)>;
  using BlockConnectedHandler =
      std::function<void(const primitives::CBlock&, std::uint32_t height)>;
  using AddressObserver = std::function<void(const std::string&)>;

  BlockSyncManager(ChainState& chain, net::PeerManager& peers);
  ~BlockSyncManager();

  void Start();
  void Stop();

  std::size_t BestHeaderHeight() const;
  bool IsSynced() const;
  bool IsRunning() const { return running_.load(); }
  SyncStats GetStats() const;
  std::vector<PeerSyncStats> GetPeerSyncStats() const;
  void SetRateLimits(std::size_t inv_per_sec,
                     std::size_t getdata_per_sec,
                     std::size_t headers_per_sec,
                     std::size_t block_per_sec,
                     std::size_t tx_per_sec);
  std::size_t AnnounceTransaction(const primitives::Hash256& txid, bool force = false);

  // Install callbacks used for transaction relay and address
  // discovery. All callbacks are optional; when unset, the
  // corresponding functionality is disabled.
  void SetTransactionHandler(TransactionHandler handler);
  void SetTxCommitmentHandler(TxCommitmentHandler handler);
  void SetTransactionInventoryPolicy(HasTransactionFn has_tx,
                                     GetTransactionBytesFn get_tx_bytes);
  void SetBlockConnectedHandler(BlockConnectedHandler handler);
  void SetAddressObserver(AddressObserver observer);

 private:
  struct Hash256Hasher {
    std::size_t operator()(const primitives::Hash256& hash) const noexcept {
      std::size_t result = 0;
      for (auto byte : hash) {
        result = (result * 131) ^ static_cast<std::size_t>(byte);
      }
      return result;
    }
  };

  struct PeerWorker {
    net::PeerManager::PeerInfo info;
    std::shared_ptr<net::PeerSession> session;
    std::jthread thread;
    std::size_t inflight_blocks{0};
    std::unordered_set<primitives::Hash256, Hash256Hasher> inflight_transactions;
    // Per-peer transaction relay shaping: avoid re-announcing txids the peer is
    // already known to have.
    std::deque<primitives::Hash256> known_tx_fifo;
    std::unordered_set<primitives::Hash256, Hash256Hasher> known_transactions;
    std::chrono::steady_clock::time_point tx_inv_window_start{};
    std::size_t tx_inv_window_count{0};
    std::size_t stall_count{0};
    std::chrono::steady_clock::time_point last_response{};
    std::chrono::steady_clock::time_point next_request_allowed{};
    bool headers_request_outstanding{false};
    // When we send getheaders to a peer we expect a headers response
    // within a short window. Unsolicited headers are ignored and scored
    // as misbehavior to avoid header-flood memory DoS.
    std::chrono::steady_clock::time_point headers_expected_until{};
  };

  void OnPeerConnected(const net::PeerManager::PeerInfo& info,
                       const std::shared_ptr<net::PeerSession>& session);
  void OnPeerDisconnected(const net::PeerManager::PeerInfo& info);
  void PeerLoop(std::stop_token stop, net::PeerManager::PeerInfo info,
                std::shared_ptr<net::PeerSession> session);
  void DispatchMessage(const net::PeerManager::PeerInfo& info,
                       const std::shared_ptr<net::PeerSession>& session,
                       const net::messages::Message& message);
  void HandleHeaders(const net::PeerManager::PeerInfo& info,
                     const std::shared_ptr<net::PeerSession>& session,
                     const net::messages::HeadersMessage& headers);
  void HandleGetHeaders(const net::PeerManager::PeerInfo& info,
                        const std::shared_ptr<net::PeerSession>& session,
                        const net::messages::GetHeadersMessage& request);
  void HandleGetData(const net::PeerManager::PeerInfo& info,
                     const std::shared_ptr<net::PeerSession>& session,
                     const net::messages::InventoryMessage& request);
  void HandleInventory(const net::PeerManager::PeerInfo& info,
                       const std::shared_ptr<net::PeerSession>& session,
                       const net::messages::InventoryMessage& inventory);
  void HandleBlock(const net::PeerManager::PeerInfo& info,
                   const std::shared_ptr<net::PeerSession>& session,
                   const net::messages::BlockMessage& block);
  void HandleTransaction(const net::PeerManager::PeerInfo& info,
                         const std::shared_ptr<net::PeerSession>& session,
                         const net::messages::Message& message);
  void HandleTxCommitment(const net::PeerManager::PeerInfo& info,
                          const net::messages::Message& message);
  void SendGetHeaders(const net::PeerManager::PeerInfo& info,
                      const std::shared_ptr<net::PeerSession>& session);
  void RequestNextBlock(const net::PeerManager::PeerInfo& info,
                        const std::shared_ptr<net::PeerSession>& session);
  void RequestFromAnyPeer();
  bool PrepareBlockRequestForPeerLocked(std::uint64_t peer_id,
                                        primitives::Hash256* out_hash);
  // Returns true when the candidate's parent is either connected (in chain) or
  // already in-flight. Callers must hold `mutex_`.
  bool IsParentSatisfiedLocked(const primitives::Hash256& candidate) const;
  void StallWatcher(std::stop_token stop);
  std::vector<primitives::Hash256> BuildLocator() const;
  static crypto::Sha3_256Hash ToInventoryId(const primitives::Hash256& hash);
  static primitives::Hash256 FromInventoryId(const crypto::Sha3_256Hash& id);
  std::optional<std::size_t> ParentHeightLocked(const primitives::Hash256& hash) const;
  void RebuildDownloadQueueLocked();
  void RemoveHeaderEntryLocked(const primitives::Hash256& hash);
  void PruneStaleHeadersLocked();
  void RemoveHeadersForPeerLocked(std::uint64_t peer_id);
  // Returns true if we should pause header requests due to backpressure.
  // This prevents "exceeded header storage caps" by pausing requests proactively.
  bool ShouldPauseHeaderRequestsLocked(std::uint64_t peer_id) const;
  // Check if backpressure conditions have cleared and we can resume.
  bool CanResumeHeaderRequestsLocked(std::uint64_t peer_id) const;
  void StoreOrphanBlockLocked(const primitives::Hash256& hash,
                              primitives::CBlock block,
                              std::size_t payload_bytes);
  std::vector<primitives::CBlock> PopOrphansForParentLocked(const primitives::Hash256& parent);
  void MaybeCompactOrphanFifoLocked();
  void EvictOrphansIfNeededLocked();

  ChainState& chain_;
  net::PeerManager& peers_;
  std::atomic<bool> running_{false};
  mutable std::mutex mutex_;
  std::unordered_map<std::uint64_t, PeerWorker> peer_workers_;
  std::deque<primitives::Hash256> download_queue_;
  std::unordered_set<primitives::Hash256, Hash256Hasher> download_queue_hashes_;
  struct InFlightBlock {
    primitives::Hash256 hash{};
    std::uint64_t peer_id{0};
    std::chrono::steady_clock::time_point assigned_at{};
  };
  std::unordered_map<std::string, InFlightBlock> inflight_blocks_;
  struct InFlightTransaction {
    std::uint64_t peer_id{0};
    std::chrono::steady_clock::time_point requested_at{};
  };
  std::unordered_map<primitives::Hash256, InFlightTransaction, Hash256Hasher>
      inflight_transactions_;
  static constexpr std::size_t kKnownTransactionsPerPeer = 10'000;
  static constexpr std::chrono::minutes kRecentRejectsTtl{10};
  struct RecentRejectEntry {
    std::chrono::steady_clock::time_point until{};
    std::string reason;
  };
  std::unordered_map<primitives::Hash256, RecentRejectEntry, Hash256Hasher> recent_rejects_;
  struct OrphanBlockEntry {
    primitives::CBlock block{};
    primitives::Hash256 parent{};
    std::size_t payload_bytes{0};
  };
  std::unordered_map<primitives::Hash256, OrphanBlockEntry, Hash256Hasher> orphan_blocks_;
  std::unordered_map<primitives::Hash256,
                     std::unordered_set<primitives::Hash256, Hash256Hasher>,
                     Hash256Hasher>
      orphans_by_parent_;
  std::deque<primitives::Hash256> orphan_fifo_;
  std::size_t orphan_bytes_{0};
  std::size_t best_header_height_{0};
  primitives::Hash256 best_header_hash_{};
  std::chrono::steady_clock::time_point last_block_progress_time_{};
  std::chrono::steady_clock::time_point last_sync_tick_{};
  std::chrono::steady_clock::time_point last_stall_recovery_time_{};
  std::chrono::steady_clock::time_point last_stall_breaker_time_{};
  struct HeaderEntry {
    primitives::Hash256 hash{};
    primitives::Hash256 previous{};
    std::size_t height{0};
    std::uint32_t difficulty_bits{0};
    std::uint64_t timestamp{0};
    std::uint64_t source_peer_id{0};
  };
  std::unordered_map<std::string, HeaderEntry> header_index_;
  std::unordered_map<std::uint64_t, std::size_t> headers_by_peer_;
  std::atomic<std::uint64_t> getheaders_sent_{0};
  std::atomic<std::uint64_t> headers_received_{0};
  std::atomic<std::uint64_t> inventories_received_{0};
  std::atomic<std::uint64_t> blocks_connected_{0};
  std::atomic<std::uint64_t> stalls_detected_{0};
  std::atomic<std::uint64_t> block_stall_recoveries_total_{0};
  std::atomic<std::uint64_t> inflight_block_timeouts_total_{0};
  std::atomic<std::uint64_t> unsolicited_headers_ignored_total_{0};
  std::atomic<std::uint64_t> parent_ready_blocked_total_{0};
  std::atomic<std::uint64_t> scheduler_no_requestable_cycles_total_{0};
  std::atomic<std::uint64_t> stall_breaker_activations_total_{0};
  // Header sync instrumentation counters
  std::atomic<std::uint64_t> headers_pruned_total_{0};
  std::atomic<std::uint64_t> headers_dropped_duplicate_{0};
  std::atomic<std::uint64_t> getheaders_paused_backpressure_{0};
  std::atomic<std::uint64_t> header_highwater_events_{0};
  // Track if we're currently in backpressure mode (high-water hit, waiting for low-water)
  std::atomic<bool> header_backpressure_active_{false};

  TransactionHandler on_transaction_received_;
  TxCommitmentHandler on_tx_commitment_received_;
  BlockConnectedHandler on_block_connected_;
  HasTransactionFn has_transaction_;
  GetTransactionBytesFn get_transaction_bytes_;
  AddressObserver on_address_seen_;

  // Background watcher for stalled block downloads.
  std::jthread stall_thread_;

  // Simple, type-specific rate limits (per peer per second).
  std::atomic<std::size_t> inv_limit_per_sec_{1000};
  std::atomic<std::size_t> getdata_limit_per_sec_{200};
   std::atomic<std::size_t> headers_limit_per_sec_{50};
   // Blocks are typically delivered only in response to our own getdata
   // requests and can arrive in bursts during initial sync. Rely on the
   // FrameChannel and overall message-rate limits for DoS protection.
   std::atomic<std::size_t> block_limit_per_sec_{0};
   std::atomic<std::size_t> tx_limit_per_sec_{200};

   friend class BlockSyncManagerTestHelper;
 };

}  // namespace qryptcoin::node
