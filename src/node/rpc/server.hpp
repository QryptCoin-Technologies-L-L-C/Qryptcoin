#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "policy/fee_estimator.hpp"
#include "nlohmann/json.hpp"
#include "node/block_builder.hpp"
#include "node/block_sync.hpp"
#include "node/chain_state.hpp"
#include "net/peer_manager.hpp"
#include "net/addr_manager.hpp"
#include "net/dns_seeds.hpp"
#include "primitives/transaction.hpp"
#include "wallet/hd_wallet.hpp"

namespace qryptcoin::rpc {

// Configure global per-second rate limits for mining-related RPCs.
// A value of 0 disables rate limiting for that method.
void ConfigureMiningRpcRateLimits(std::uint32_t max_getblocktemplate_per_second,
                                  std::uint32_t max_submitblock_per_second);

class RpcServer {
 public:
  RpcServer(std::unique_ptr<wallet::HDWallet> wallet, bool wallet_enabled, node::ChainState& chain,
            net::PeerManager* peers, node::BlockSyncManager* sync, net::AddrManager* addrman,
            net::DnsSeedManager* dns_seeds, bool is_seed_node, std::string default_mining_address,
            bool allow_generate, bool read_only, std::uint64_t mempool_limit_bytes);
  RpcServer(std::unique_ptr<wallet::HDWallet> wallet, bool wallet_enabled, node::ChainState& chain,
            net::PeerManager* peers, node::BlockSyncManager* sync, net::AddrManager* addrman,
            net::DnsSeedManager* dns_seeds, bool is_seed_node, std::string default_mining_address,
            bool allow_generate, bool read_only, std::uint64_t mempool_limit_bytes,
            std::string mempool_persist_path, std::uint64_t mempool_expiry_seconds,
            std::uint64_t mempool_rebroadcast_seconds,
            std::uint64_t mempool_persist_interval_seconds);
  ~RpcServer();

  nlohmann::json Handle(const nlohmann::json& request);

  void SaveWalletIfLoaded() const {
    if (wallet_) {
      wallet_->Save();
    }
  }

 private:
  bool WalletEnabled() const noexcept { return wallet_enabled_; }
  bool WalletLoaded() const noexcept { return wallet_ != nullptr; }
  wallet::HDWallet& WalletOrThrow();
  const wallet::HDWallet& WalletOrThrow() const;

  nlohmann::json HandleGetBlockchainInfo(const nlohmann::json& params) const;
  nlohmann::json HandleGetBlock(const nlohmann::json& params) const;
  nlohmann::json HandleGetBlockHash(const nlohmann::json& params) const;
  nlohmann::json HandleGetBestBlockHash() const;
  nlohmann::json HandleGetBlockCount() const;
  nlohmann::json HandleWaitForNewBlock(const nlohmann::json& params) const;
  nlohmann::json HandleWaitForBlockHeight(const nlohmann::json& params) const;
  nlohmann::json HandleWaitForBlock(const nlohmann::json& params) const;
  nlohmann::json HandleGetRawTransaction(const nlohmann::json& params) const;
  nlohmann::json HandleGetNewAddress(const nlohmann::json& params);
  nlohmann::json HandleGetPaymentCode(const nlohmann::json& params) const;
  nlohmann::json HandleValidatePaymentCode(const nlohmann::json& params) const;
  nlohmann::json HandleResolvePaymentCode(const nlohmann::json& params);
  nlohmann::json HandleRegisterPaymentCode(const nlohmann::json& params);
  nlohmann::json HandleResolvePaymentCodeShort(const nlohmann::json& params) const;
  nlohmann::json HandleSendToAddress(const nlohmann::json& params);
  nlohmann::json HandleSendToPaymentCode(const nlohmann::json& params);
  nlohmann::json HandleSendCommitment(const nlohmann::json& params);
  nlohmann::json HandleRevealCommitment(const nlohmann::json& params);
  nlohmann::json HandleGetCommitmentStatus(const nlohmann::json& params) const;
  nlohmann::json HandleGetWalletInfo() const;
  nlohmann::json HandleListTransactions(const nlohmann::json& params) const;
  nlohmann::json HandleListUtxos() const;
  nlohmann::json HandleListAddresses() const;
  nlohmann::json HandleForgetAddresses(const nlohmann::json& params);
  nlohmann::json HandlePurgeUtxos();
  nlohmann::json HandleResyncWallet(const nlohmann::json& params);
  nlohmann::json HandleImportAddress(const nlohmann::json& params);
  nlohmann::json HandleListWatchOnly() const;
  nlohmann::json HandleRemoveWatchOnly(const nlohmann::json& params);
  nlohmann::json HandleGetPqInfo() const;
  nlohmann::json HandleGetNetworkInfo() const;
  nlohmann::json HandleGetPeerInfo() const;
  nlohmann::json HandleGetChainTips() const;
  nlohmann::json HandleGetSeedHealth() const;
  nlohmann::json HandleListDnsSeeds() const;
  nlohmann::json HandleRefreshDnsSeeds();
  nlohmann::json HandleAddNode(const nlohmann::json& params);
  nlohmann::json HandleDisconnectNode(const nlohmann::json& params);
  nlohmann::json HandleGetAddedNodeInfo() const;
  nlohmann::json HandleSetNetworkLimits(const nlohmann::json& params);
  nlohmann::json HandleGetMiningInfo() const;
  nlohmann::json HandleGetMiningInfoQry() const;
  nlohmann::json HandleGetMempoolInfo() const;
  nlohmann::json HandleGetHealth() const;
  nlohmann::json HandleGetRawMempool(const nlohmann::json& params) const;
  nlohmann::json HandleGetMempoolEntry(const nlohmann::json& params) const;
  nlohmann::json HandleCreateRawTransaction(const nlohmann::json& params) const;
  nlohmann::json HandleDecodeRawTransaction(const nlohmann::json& params) const;
  nlohmann::json HandleSendRawTransaction(const nlohmann::json& params);
  nlohmann::json HandleEstimateSmartFee(const nlohmann::json& params) const;
  nlohmann::json HandleGetBlockTemplate(const nlohmann::json& params);
  nlohmann::json HandleGetBlockTemplateQry(const nlohmann::json& params);
  nlohmann::json HandleSubmitBlock(const nlohmann::json& params);
  nlohmann::json HandleSubmitBlockQry(const nlohmann::json& params);
  nlohmann::json HandleGenerate(const nlohmann::json& params, bool to_address);
  nlohmann::json HandleCreateWallet(const nlohmann::json& params);
  nlohmann::json HandleLoadWallet(const nlohmann::json& params);
  nlohmann::json HandleBackupWallet(const nlohmann::json& params);
  nlohmann::json HandleEncryptWallet(const nlohmann::json& params);
  nlohmann::json HandleWalletLock(const nlohmann::json& params);
  nlohmann::json HandleWalletPassphrase(const nlohmann::json& params);
  void RescanWallet(std::size_t start_height = 0, bool force_start_height = false);
  bool MineSingleBlock(const crypto::P2QHDescriptor& reward, std::string* hash_hex,
                       std::uint32_t* height, std::string* error);
  crypto::P2QHDescriptor DescriptorForAddress(const std::string& address) const;
  crypto::P2QHDescriptor DefaultMiningRewardDescriptor(std::string* out_address = nullptr);
  std::string DefaultMiningAddress() const;
  void IndexWalletOutputs(const primitives::CBlock& block, bool save_wallet = true);
  void AnnounceBlock(const primitives::Hash256& hash);
  std::size_t BroadcastTransaction(const primitives::CTransaction& tx);
  std::size_t BroadcastTransactionCommitment(const primitives::Hash256& commitment,
                                             std::uint64_t exclude_peer_id = 0);
  void QueueTransactionRelayRetry(const primitives::Hash256& txid);
  void ProcessRelayRetryQueue(std::chrono::steady_clock::time_point now);
  void QueueWalletRollback(const primitives::Hash256& txid);
  void ProcessWalletRollbackQueue();

  struct Hash256Hasher {
    std::size_t operator()(const primitives::Hash256& hash) const noexcept {
      std::size_t result = 0;
      for (auto byte : hash) {
        result = (result * 131) ^ static_cast<std::size_t>(byte);
      }
      return result;
    }
  };

  struct OutPointHasher {
    std::size_t operator()(const primitives::COutPoint& outpoint) const noexcept {
      std::size_t result = 0;
      for (auto byte : outpoint.txid) {
        result = (result * 131) ^ static_cast<std::size_t>(byte);
      }
      result ^= static_cast<std::size_t>(outpoint.index) + 0x9e3779b97f4a7c15ULL +
                (result << 6) + (result >> 2);
      return result;
    }
  };

  struct MempoolEntry {
    primitives::CTransaction tx;
    primitives::Hash256 txid;
    std::uint64_t size_bytes{0};
    std::uint64_t vbytes{0};
    primitives::Amount fee_miks{0};
    double feerate_miks_per_vb{0.0};
    std::uint64_t feerate_q{0};  // quantized feerate for deterministic ordering/eviction
    std::uint32_t entry_height{0};
    std::uint64_t time_first_seen{0};
  };

  struct FeeIndexKey {
    std::uint64_t feerate_q{0};
    primitives::Hash256 txid{};
  };

  struct FeeIndexLess {
    bool operator()(const FeeIndexKey& a, const FeeIndexKey& b) const noexcept {
      if (a.feerate_q != b.feerate_q) {
        return a.feerate_q < b.feerate_q;
      }
      // Tie-break by txid so ordering is strict and deterministic.
      return a.txid < b.txid;
    }
  };

  struct Array16Hasher {
    std::size_t operator()(const std::array<std::uint8_t, 16>& value) const noexcept {
      std::size_t result = 0;
      for (auto byte : value) {
        result = (result * 131) ^ static_cast<std::size_t>(byte);
      }
      return result;
    }
  };

  bool AddToMempool(const primitives::CTransaction& tx,
                    std::optional<double> feerate_miks_per_vb_override,
                    std::string* reject_reason = nullptr,
                    std::optional<std::uint64_t> time_first_seen_override = std::nullopt);
  void FillBlockFromMempool(primitives::CBlock* block, std::uint32_t height);
  void RemoveMinedTransactions(const primitives::CBlock& block, std::uint32_t height);
  void RemoveFromMempoolLocked(const primitives::Hash256& txid);
  void RemoveFromMempoolWithDescendantsLocked(const primitives::Hash256& txid);
  void TrimMempoolIfNeededLocked();
  void MaybeDecayMempoolMinFeeLocked();
  void MempoolMaintenanceLoop(std::stop_token stop);
  void MaybeExpireMempool(std::uint64_t now_seconds);
  void RebroadcastMempool();
  bool LoadMempoolFromDisk(std::string* error);
  bool SaveMempoolToDisk(std::string* error);

  std::mutex wallet_event_mutex_;
  std::vector<primitives::Hash256> wallet_rollback_queue_;

 public:
  // Test-only helper to exercise mempool logic without going through
  // the full JSON-RPC surface.
  bool AddToMempoolForTest(const primitives::CTransaction& tx,
                           double feerate_miks_per_vb) {
    return AddToMempool(tx, feerate_miks_per_vb, nullptr);
  }

  // Exposed so qryptd can apply operator-tuned parameters.
  void ConfigureFeeEstimator(double decay, std::size_t max_samples) {
    fee_estimator_.Configure(decay, max_samples);
  }

  // Lightweight hooks used by the P2P layer for transaction relay.
  bool HasMempoolTransaction(const primitives::Hash256& txid) const;
  bool GetMempoolTransactionBytes(const primitives::Hash256& txid,
                                  std::vector<std::uint8_t>* out) const;
  bool SubmitTransactionFromNetwork(const primitives::CTransaction& tx,
                                    std::string* reject_reason = nullptr);
  void NotifyTransactionCommitmentFromNetwork(const primitives::Hash256& commitment,
                                              std::uint64_t peer_id);
  void NotifyBlockConnected(const primitives::CBlock& block, std::uint32_t height);

  std::unique_ptr<wallet::HDWallet> wallet_;
  mutable std::mutex wallet_rpc_mutex_;
  bool wallet_enabled_{true};
  node::ChainState& chain_;
  net::PeerManager* peers_;
  node::BlockSyncManager* sync_;
  net::AddrManager* addrman_;
  net::DnsSeedManager* dns_seeds_{nullptr};
  std::string default_mining_address_;
  std::mutex mining_reward_mutex_;
  std::string mining_reward_tip_hash_;
  std::uint32_t mining_reward_height_{0};
  std::string mining_reward_address_;
  crypto::P2QHDescriptor mining_reward_descriptor_{};
  bool mining_reward_cached_{false};
  bool allow_generate_{false};
  bool read_only_{false};
  bool is_seed_node_{false};

  std::unordered_map<primitives::Hash256, MempoolEntry, Hash256Hasher> mempool_by_txid_;
  std::unordered_map<primitives::COutPoint, primitives::Hash256, OutPointHasher> mempool_spends_;
  std::unordered_set<primitives::Hash256, Hash256Hasher> mempool_revealed_pubkeys_;
  std::set<FeeIndexKey, FeeIndexLess> mempool_fee_index_;
  mutable std::mutex mempool_mutex_;
  std::uint64_t mempool_bytes_{0};
  std::uint64_t mempool_limit_bytes_{0};
  double mempool_min_fee_miks_per_vb_{0.0};
  policy::RollingFeeEstimator fee_estimator_{0.95, 512};
  std::chrono::seconds mempool_expiry_{0};
  std::chrono::seconds mempool_rebroadcast_interval_{0};
  std::string mempool_persist_path_;
  std::chrono::seconds mempool_persist_interval_{std::chrono::seconds(60)};
  std::atomic<bool> mempool_dirty_{false};
  std::jthread mempool_maintenance_thread_;

  struct RelayRetryEntry {
    std::chrono::steady_clock::time_point first_scheduled{};
    std::chrono::steady_clock::time_point next_attempt{};
    std::uint32_t attempts{0};
  };
  mutable std::mutex relay_retry_mutex_;
  std::unordered_map<primitives::Hash256, RelayRetryEntry, Hash256Hasher> relay_retry_queue_;
  std::atomic<std::uint64_t> relay_broadcast_attempts_total_{0};
  std::atomic<std::uint64_t> relay_broadcast_success_total_{0};
  std::atomic<std::uint64_t> relay_broadcast_zero_peer_total_{0};
  std::atomic<std::uint64_t> relay_broadcast_retry_scheduled_total_{0};
  std::atomic<std::uint64_t> relay_broadcast_retry_success_total_{0};

  struct TxCommitmentEntry {
    std::uint32_t first_seen_height{0};
    std::uint64_t first_seen_time{0};
    bool locally_created{false};
    bool revealed{false};
    std::optional<primitives::CTransaction> tx;
  };
  mutable std::mutex tx_commitment_mutex_;
  std::unordered_map<primitives::Hash256, TxCommitmentEntry, Hash256Hasher> tx_commitments_;

  mutable std::mutex paycode_registry_mutex_;
  std::unordered_map<std::array<std::uint8_t, 16>, std::string, Array16Hasher>
      paycode_v2_registry_;

  // Simple tracking of peers added via addnode so operators can
  // inspect them with getaddednodeinfo.
  std::vector<std::string> added_nodes_;
  mutable std::mutex added_nodes_mutex_;
};

}  // namespace qryptcoin::rpc
