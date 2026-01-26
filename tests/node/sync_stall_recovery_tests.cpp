// Validates that sync stall recovery triggers without requiring a datadir wipe.

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <span>
#include <string>
#include <thread>

#include "config/network.hpp"
#include "net/peer_manager.hpp"
#include "node/block_sync.hpp"
#include "node/chain_state.hpp"
#include "util/hex.hpp"

namespace qryptcoin::net {

class PeerManagerTestHelper {
 public:
  static void AddFakePeer(PeerManager& manager,
                          std::uint64_t id,
                          bool inbound,
                          const std::string& address) {
    PeerManager::PeerEntry entry;
    entry.info.id = id;
    entry.info.inbound = inbound;
    entry.info.address = address;
    entry.session.reset();
    manager.peers_.push_back(entry);
  }
};

}  // namespace qryptcoin::net

namespace qryptcoin::node {

class BlockSyncManagerTestHelper {
 public:
  static void AddPeerWorker(BlockSyncManager& sync,
                            const net::PeerManager::PeerInfo& info) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    BlockSyncManager::PeerWorker worker;
    worker.info = info;
    worker.session.reset();
    sync.peer_workers_[info.id] = std::move(worker);
  }

  static void ConfigureHeadersAheadStall(BlockSyncManager& sync,
                                         std::size_t best_header_height,
                                         const primitives::Hash256& queued_hash,
                                         std::chrono::steady_clock::time_point last_progress) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    sync.best_header_height_ = best_header_height;
    sync.inflight_blocks_.clear();
    sync.download_queue_.clear();
    sync.download_queue_hashes_.clear();
    sync.download_queue_.push_back(queued_hash);
    sync.download_queue_hashes_.insert(queued_hash);
    sync.last_block_progress_time_ = last_progress;
  }

  static void AddInflightBlock(BlockSyncManager& sync,
                               const primitives::Hash256& hash,
                               std::uint64_t peer_id,
                               std::chrono::steady_clock::time_point assigned_at) {
    const std::string hex =
        util::HexEncode(std::span<const std::uint8_t>(hash.data(), hash.size()));
    std::lock_guard<std::mutex> lock(sync.mutex_);
    auto it_worker = sync.peer_workers_.find(peer_id);
    if (it_worker == sync.peer_workers_.end()) {
      BlockSyncManager::PeerWorker worker;
      worker.info.id = peer_id;
      worker.info.inbound = false;
      worker.session.reset();
      sync.peer_workers_[peer_id] = std::move(worker);
      it_worker = sync.peer_workers_.find(peer_id);
    }
    it_worker->second.inflight_blocks = 1;
    sync.inflight_blocks_[hex] = BlockSyncManager::InFlightBlock{hash, peer_id, assigned_at};
  }

  static bool DownloadQueueContains(const BlockSyncManager& sync,
                                    const primitives::Hash256& hash) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    return sync.download_queue_hashes_.find(hash) != sync.download_queue_hashes_.end();
  }

  static bool InflightBlocksContains(const BlockSyncManager& sync,
                                     const primitives::Hash256& hash) {
    const std::string hex =
        util::HexEncode(std::span<const std::uint8_t>(hash.data(), hash.size()));
    std::lock_guard<std::mutex> lock(sync.mutex_);
    return sync.inflight_blocks_.find(hex) != sync.inflight_blocks_.end();
  }
};

}  // namespace qryptcoin::node

namespace {

using namespace std::chrono_literals;

std::filesystem::path MakeTempDir(std::string_view name) {
  std::error_code ec;
  auto base = std::filesystem::temp_directory_path(ec);
  if (ec) {
    base = std::filesystem::path(".");
  }
  auto dir = base / "qryptcoin-tests" / std::string(name);
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    return std::filesystem::path(".");
  }
  return dir;
}

bool WaitUntil(const std::function<bool()>& predicate,
               std::chrono::steady_clock::duration timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(50ms);
  }
  return predicate();
}

bool TestHeadersAheadTriggersRecovery() {
  auto dir = MakeTempDir("sync_stall_recovery");
  qryptcoin::node::ChainState chain((dir / "blocks.dat").string(), (dir / "utxo.dat").string());
  qryptcoin::net::PeerManager peers(qryptcoin::config::GetNetworkConfig());
  qryptcoin::node::BlockSyncManager sync(chain, peers);
  sync.Start();

  qryptcoin::net::PeerManager::PeerInfo peer_info;
  peer_info.id = 1;
  peer_info.inbound = false;
  peer_info.address = "203.0.113.5:9375";
  qryptcoin::net::PeerManagerTestHelper::AddFakePeer(
      peers, peer_info.id, peer_info.inbound, peer_info.address);
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, peer_info);

  qryptcoin::primitives::Hash256 queued{};
  queued[0] = 0x42;
  qryptcoin::node::BlockSyncManagerTestHelper::ConfigureHeadersAheadStall(
      sync, /*best_header_height=*/10, queued,
      std::chrono::steady_clock::now() - 31s);

  if (!WaitUntil([&]() { return sync.GetStats().block_stall_recoveries >= 1; }, 10s)) {
    std::cerr << "expected block stall recovery to trigger\n";
    return false;
  }
  return true;
}

bool TestInflightTimeoutRequeuesBlocks() {
  auto dir = MakeTempDir("sync_timeout_requeue");
  qryptcoin::node::ChainState chain((dir / "blocks.dat").string(), (dir / "utxo.dat").string());
  qryptcoin::net::PeerManager peers(qryptcoin::config::GetNetworkConfig());
  qryptcoin::node::BlockSyncManager sync(chain, peers);
  sync.Start();

  qryptcoin::net::PeerManager::PeerInfo peer_info;
  peer_info.id = 1;
  peer_info.inbound = false;
  peer_info.address = "203.0.113.5:9375";
  qryptcoin::net::PeerManagerTestHelper::AddFakePeer(
      peers, peer_info.id, peer_info.inbound, peer_info.address);
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, peer_info);

  qryptcoin::primitives::Hash256 inflight{};
  inflight[0] = 0x99;
  qryptcoin::node::BlockSyncManagerTestHelper::AddInflightBlock(
      sync, inflight, peer_info.id,
      std::chrono::steady_clock::now() - 31s);

  if (!WaitUntil([&]() { return sync.GetStats().inflight_block_timeouts >= 1; }, 10s)) {
    std::cerr << "expected inflight block timeout to be recorded\n";
    return false;
  }
  if (!WaitUntil([&]() { return qryptcoin::node::BlockSyncManagerTestHelper::DownloadQueueContains(sync, inflight); },
                 2s)) {
    std::cerr << "expected timed out block to be re-queued\n";
    return false;
  }
  if (qryptcoin::node::BlockSyncManagerTestHelper::InflightBlocksContains(sync, inflight)) {
    std::cerr << "expected timed out block to be removed from inflight map\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!TestHeadersAheadTriggersRecovery()) {
    return EXIT_FAILURE;
  }
  if (!TestInflightTimeoutRequeuesBlocks()) {
    return EXIT_FAILURE;
  }
  std::cout << "sync_stall_recovery_tests: OK\n";
  return EXIT_SUCCESS;
}
