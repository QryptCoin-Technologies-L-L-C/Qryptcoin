// Reproduces and guards against scheduler deadlocks where parents are "queued"
// but never requested, requiring a manual restart to recover.

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

  static void ConfigureHeaderChain(BlockSyncManager& sync,
                                   const net::PeerManager::PeerInfo& peer,
                                   const primitives::Hash256& h1,
                                   const primitives::Hash256& h2,
                                   const primitives::Hash256& h3) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    sync.header_index_.clear();
    sync.headers_by_peer_.clear();
    sync.download_queue_.clear();
    sync.download_queue_hashes_.clear();
    sync.inflight_blocks_.clear();
    sync.best_header_height_ = 3;
    sync.best_header_hash_ = h3;

    BlockSyncManager::HeaderEntry e1;
    e1.hash = h1;
    e1.previous.fill(0);
    e1.height = 1;
    e1.source_peer_id = peer.id;

    BlockSyncManager::HeaderEntry e2;
    e2.hash = h2;
    e2.previous = h1;
    e2.height = 2;
    e2.source_peer_id = peer.id;

    BlockSyncManager::HeaderEntry e3;
    e3.hash = h3;
    e3.previous = h2;
    e3.height = 3;
    e3.source_peer_id = peer.id;

    sync.header_index_[util::HexEncode(std::span<const std::uint8_t>(h1.data(), h1.size()))] = e1;
    sync.header_index_[util::HexEncode(std::span<const std::uint8_t>(h2.data(), h2.size()))] = e2;
    sync.header_index_[util::HexEncode(std::span<const std::uint8_t>(h3.data(), h3.size()))] = e3;
    sync.headers_by_peer_[peer.id] = 3;
  }

  static void ConfigureDownloadQueue(BlockSyncManager& sync,
                                     std::initializer_list<primitives::Hash256> hashes) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    sync.download_queue_.clear();
    sync.download_queue_hashes_.clear();
    for (const auto& h : hashes) {
      sync.download_queue_.push_back(h);
      sync.download_queue_hashes_.insert(h);
    }
  }

  static bool PrepareBlockRequest(BlockSyncManager& sync,
                                  std::uint64_t peer_id,
                                  primitives::Hash256* out) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    return sync.PrepareBlockRequestForPeerLocked(peer_id, out);
  }

  static bool DownloadQueueContains(const BlockSyncManager& sync,
                                    const primitives::Hash256& hash) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    return sync.download_queue_hashes_.find(hash) != sync.download_queue_hashes_.end();
  }

  static void SetLastBlockProgress(BlockSyncManager& sync,
                                   std::chrono::steady_clock::time_point when) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    sync.last_block_progress_time_ = when;
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
    std::this_thread::sleep_for(20ms);
  }
  return predicate();
}

bool TestParentFirstEscalationAvoidsDeadlock() {
  auto dir = MakeTempDir("scheduler_deadlock_parent_first");
  qryptcoin::node::ChainState chain((dir / "blocks.dat").string(), (dir / "utxo.dat").string());
  qryptcoin::net::PeerManager peers(qryptcoin::config::GetNetworkConfig());
  qryptcoin::node::BlockSyncManager sync(chain, peers);
  sync.Start();

  qryptcoin::net::PeerManager::PeerInfo peer;
  peer.id = 1;
  peer.inbound = false;
  peer.address = "203.0.113.10:9375";
  qryptcoin::net::PeerManagerTestHelper::AddFakePeer(peers, peer.id, peer.inbound, peer.address);
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, peer);

  qryptcoin::primitives::Hash256 h1{};
  qryptcoin::primitives::Hash256 h2{};
  qryptcoin::primitives::Hash256 h3{};
  h1[0] = 0x01;
  h2[0] = 0x02;
  h3[0] = 0x03;

  qryptcoin::node::BlockSyncManagerTestHelper::ConfigureHeaderChain(sync, peer, h1, h2, h3);
  // Deadlock reproduction: children queued, parent missing from the queue.
  qryptcoin::node::BlockSyncManagerTestHelper::ConfigureDownloadQueue(sync, {h2, h3});

  qryptcoin::primitives::Hash256 requested{};
  if (!qryptcoin::node::BlockSyncManagerTestHelper::PrepareBlockRequest(sync, peer.id, &requested)) {
    std::cerr << "expected scheduler to request missing parent via escalation\n";
    return false;
  }
  if (requested != h1) {
    std::cerr << "expected first request to be parent hash (h1)\n";
    return false;
  }

  // Pipeline should continue once the parent is in-flight.
  qryptcoin::primitives::Hash256 requested2{};
  if (!qryptcoin::node::BlockSyncManagerTestHelper::PrepareBlockRequest(sync, peer.id, &requested2)) {
    std::cerr << "expected scheduler to pipeline next block request\n";
    return false;
  }
  if (requested2 != h2) {
    std::cerr << "expected second request to be child hash (h2)\n";
    return false;
  }
  return true;
}

bool TestStallBreakerRebuildsFrontierPlan() {
  auto dir = MakeTempDir("scheduler_deadlock_stall_breaker");
  qryptcoin::node::ChainState chain((dir / "blocks.dat").string(), (dir / "utxo.dat").string());
  qryptcoin::net::PeerManager peers(qryptcoin::config::GetNetworkConfig());
  qryptcoin::node::BlockSyncManager sync(chain, peers);
  sync.Start();

  qryptcoin::net::PeerManager::PeerInfo peer;
  peer.id = 1;
  peer.inbound = false;
  peer.address = "203.0.113.11:9375";
  qryptcoin::net::PeerManagerTestHelper::AddFakePeer(peers, peer.id, peer.inbound, peer.address);
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, peer);

  qryptcoin::primitives::Hash256 h1{};
  qryptcoin::primitives::Hash256 h2{};
  qryptcoin::primitives::Hash256 h3{};
  h1[0] = 0x11;
  h2[0] = 0x22;
  h3[0] = 0x33;

  qryptcoin::node::BlockSyncManagerTestHelper::ConfigureHeaderChain(sync, peer, h1, h2, h3);
  qryptcoin::node::BlockSyncManagerTestHelper::ConfigureDownloadQueue(sync, {h2, h3});
  qryptcoin::node::BlockSyncManagerTestHelper::SetLastBlockProgress(
      sync, std::chrono::steady_clock::now() - 2min);

  if (!WaitUntil([&]() { return sync.GetStats().stall_breaker_activations >= 1; }, 12s)) {
    std::cerr << "expected stall-breaker to activate\n";
    return false;
  }

  if (!qryptcoin::node::BlockSyncManagerTestHelper::DownloadQueueContains(sync, h1)) {
    std::cerr << "expected stall-breaker to rebuild queue with missing parent\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!TestParentFirstEscalationAvoidsDeadlock()) {
    return EXIT_FAILURE;
  }
  if (!TestStallBreakerRebuildsFrontierPlan()) {
    return EXIT_FAILURE;
  }
  std::cout << "scheduler_deadlock_tests: OK\n";
  return EXIT_SUCCESS;
}

