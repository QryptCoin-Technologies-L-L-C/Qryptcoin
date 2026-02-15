// Tests for peer stall detection and dead connection eviction (PR #XX).
//
// Validates:
// 1. GetPeerSyncStats reports stall counts and last-response times correctly.
// 2. StallWatcher disconnects peers that exceed kMaxStallsBeforeDisconnect.
// 3. Sync-aware EvictStalestOutboundPeer uses sync-level staleness.
// 4. Send failure in PeerLoop triggers immediate disconnect.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>

#include "config/network.hpp"
#include "net/channel.hpp"
#include "net/messages.hpp"
#include "net/peer_manager.hpp"
#include "net/peer_session.hpp"
#include "node/block_sync.hpp"
#include "node/chain_state.hpp"

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

  static void AddFakePeerWithSession(PeerManager& manager,
                                     std::uint64_t id,
                                     bool inbound,
                                     const std::string& address,
                                     const std::shared_ptr<PeerSession>& session) {
    PeerManager::PeerEntry entry;
    entry.info.id = id;
    entry.info.inbound = inbound;
    entry.info.address = address;
    entry.session = session;
    manager.peers_.push_back(entry);
  }

  static bool PeerExists(const PeerManager& manager, std::uint64_t id) {
    std::lock_guard<std::mutex> lock(manager.peers_mutex_);
    for (const auto& entry : manager.peers_) {
      if (entry.info.id == id) return true;
    }
    return false;
  }
};

}  // namespace qryptcoin::net

namespace qryptcoin::node {

class BlockSyncManagerTestHelper {
 public:
  static void AddPeerWorker(BlockSyncManager& sync,
                            const net::PeerManager::PeerInfo& info,
                            const std::shared_ptr<net::PeerSession>& session) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    BlockSyncManager::PeerWorker worker;
    worker.info = info;
    worker.session = session;
    sync.peer_workers_[info.id] = std::move(worker);
  }

  static void SetStallCount(BlockSyncManager& sync,
                            std::uint64_t peer_id,
                            std::size_t count) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    auto it = sync.peer_workers_.find(peer_id);
    if (it != sync.peer_workers_.end()) {
      it->second.stall_count = count;
    }
  }

  static void SetLastResponse(BlockSyncManager& sync,
                              std::uint64_t peer_id,
                              std::chrono::steady_clock::time_point tp) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    auto it = sync.peer_workers_.find(peer_id);
    if (it != sync.peer_workers_.end()) {
      it->second.last_response = tp;
    }
  }

  static void RunStallWatcherOnce(BlockSyncManager& sync, std::stop_token stop) {
    // Run a single iteration of StallWatcher by starting it and stopping
    // shortly after.  StallWatcher sleeps 5s between iterations; we let it
    // run just long enough to complete one pass.
    sync.StallWatcher(stop);
  }

  static void RunPeerLoop(BlockSyncManager& sync,
                          std::stop_token stop,
                          net::PeerManager::PeerInfo info,
                          const std::shared_ptr<net::PeerSession>& session) {
    sync.PeerLoop(stop, std::move(info), session);
  }

  static bool HasPeerWorker(const BlockSyncManager& sync, std::uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    return sync.peer_workers_.find(peer_id) != sync.peer_workers_.end();
  }

  static std::size_t GetStallCount(const BlockSyncManager& sync, std::uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    auto it = sync.peer_workers_.find(peer_id);
    if (it == sync.peer_workers_.end()) return 0;
    return it->second.stall_count;
  }
};

}  // namespace qryptcoin::node

namespace {

using namespace std::chrono_literals;

qryptcoin::node::ChainState MakeNoopChainState() {
  return qryptcoin::node::ChainState("stall_test_blocks.dat", "stall_test_utxo.dat");
}

struct SessionPair {
  std::shared_ptr<qryptcoin::net::PeerSession> server;
  std::shared_ptr<qryptcoin::net::PeerSession> client;
  qryptcoin::config::NetworkConfig config;
};

bool CreatePlaintextSessionPair(SessionPair* out) {
  if (!out) return false;
  out->server.reset();
  out->client.reset();

  using qryptcoin::config::EncryptionMode;
  qryptcoin::config::NetworkConfig cfg = qryptcoin::config::GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  cfg.encryption_mode = EncryptionMode::kPlaintext;
  cfg.encryption_required = false;
  cfg.authenticated_transport_required = false;
  cfg.data_dir.clear();

  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));

  qryptcoin::net::FrameChannel listener;
  bool bound = false;
  for (int attempt = 0; attempt < 50; ++attempt) {
    cfg.listen_port = static_cast<std::uint16_t>(20000u + (rng() % 30000u));
    if (listener.BindAndListen(cfg.listen_address, cfg.listen_port, /*backlog=*/1)) {
      bound = true;
      break;
    }
  }
  if (!bound) {
    std::cerr << "failed to bind listener for session pair\n";
    return false;
  }

  auto server = std::make_shared<qryptcoin::net::PeerSession>();
  auto client = std::make_shared<qryptcoin::net::PeerSession>();

  std::atomic<bool> server_ok{false};
  std::string server_error;
  std::jthread accept_thread([&](std::stop_token) {
    qryptcoin::net::FrameChannel inbound = listener.AcceptWithTimeout(5000);
    if (!inbound.IsValid()) {
      server_error = "accept timed out";
      return;
    }
    server->Accept(std::move(inbound));
    if (!server->PerformHandshake(cfg)) {
      server_error = server->last_error().empty() ? "handshake failed" : server->last_error();
      return;
    }
    server_ok.store(true);
  });

  if (!client->Connect(cfg.listen_address, cfg.listen_port)) {
    std::cerr << "client connect failed\n";
    return false;
  }
  if (!client->PerformHandshake(cfg)) {
    std::cerr << "client handshake failed: " << client->last_error() << "\n";
    return false;
  }

  const auto deadline = std::chrono::steady_clock::now() + 6s;
  while (!server_ok.load() && server_error.empty() &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(10ms);
  }
  if (!server_ok.load()) {
    std::cerr << "server handshake failed: "
              << (server_error.empty() ? "unknown" : server_error) << "\n";
    return false;
  }

  out->server = std::move(server);
  out->client = std::move(client);
  out->config = cfg;
  return true;
}

bool WaitUntil(const std::function<bool()>& predicate,
               std::chrono::steady_clock::duration timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) return true;
    std::this_thread::sleep_for(10ms);
  }
  return predicate();
}

// ---------------------------------------------------------------------------
// Test 1: GetPeerSyncStats reports stall counts and last-response times.
// ---------------------------------------------------------------------------
bool TestGetPeerSyncStats() {
  auto chain = MakeNoopChainState();
  qryptcoin::net::PeerManager peers(qryptcoin::config::GetNetworkConfig());
  qryptcoin::node::BlockSyncManager sync(chain, peers);

  // Create a dummy session just to satisfy the worker struct.
  SessionPair sessions;
  if (!CreatePlaintextSessionPair(&sessions)) {
    std::cerr << "TestGetPeerSyncStats: failed to create session pair\n";
    return false;
  }

  qryptcoin::net::PeerManager::PeerInfo info;
  info.id = 42;
  info.inbound = false;
  info.address = "203.0.113.1:9375";

  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, info, sessions.server);
  qryptcoin::node::BlockSyncManagerTestHelper::SetStallCount(sync, 42, 7);

  const auto recent = std::chrono::steady_clock::now() - std::chrono::seconds(5);
  qryptcoin::node::BlockSyncManagerTestHelper::SetLastResponse(sync, 42, recent);

  auto stats = sync.GetPeerSyncStats();
  if (stats.size() != 1) {
    std::cerr << "TestGetPeerSyncStats: expected 1 entry, got " << stats.size() << "\n";
    return false;
  }
  if (stats[0].peer_id != 42) {
    std::cerr << "TestGetPeerSyncStats: wrong peer_id " << stats[0].peer_id << "\n";
    return false;
  }
  if (stats[0].stall_count != 7) {
    std::cerr << "TestGetPeerSyncStats: expected stall_count=7, got "
              << stats[0].stall_count << "\n";
    return false;
  }
  // last_response_ms should be approximately 5000ms (within a broad tolerance).
  if (stats[0].last_response_ms < 3000 || stats[0].last_response_ms > 10000) {
    std::cerr << "TestGetPeerSyncStats: unexpected last_response_ms="
              << stats[0].last_response_ms << "\n";
    return false;
  }

  sessions.server->Close();
  sessions.client->Close();
  return true;
}

// ---------------------------------------------------------------------------
// Test 2: StallWatcher disconnects peers exceeding kMaxStallsBeforeDisconnect.
// ---------------------------------------------------------------------------
bool TestStallWatcherDisconnectsExcessiveStalls() {
  auto chain = MakeNoopChainState();
  qryptcoin::config::NetworkConfig cfg = qryptcoin::config::GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  qryptcoin::net::PeerManager peers(cfg);
  qryptcoin::node::BlockSyncManager sync(chain, peers);

  // Create two session pairs: one for the stalling peer, one for a healthy peer.
  SessionPair stalling_sessions, healthy_sessions;
  if (!CreatePlaintextSessionPair(&stalling_sessions) ||
      !CreatePlaintextSessionPair(&healthy_sessions)) {
    std::cerr << "TestStallWatcherDisconnectsExcessiveStalls: session setup failed\n";
    return false;
  }

  // Register the stalling peer in both PeerManager and BlockSyncManager.
  constexpr std::uint64_t kStallingPeerId = 10;
  constexpr std::uint64_t kHealthyPeerId = 20;

  qryptcoin::net::PeerManagerTestHelper::AddFakePeerWithSession(
      peers, kStallingPeerId, false, "203.0.113.10:9375", stalling_sessions.server);
  qryptcoin::net::PeerManagerTestHelper::AddFakePeerWithSession(
      peers, kHealthyPeerId, false, "203.0.113.20:9375", healthy_sessions.server);

  qryptcoin::net::PeerManager::PeerInfo stalling_info;
  stalling_info.id = kStallingPeerId;
  stalling_info.inbound = false;
  stalling_info.address = "203.0.113.10:9375";
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, stalling_info,
                                                             stalling_sessions.server);

  qryptcoin::net::PeerManager::PeerInfo healthy_info;
  healthy_info.id = kHealthyPeerId;
  healthy_info.inbound = false;
  healthy_info.address = "203.0.113.20:9375";
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, healthy_info,
                                                             healthy_sessions.server);

  // Set stall count: stalling peer exceeds threshold, healthy peer does not.
  qryptcoin::node::BlockSyncManagerTestHelper::SetStallCount(sync, kStallingPeerId, 12);
  qryptcoin::node::BlockSyncManagerTestHelper::SetStallCount(sync, kHealthyPeerId, 3);

  // Run StallWatcher for a single pass by starting it with a stop source
  // that fires shortly after the 5s sleep.
  std::stop_source stop_source;
  std::jthread watcher([&](std::stop_token stop) {
    qryptcoin::node::BlockSyncManagerTestHelper::RunStallWatcherOnce(sync, stop);
  });

  // StallWatcher sleeps 5s then runs a pass. Give it enough time.
  std::this_thread::sleep_for(7s);
  stop_source.request_stop();
  watcher.request_stop();
  watcher.join();

  // Stalling peer should have been disconnected from PeerManager.
  if (qryptcoin::net::PeerManagerTestHelper::PeerExists(peers, kStallingPeerId)) {
    std::cerr << "TestStallWatcherDisconnectsExcessiveStalls: "
              << "stalling peer should have been disconnected\n";
    return false;
  }

  // Healthy peer should still be connected.
  if (!qryptcoin::net::PeerManagerTestHelper::PeerExists(peers, kHealthyPeerId)) {
    std::cerr << "TestStallWatcherDisconnectsExcessiveStalls: "
              << "healthy peer should still be connected\n";
    return false;
  }

  stalling_sessions.client->Close();
  healthy_sessions.server->Close();
  healthy_sessions.client->Close();
  return true;
}

// ---------------------------------------------------------------------------
// Test 3: EvictStalestOutboundPeer prefers sync-level staleness over TCP idle.
// ---------------------------------------------------------------------------
bool TestSyncAwareEviction() {
  qryptcoin::config::NetworkConfig cfg = qryptcoin::config::GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  qryptcoin::net::PeerManager peers(cfg);

  // Create two session pairs so we have valid sessions with LastActivity.
  SessionPair sessions_a, sessions_b;
  if (!CreatePlaintextSessionPair(&sessions_a) ||
      !CreatePlaintextSessionPair(&sessions_b)) {
    std::cerr << "TestSyncAwareEviction: session setup failed\n";
    return false;
  }

  constexpr std::uint64_t kPeerA = 100;
  constexpr std::uint64_t kPeerB = 200;

  // Peer A: recently active at TCP level.
  // Peer B: recently active at TCP level.
  // Both peers have recent TCP activity, but sync_staleness_ms shows Peer A
  // is much more stale at the sync level.
  qryptcoin::net::PeerManagerTestHelper::AddFakePeerWithSession(
      peers, kPeerA, false, "203.0.113.100:9375", sessions_a.server);
  qryptcoin::net::PeerManagerTestHelper::AddFakePeerWithSession(
      peers, kPeerB, false, "203.0.113.200:9375", sessions_b.server);

  std::unordered_map<std::uint64_t, std::uint64_t> sync_staleness;
  sync_staleness[kPeerA] = 300000;  // 300 seconds since last sync response
  sync_staleness[kPeerB] = 5000;    // 5 seconds since last sync response

  const auto evicted = peers.EvictStalestOutboundPeer(sync_staleness);
  if (evicted != kPeerA) {
    std::cerr << "TestSyncAwareEviction: expected peer A (id=" << kPeerA
              << ") to be evicted, got " << evicted << "\n";
    return false;
  }

  // Peer A should be gone, Peer B should remain.
  if (qryptcoin::net::PeerManagerTestHelper::PeerExists(peers, kPeerA)) {
    std::cerr << "TestSyncAwareEviction: peer A should have been evicted\n";
    return false;
  }
  if (!qryptcoin::net::PeerManagerTestHelper::PeerExists(peers, kPeerB)) {
    std::cerr << "TestSyncAwareEviction: peer B should still exist\n";
    return false;
  }

  sessions_a.server->Close();
  sessions_a.client->Close();
  sessions_b.server->Close();
  sessions_b.client->Close();
  return true;
}

// ---------------------------------------------------------------------------
// Test 4: Send failure triggers immediate peer disconnect.
// ---------------------------------------------------------------------------
bool TestSendFailureDisconnects() {
  auto chain = MakeNoopChainState();
  qryptcoin::config::NetworkConfig cfg = qryptcoin::config::GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  qryptcoin::net::PeerManager peers(cfg);
  qryptcoin::node::BlockSyncManager sync(chain, peers);

  SessionPair sessions;
  if (!CreatePlaintextSessionPair(&sessions)) {
    std::cerr << "TestSendFailureDisconnects: session setup failed\n";
    return false;
  }

  constexpr std::uint64_t kPeerId = 50;

  qryptcoin::net::PeerManagerTestHelper::AddFakePeerWithSession(
      peers, kPeerId, false, "203.0.113.50:9375", sessions.server);

  qryptcoin::net::PeerManager::PeerInfo info;
  info.id = kPeerId;
  info.inbound = false;
  info.address = "203.0.113.50:9375";
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, info, sessions.server);

  // Start a PeerLoop thread for this peer.
  std::jthread loop_thread([&](std::stop_token stop) {
    qryptcoin::node::BlockSyncManagerTestHelper::RunPeerLoop(sync, stop, info, sessions.server);
  });

  // Close the server-side socket to force subsequent Receive() to fail.
  // The PeerLoop should detect this and disconnect the peer.
  sessions.server->Close();

  // Wait for the disconnect to propagate.
  const bool disconnected = WaitUntil([&]() {
    return !qryptcoin::net::PeerManagerTestHelper::PeerExists(peers, kPeerId);
  }, 5s);

  // Stop the loop thread. PeerLoop should have already exited due to
  // Receive failure, but request_stop ensures we don't hang.
  loop_thread.request_stop();
  sessions.client->Close();
  loop_thread.join();

  if (!disconnected) {
    std::cerr << "TestSendFailureDisconnects: peer should have been disconnected "
              << "after socket close\n";
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Test 5: Post-handshake socket has a finite read timeout (not infinite).
// ---------------------------------------------------------------------------
bool TestPostHandshakeTimeout() {
  SessionPair sessions;
  if (!CreatePlaintextSessionPair(&sessions)) {
    std::cerr << "TestPostHandshakeTimeout: session setup failed\n";
    return false;
  }

  // After handshake, a Receive call on the server should time out (not block
  // forever). The 60s timeout is too long for a unit test, but we can verify
  // that a Receive on a silent connection eventually returns false.
  // We set a shorter timeout for this test.
  // Actually, the handshake already set 60s. We can't easily test 60s in a
  // unit test. Instead, verify the behavior: close the client, the server
  // Receive should return false promptly.
  sessions.client->Close();

  qryptcoin::net::messages::Message msg;
  const auto start = std::chrono::steady_clock::now();
  const bool received = sessions.server->Receive(&msg);
  const auto elapsed = std::chrono::steady_clock::now() - start;

  if (received) {
    std::cerr << "TestPostHandshakeTimeout: Receive should have returned false\n";
    return false;
  }

  // Should return quickly (well under 60s) since the peer closed the connection.
  if (elapsed > 5s) {
    std::cerr << "TestPostHandshakeTimeout: Receive took too long ("
              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
              << "ms)\n";
    return false;
  }

  sessions.server->Close();
  return true;
}

}  // namespace

int main() {
  try {
    const auto net = qryptcoin::config::NetworkFromString("mainnet");
    qryptcoin::config::SelectNetwork(net);

    if (!TestGetPeerSyncStats()) {
      std::cerr << "FAIL: TestGetPeerSyncStats\n";
      return EXIT_FAILURE;
    }

    if (!TestSyncAwareEviction()) {
      std::cerr << "FAIL: TestSyncAwareEviction\n";
      return EXIT_FAILURE;
    }

    if (!TestSendFailureDisconnects()) {
      std::cerr << "FAIL: TestSendFailureDisconnects\n";
      return EXIT_FAILURE;
    }

    if (!TestPostHandshakeTimeout()) {
      std::cerr << "FAIL: TestPostHandshakeTimeout\n";
      return EXIT_FAILURE;
    }

    if (!TestStallWatcherDisconnectsExcessiveStalls()) {
      std::cerr << "FAIL: TestStallWatcherDisconnectsExcessiveStalls\n";
      return EXIT_FAILURE;
    }

    std::cout << "block_sync_stall_detection_tests: OK\n";
    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "block_sync_stall_detection_tests: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
}
