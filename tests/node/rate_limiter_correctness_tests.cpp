// Validates that requested HEADERS responses are not rate-limited while
// unsolicited HEADERS floods are.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <thread>

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

  static int GetBanScore(const PeerManager& manager, const std::string& host) {
    std::lock_guard<std::mutex> lock(manager.peers_mutex_);
    auto it = manager.ban_scores_.find(host);
    if (it == manager.ban_scores_.end()) {
      return 0;
    }
    return it->second;
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

  static void SetHeadersRequestOutstanding(BlockSyncManager& sync,
                                           std::uint64_t peer_id,
                                           bool outstanding) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    auto it = sync.peer_workers_.find(peer_id);
    if (it != sync.peer_workers_.end()) {
      it->second.headers_request_outstanding = outstanding;
    }
  }

  static bool IsHeadersRequestOutstanding(const BlockSyncManager& sync,
                                         std::uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(sync.mutex_);
    auto it = sync.peer_workers_.find(peer_id);
    if (it == sync.peer_workers_.end()) {
      return false;
    }
    return it->second.headers_request_outstanding;
  }

  static void RunPeerLoop(BlockSyncManager& sync,
                          std::stop_token stop,
                          net::PeerManager::PeerInfo info,
                          const std::shared_ptr<net::PeerSession>& session) {
    sync.PeerLoop(stop, std::move(info), session);
  }
};

}  // namespace qryptcoin::node

namespace {

using namespace std::chrono_literals;

struct SessionPair {
  std::shared_ptr<qryptcoin::net::PeerSession> server;
  std::shared_ptr<qryptcoin::net::PeerSession> client;
  qryptcoin::config::NetworkConfig config;
};

bool WaitUntil(const std::function<bool()>& predicate,
               std::chrono::steady_clock::duration timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(10ms);
  }
  return predicate();
}

bool CreatePlaintextSessionPair(SessionPair* out) {
  if (!out) {
    return false;
  }
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
    std::cerr << "server handshake failed: " << (server_error.empty() ? "unknown" : server_error)
              << "\n";
    return false;
  }

  out->server = std::move(server);
  out->client = std::move(client);
  out->config = cfg;
  return true;
}

qryptcoin::node::ChainState MakeNoopChainState() {
  // The rate limiter tests only send empty HEADERS messages, so the chain state
  // is never consulted. Use throwaway paths to avoid touching any real datadir.
  return qryptcoin::node::ChainState("rate_limit_blocks.dat", "rate_limit_utxo.dat");
}

bool TestRequestedHeadersNotRateLimited() {
  auto chain = MakeNoopChainState();
  qryptcoin::net::PeerManager peers(qryptcoin::config::GetNetworkConfig());
  qryptcoin::node::BlockSyncManager sync(chain, peers);
  sync.SetRateLimits(/*inv_per_sec=*/0, /*getdata_per_sec=*/0, /*headers_per_sec=*/1,
                     /*block_per_sec=*/0, /*tx_per_sec=*/0);

  constexpr std::uint64_t kPeerId = 1;
  constexpr auto kPeerAddress = "203.0.113.5:9375";
  qryptcoin::net::PeerManagerTestHelper::AddFakePeer(
      peers, kPeerId, /*inbound=*/false, kPeerAddress);

  SessionPair sessions;
  if (!CreatePlaintextSessionPair(&sessions)) {
    return false;
  }

  qryptcoin::net::PeerManager::PeerInfo info;
  info.id = kPeerId;
  info.inbound = false;
  info.address = kPeerAddress;
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, info, sessions.server);

  std::jthread loop_thread([&](std::stop_token stop) {
    qryptcoin::node::BlockSyncManagerTestHelper::RunPeerLoop(sync, stop, info, sessions.server);
  });

  qryptcoin::net::messages::HeadersMessage empty_headers{};
  const auto msg = qryptcoin::net::messages::EncodeHeaders(empty_headers);

  for (int i = 0; i < 5; ++i) {
    qryptcoin::node::BlockSyncManagerTestHelper::SetHeadersRequestOutstanding(sync, kPeerId, true);
    if (!sessions.client->Send(msg)) {
      std::cerr << "failed to send HEADERS message\n";
      return false;
    }
    if (!WaitUntil([&]() {
          return !qryptcoin::node::BlockSyncManagerTestHelper::IsHeadersRequestOutstanding(sync, kPeerId);
        },
        2s)) {
      std::cerr << "timed out waiting for HEADERS to be processed\n";
      return false;
    }
  }

  // Signal stop BEFORE closing sessions so PeerLoop sees the stop token and
  // skips spawning a detached disconnect thread that could race with the
  // destruction of stack-local PeerManager.
  loop_thread.request_stop();
  sessions.server->Close();
  sessions.client->Close();
  loop_thread.join();

  const int ban_score = qryptcoin::net::PeerManagerTestHelper::GetBanScore(peers, "203.0.113.5");
  if (ban_score != 0) {
    std::cerr << "expected no ban score for requested HEADERS, got " << ban_score << "\n";
    return false;
  }
  return true;
}

bool TestUnsolicitedHeadersAreRateLimited() {
  auto chain = MakeNoopChainState();
  qryptcoin::net::PeerManager peers(qryptcoin::config::GetNetworkConfig());
  qryptcoin::node::BlockSyncManager sync(chain, peers);
  sync.SetRateLimits(/*inv_per_sec=*/0, /*getdata_per_sec=*/0, /*headers_per_sec=*/1,
                     /*block_per_sec=*/0, /*tx_per_sec=*/0);

  constexpr std::uint64_t kPeerId = 1;
  constexpr auto kPeerAddress = "203.0.113.5:9375";
  qryptcoin::net::PeerManagerTestHelper::AddFakePeer(
      peers, kPeerId, /*inbound=*/false, kPeerAddress);

  SessionPair sessions;
  if (!CreatePlaintextSessionPair(&sessions)) {
    return false;
  }

  qryptcoin::net::PeerManager::PeerInfo info;
  info.id = kPeerId;
  info.inbound = false;
  info.address = kPeerAddress;
  qryptcoin::node::BlockSyncManagerTestHelper::AddPeerWorker(sync, info, sessions.server);

  std::jthread loop_thread([&](std::stop_token stop) {
    qryptcoin::node::BlockSyncManagerTestHelper::RunPeerLoop(sync, stop, info, sessions.server);
  });

  qryptcoin::net::messages::HeadersMessage empty_headers{};
  const auto msg = qryptcoin::net::messages::EncodeHeaders(empty_headers);

  for (int i = 0; i < 10; ++i) {
    if (!sessions.client->Send(msg)) {
      std::cerr << "failed to send HEADERS messages\n";
      return false;
    }
    std::this_thread::sleep_for(50ms);
  }
  if (!WaitUntil([&]() {
        return qryptcoin::net::PeerManagerTestHelper::GetBanScore(peers, "203.0.113.5") >= 10;
      },
      5s)) {
    std::cerr << "expected unsolicited HEADERS flood to trigger ban score\n";
    return false;
  }

  // Signal stop BEFORE closing sessions so PeerLoop sees the stop token and
  // skips spawning a detached disconnect thread that could race with the
  // destruction of stack-local PeerManager.
  loop_thread.request_stop();
  sessions.server->Close();
  sessions.client->Close();
  loop_thread.join();

  const int ban_score = qryptcoin::net::PeerManagerTestHelper::GetBanScore(peers, "203.0.113.5");
  if (ban_score < 10) {
    std::cerr << "expected ban score >= 10 for unsolicited HEADERS rate limit, got " << ban_score
              << "\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!TestRequestedHeadersNotRateLimited()) {
    return EXIT_FAILURE;
  }
  if (!TestUnsolicitedHeadersAreRateLimited()) {
    return EXIT_FAILURE;
  }
  std::cout << "rate_limiter_correctness_tests: OK\n";
  return EXIT_SUCCESS;
}
