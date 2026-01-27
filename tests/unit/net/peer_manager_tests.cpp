#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <thread>

#include "config/network.hpp"
#include "net/peer_manager.hpp"
#include "net/peer_session.hpp"

using qryptcoin::config::GetNetworkConfig;
using qryptcoin::config::NetworkFromString;
using qryptcoin::config::NetworkType;
using qryptcoin::config::SelectNetwork;
using qryptcoin::net::PeerManager;

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

  static bool HasAnyBan(const PeerManager& manager) {
    return !manager.banned_until_.empty();
  }

  static void BanHost(PeerManager& manager, const std::string& host,
                      std::chrono::steady_clock::time_point until) {
    manager.banned_until_[host] = until;
    manager.ban_scores_[host] = 100;
  }

  static void SetInboundHandshakeFn(
      PeerManager& manager,
      std::function<bool(PeerSession*, const qryptcoin::config::NetworkConfig&)> fn) {
    manager.inbound_handshake_ = std::move(fn);
  }

  static bool AllowInboundBeforeHandshake(PeerManager& manager,
                                         const std::string& address,
                                         std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(manager.peers_mutex_);
    return manager.AllowInboundBeforeHandshakeLocked(address, now);
  }
};

}  // namespace qryptcoin::net

namespace {

bool TestInboundHandshakeGatingAvoidsHandshake() {
  using namespace qryptcoin;
  config::NetworkConfig cfg = GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  cfg.encryption_mode = config::EncryptionMode::kEncrypted;
  cfg.encryption_required = true;

  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));

  for (int attempt = 0; attempt < 200; ++attempt) {
    cfg.listen_port = static_cast<std::uint16_t>(20000u + (rng() % 30000u));
    PeerManager manager(cfg);

    std::atomic<std::uint64_t> handshake_calls{0};
    qryptcoin::net::PeerManagerTestHelper::SetInboundHandshakeFn(
        manager,
        [&](net::PeerSession*, const config::NetworkConfig&) -> bool {
          handshake_calls.fetch_add(1);
          return false;
        });
    qryptcoin::net::PeerManagerTestHelper::BanHost(
        manager, "127.0.0.1",
        std::chrono::steady_clock::now() + std::chrono::minutes(10));

    if (!manager.StartListener()) {
      continue;
    }

    // Connect a banned inbound peer. The listener must drop it without
    // invoking the expensive handshake path.
    net::PeerSession client;
    if (client.Connect(cfg.listen_address, cfg.listen_port)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      client.Close();
    }

    manager.Stop();
    if (handshake_calls.load() != 0) {
      std::cerr << "expected banned inbound connection to be dropped before handshake\n";
      return false;
    }
    return true;
  }

  std::cerr << "failed to bind listener for inbound gating test\n";
  return false;
}

bool TestInboundHandshakeThrottle() {
  using namespace qryptcoin;
  PeerManager manager(GetNetworkConfig());
  const std::string address = "203.0.113.5:9375";
  const auto base = std::chrono::steady_clock::now();

  // Default limits: allow a burst of 32 per host then reject within the window.
  // (Limit was increased from 8 to 32 to handle burst traffic on seed nodes.)
  for (int i = 0; i < 32; ++i) {
    if (!qryptcoin::net::PeerManagerTestHelper::AllowInboundBeforeHandshake(manager, address, base)) {
      std::cerr << "expected inbound attempt " << i << " to be allowed\n";
      return false;
    }
  }
  if (qryptcoin::net::PeerManagerTestHelper::AllowInboundBeforeHandshake(manager, address, base)) {
    std::cerr << "expected inbound attempts to be throttled\n";
    return false;
  }

  // After the window elapses, attempts should be allowed again.
  const auto later = base + std::chrono::seconds(11);
  if (!qryptcoin::net::PeerManagerTestHelper::AllowInboundBeforeHandshake(manager, address, later)) {
    std::cerr << "expected inbound attempts to recover after throttle window\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  try {
    const auto net = NetworkFromString("mainnet");
    SelectNetwork(net);
    PeerManager manager(GetNetworkConfig());

    // Insert a synthetic peer and ensure it shows up. Use an RFC 5737
    // documentation address so the test does not reference a real LAN.
    qryptcoin::net::PeerManagerTestHelper::AddFakePeer(
        manager, 1, true, "203.0.113.5:9375");
    auto peers_before = manager.GetPeerInfos();
    if (peers_before.size() != 1u) {
      std::cerr << "expected 1 peer, found " << peers_before.size() << "\n";
      return 1;
    }

    // Accumulate ban score above the threshold; the peer should be
    // disconnected and the address added to the ban map.
    manager.AddBanScore(1, 60);
    manager.AddBanScore(1, 50);

    auto peers_after = manager.GetPeerInfos();
    if (!peers_after.empty()) {
      std::cerr << "expected peer to be disconnected after ban threshold\n";
      return 1;
    }
    if (!qryptcoin::net::PeerManagerTestHelper::HasAnyBan(manager)) {
      std::cerr << "expected banned_until_ to contain an entry after ban\n";
      return 1;
    }

    if (!TestInboundHandshakeGatingAvoidsHandshake()) {
      return 1;
    }

    if (!TestInboundHandshakeThrottle()) {
      return 1;
    }

    std::cout << "peer_manager_tests: OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "peer_manager_tests: " << ex.what() << "\n";
    return 1;
  }
}
