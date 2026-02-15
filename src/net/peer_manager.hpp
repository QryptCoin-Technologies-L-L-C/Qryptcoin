#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>

#include "config/network.hpp"
#include "net/peer_session.hpp"
#include "net/socket.hpp"

namespace qryptcoin::net {

class PeerManagerTestHelper;

struct NetworkStats {
  std::size_t total{0};
  std::size_t inbound{0};
  std::size_t outbound{0};
  config::EncryptionMode default_encryption{config::EncryptionMode::kEncrypted};
  std::uint64_t service_bits{0};
  std::vector<std::string> dns_seeds;
  std::vector<std::string> static_seeds;
  bool listening{false};
  bool inbound_seen{false};
};

class PeerManager {
 public:
  struct PeerInfo {
    std::uint64_t id{0};
    bool inbound{false};
    std::string address;
  };
  using PeerConnectedHandler =
      std::function<void(const PeerInfo&, const std::shared_ptr<PeerSession>&)>;
  using PeerDisconnectedHandler = std::function<void(const PeerInfo&)>;

  explicit PeerManager(config::NetworkConfig config);
  ~PeerManager();

  bool StartListener();
  void Stop();
  bool ConnectToPeer(const std::string& host, std::uint16_t port, std::string* error = nullptr,
                     bool enforce_identity_pins = true);
  // Allow connecting to a host that already has an outbound link. Used only
  // by the outbound maintenance loop in sparse-network fallback.
  bool ConnectToPeerAllowDuplicate(const std::string& host, std::uint16_t port,
                                   std::string* error = nullptr,
                                   bool enforce_identity_pins = true);
  void BroadcastInventory(const messages::InventoryMessage& inv);
  void BroadcastMessage(const messages::Message& message);
  void BroadcastPing(std::uint64_t nonce);
  bool SendToPeer(std::uint64_t peer_id, const messages::Message& message);
  bool DisconnectPeer(std::uint64_t peer_id);
  std::vector<PeerInfo> GetPeerInfos() const;
  NetworkStats GetStats() const;
  std::uint64_t local_session_nonce() const noexcept { return local_session_nonce_; }
  void SetPeerConnectedHandler(PeerConnectedHandler handler);
  void SetPeerDisconnectedHandler(PeerDisconnectedHandler handler);
  // Increase the ban score for a peer. When the score for a given address
  // crosses the ban threshold, the peer is disconnected and future
  // connection attempts from that address are rejected until the ban
  // expires.
  void AddBanScore(std::uint64_t peer_id, int score);
  // Increase the ban score for an address before it has been assigned a peer id
  // (e.g. during handshake). The host component is extracted automatically.
  void AddBanScoreForAddress(const std::string& address, int score);

  // Return the set of hosts that currently have outbound connections.
  // Used by the outbound maintenance loop to avoid selecting
  // already-connected addresses from the address manager.
  std::unordered_set<std::string> GetConnectedOutboundHosts() const;

  // Evict the outbound peer with the longest idle time to make room
  // for a fresh connection attempt.  Returns the evicted peer's ID,
  // or 0 if no outbound peer could be evicted.
  std::uint64_t EvictStalestOutboundPeer();
  std::uint64_t EvictStalestOutboundPeer(
      const std::unordered_map<std::uint64_t, std::uint64_t>& sync_staleness_ms);

 private:
  struct PeerEntry {
    PeerInfo info;
    std::shared_ptr<PeerSession> session;
  };

  bool ConnectToPeerInternal(const std::string& host, std::uint16_t port, std::string* error,
                              bool enforce_identity_pins,
                              bool allow_duplicate_outbound_host);

  void ListenerThread();
  void IdleSweeperThread();
  void NotifyPeerConnected(const PeerInfo& info, const std::shared_ptr<PeerSession>& session);
  void NotifyPeerDisconnected(const PeerInfo& info);
  std::vector<std::shared_ptr<PeerSession>> SnapshotSessions() const;
  std::vector<PeerInfo> SnapshotPeerInfos() const;
  std::vector<PeerEntry>::iterator FindPeerLocked(std::uint64_t peer_id);
  bool HasCapacityLocked(bool inbound) const;
  bool HasCapacityForAddressLocked(bool inbound, const std::string& address,
                                   bool allow_duplicate_outbound_host = false) const;
  std::size_t CountInboundPeersLocked() const;
  std::size_t CountOutboundPeersLocked() const;
  bool IsAddressBannedLocked(const std::string& address) const;
  bool AllowInboundBeforeHandshakeLocked(const std::string& address,
                                        std::chrono::steady_clock::time_point now);
  // Evict the least useful inbound peer to make room for a new connection.
  // Returns the evicted peer's ID, or 0 if no peer could be evicted.
  std::uint64_t EvictInboundPeerLocked();
  // Decide whether to accept a new inbound connection, potentially evicting
  // an existing peer if at capacity. Returns true if the connection should
  // be accepted.
  bool ShouldAcceptInboundLocked(const std::string& address);
  // Check whether an outbound connection to this host already exists.
  // Prevents duplicate outbound connections to the same IP.
  bool IsAlreadyConnectedOutboundLocked(const std::string& host) const;

  static std::string ExtractHost(const std::string& address);
  static std::string SubnetKey(const std::string& address);

  config::NetworkConfig config_;
  std::thread listener_thread_;
  std::thread idle_sweeper_thread_;
  std::atomic<bool> running_{false};
  std::vector<PeerEntry> peers_;
  mutable std::mutex peers_mutex_;
  std::atomic<std::uint64_t> next_peer_id_{1};
  PeerConnectedHandler on_peer_connected_;
  PeerDisconnectedHandler on_peer_disconnected_;
  mutable std::mutex handler_mutex_;
  FrameChannel listener_channel_;

  // Simple address-based ban tracking and scores.
  mutable std::unordered_map<std::string, int> ban_scores_;
  mutable std::unordered_map<std::string, std::chrono::steady_clock::time_point> banned_until_;
  std::atomic<bool> listening_{false};
  std::atomic<bool> seen_inbound_{false};

  // Configurable peer limits (set from NetworkConfig or defaults).
  std::size_t max_inbound_peers_{128};
  std::size_t max_outbound_peers_{16};
  std::size_t max_total_peers_{256};

  using InboundHandshakeFn =
      std::function<bool(PeerSession* session, const config::NetworkConfig& cfg)>;
  InboundHandshakeFn inbound_handshake_;

  struct ThrottleWindow {
    std::chrono::steady_clock::time_point window_start{};
    std::size_t count{0};
  };
  std::unordered_map<std::string, ThrottleWindow> inbound_host_throttle_;
  std::unordered_map<std::string, ThrottleWindow> inbound_subnet_throttle_;
  std::uint64_t local_session_nonce_{0};

  friend class PeerManagerTestHelper;
};

}  // namespace qryptcoin::net
