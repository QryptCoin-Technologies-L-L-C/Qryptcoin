#include "net/peer_manager.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <chrono>

#include "net/messages.hpp"

namespace qryptcoin::net {

namespace {

constexpr std::size_t kMaxInboundPeers = 32;
constexpr std::size_t kMaxOutboundPeers = 32;
constexpr std::size_t kMaxTotalPeers = 64;
// Per-subnet cap to avoid a single /24 dominating inbound slots.
constexpr std::size_t kMaxPeersPerSubnet = 8;
// Pre-handshake inbound throttling. This is applied before expensive crypto
// (Kyber) work to reduce CPU DoS from connection floods.
constexpr std::chrono::seconds kInboundHandshakeThrottleWindow{10};
constexpr std::size_t kMaxInboundHandshakesPerHostWindow = 8;
constexpr std::size_t kMaxInboundHandshakesPerSubnetWindow = 32;
constexpr std::size_t kMaxInboundThrottleEntries = 4096;
// Disconnect peers that have been silent longer than this.
constexpr std::chrono::seconds kIdlePeerTimeout{120};
constexpr std::chrono::seconds kIdleSweepInterval{15};
constexpr int kListenerBacklog = 16;
// Simple ban scoring parameters.
constexpr int kBanThreshold = 100;
constexpr std::chrono::minutes kBanDuration{60};

}  // namespace

PeerManager::PeerManager(config::NetworkConfig config) : config_(std::move(config)) {
  inbound_handshake_ = [](PeerSession* session, const config::NetworkConfig& cfg) -> bool {
    return session != nullptr && session->PerformHandshake(cfg);
  };
}

PeerManager::~PeerManager() { Stop(); }

bool PeerManager::StartListener() {
  if (running_) return true;
  listener_channel_.SetMessageStart(config_.message_start);
  if (!listener_channel_.BindAndListen(config_.listen_address, config_.listen_port,
                                       kListenerBacklog)) {
    std::cerr << "Failed to bind P2P listener\n";
    return false;
  }
  running_ = true;
  listening_.store(true);
  listener_thread_ = std::thread(&PeerManager::ListenerThread, this);
  idle_sweeper_thread_ = std::thread(&PeerManager::IdleSweeperThread, this);
  return true;
}

void PeerManager::Stop() {
  running_ = false;
  listener_channel_.socket().Close();
  if (listener_thread_.joinable()) {
    listener_thread_.join();
  }
  if (idle_sweeper_thread_.joinable()) {
    idle_sweeper_thread_.join();
  }
  auto infos = SnapshotPeerInfos();
  for (const auto& info : infos) {
    DisconnectPeer(info.id);
  }
  listening_.store(false);
}

bool PeerManager::ConnectToPeer(const std::string& host, std::uint16_t port, std::string* error,
                                bool enforce_identity_pins) {
  if (error) {
    error->clear();
  }

  auto dial_with = [&](const config::NetworkConfig& cfg,
                       std::uint32_t local_protocol,
                       std::shared_ptr<PeerSession>* out_peer,
                       std::string* out_error) -> bool {
    if (out_error) {
      out_error->clear();
    }
    PeerSession session;
    // When a SOCKS5 proxy is configured, use it for outbound dials so
    // operators can route traffic through Tor/I2P gateways. Otherwise,
    // connect directly as before.
    const bool use_proxy = !cfg.socks5_proxy_host.empty() && cfg.socks5_proxy_port != 0;
    if (use_proxy) {
      if (!session.ConnectViaProxy(cfg.socks5_proxy_host,
                                   cfg.socks5_proxy_port,
                                   host, port)) {
        if (out_error) {
          *out_error = !session.last_error().empty() ? session.last_error() : "proxy connect failed";
        }
        return false;
      }
    } else {
      if (!session.Connect(host, port)) {
        if (out_error) {
          *out_error = !session.last_error().empty() ? session.last_error() : "tcp connect failed";
        }
        return false;
      }
    }
    session.SetEnforcePeerIdentityPinning(enforce_identity_pins);
    if (!session.PerformHandshake(cfg, local_protocol)) {
      if (out_error) {
        *out_error = !session.last_error().empty() ? session.last_error() : "handshake failed";
      }
      return false;
    }
    if (out_peer) {
      *out_peer = std::make_shared<PeerSession>(std::move(session));
    }
    return true;
  };

  std::shared_ptr<PeerSession> peer;
  std::string primary_error;
  if (!dial_with(config_, messages::kCurrentProtocolVersion, &peer, &primary_error)) {
    if (primary_error == "peer identity key mismatch") {
      std::cerr << "[net] warn: peer identity key mismatch for outbound target " << host
                << "; refusing connection\n";
    }
    if (error) {
      *error = primary_error;
    }
    return false;
  }

  PeerInfo info;
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    const std::string address = peer->PeerAddress();
    if (!HasCapacityForAddressLocked(false, address)) {
      std::cerr << "Outbound peer limit or ban reached, refusing new connection\n";
      return false;
    }
    info.id = next_peer_id_++;
    info.inbound = false;
    info.address = address;
    peers_.push_back(PeerEntry{info, peer});
  }
  NotifyPeerConnected(info, peer);
  return true;
}

void PeerManager::BroadcastInventory(const messages::InventoryMessage& inv) {
  auto sessions = SnapshotSessions();
  for (const auto& session : sessions) {
    if (!session) {
      continue;
    }
    session->Send(messages::EncodeInventory(inv));
  }
}

void PeerManager::BroadcastMessage(const messages::Message& message) {
  auto sessions = SnapshotSessions();
  for (const auto& session : sessions) {
    session->Send(message);
  }
}

void PeerManager::BroadcastPing(std::uint64_t nonce) {
  messages::Message ping = messages::EncodePing(messages::PingMessage{nonce});
  auto sessions = SnapshotSessions();
  for (const auto& session : sessions) {
    session->Send(ping);
  }
}

bool PeerManager::SendToPeer(std::uint64_t peer_id, const messages::Message& message) {
  std::shared_ptr<PeerSession> target;
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = FindPeerLocked(peer_id);
    if (it == peers_.end()) {
      return false;
    }
    target = it->session;
  }
  return target && target->Send(message);
}

bool PeerManager::DisconnectPeer(std::uint64_t peer_id) {
  PeerInfo info;
  std::shared_ptr<PeerSession> session;
  bool removed = false;
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = FindPeerLocked(peer_id);
    if (it != peers_.end()) {
      info = it->info;
      session = it->session;
      peers_.erase(it);
      removed = true;
    }
  }
  if (removed) {
    if (session) {
      session->Close();
    }
    NotifyPeerDisconnected(info);
  }
  return removed;
}

std::vector<PeerManager::PeerInfo> PeerManager::GetPeerInfos() const {
  return SnapshotPeerInfos();
}

void PeerManager::ListenerThread() {
  using clock = std::chrono::steady_clock;
  constexpr auto kDropLogInterval = std::chrono::seconds(10);
  clock::time_point last_drop_log{};
  std::uint64_t drops_since_log = 0;

  while (running_) {
    FrameChannel inbound = listener_channel_.AcceptWithTimeout(200);
    if (!inbound.IsValid()) {
      continue;
    }

    // Apply cheap gating (ban/capacity/throttles) before running the protocol
    // handshake so that banned or abusive peers do not trigger expensive Kyber
    // computations.
    const std::string prehandshake_address = inbound.socket().PeerAddress();
    bool dropped_prehandshake = false;
    bool log_drop = false;
    std::uint64_t drop_count = 0;
    {
      std::lock_guard<std::mutex> lock(peers_mutex_);
      if (!AllowInboundBeforeHandshakeLocked(prehandshake_address, clock::now())) {
        dropped_prehandshake = true;
        ++drops_since_log;
        const auto now = clock::now();
        if (last_drop_log.time_since_epoch().count() == 0 ||
            now - last_drop_log >= kDropLogInterval) {
          log_drop = true;
          drop_count = drops_since_log;
          drops_since_log = 0;
          last_drop_log = now;
        }
      }
    }
    if (dropped_prehandshake) {
      if (log_drop) {
        std::cerr << "Inbound peer limit, ban, or throttle reached, dropping connection";
        if (drop_count > 1) {
          std::cerr << " (" << drop_count << " drops in last "
                    << std::chrono::duration_cast<std::chrono::seconds>(kDropLogInterval).count()
                    << "s)";
        }
        std::cerr << "\n";
      }
      inbound.socket().Close();
      continue;
    }

    auto session = std::make_shared<PeerSession>();
    session->Accept(std::move(inbound));
    if (!inbound_handshake_(session.get(), config_)) {
      const auto err = session->last_error();
      if (err == "peer identity key mismatch") {
        std::cerr << "[net] warn: peer identity key mismatch from " << prehandshake_address
                  << "; refusing inbound connection\n";
      }
      session->Close();
      continue;
    }
    PeerInfo info;
    bool dropped = false;
    {
      std::lock_guard<std::mutex> lock(peers_mutex_);
      const std::string address = session->PeerAddress();
      if (!HasCapacityForAddressLocked(true, address)) {
        dropped = true;
        ++drops_since_log;
        const auto now = clock::now();
        if (last_drop_log.time_since_epoch().count() == 0 ||
            now - last_drop_log >= kDropLogInterval) {
          log_drop = true;
          drop_count = drops_since_log;
          drops_since_log = 0;
          last_drop_log = now;
        }
      } else {
        info.id = next_peer_id_++;
        info.inbound = true;
        info.address = address;
        peers_.push_back(PeerEntry{info, session});
      }
    }
    if (dropped) {
      if (log_drop) {
        std::cerr << "Inbound peer limit or ban reached, dropping connection";
        if (drop_count > 1) {
          std::cerr << " (" << drop_count << " drops in last "
                    << std::chrono::duration_cast<std::chrono::seconds>(kDropLogInterval).count()
                    << "s)";
        }
        std::cerr << "\n";
      }
      session->Close();
      continue;
    }
    seen_inbound_.store(true);
    NotifyPeerConnected(info, session);
  }
}

void PeerManager::IdleSweeperThread() {
  while (running_) {
    std::this_thread::sleep_for(kIdleSweepInterval);
    std::vector<std::uint64_t> to_drop;
    {
      std::lock_guard<std::mutex> lock(peers_mutex_);
      const auto now = std::chrono::steady_clock::now();
      for (const auto& entry : peers_) {
        if (!entry.session) continue;
        const auto last = entry.session->LastActivity();
        if (now - last > kIdlePeerTimeout) {
          to_drop.push_back(entry.info.id);
        }
      }
      // Apply a simple, time-based decay to ban scores for hosts
      // that are not currently banned. This prevents minor,
      // one-off misbehavior from accumulating indefinitely.
      for (auto& kv : ban_scores_) {
        const std::string& host = kv.first;
        auto it = banned_until_.find(host);
        if (it != banned_until_.end()) {
          continue;
        }
        if (kv.second > 0) {
          --kv.second;
        }
      }
    }
    for (auto id : to_drop) {
      DisconnectPeer(id);
    }
  }
}

NetworkStats PeerManager::GetStats() const {
  NetworkStats stats;
  stats.default_encryption = config_.encryption_mode;
  stats.service_bits = config_.service_bits;
  stats.dns_seeds = config_.dns_seeds;
  stats.static_seeds = config_.static_seeds;
  std::lock_guard<std::mutex> lock(peers_mutex_);
  stats.total = peers_.size();
  for (const auto& peer : peers_) {
    if (peer.info.inbound) {
      ++stats.inbound;
    } else {
      ++stats.outbound;
    }
  }
  stats.listening = listening_.load();
  stats.inbound_seen = seen_inbound_.load();
  return stats;
}

void PeerManager::SetPeerConnectedHandler(PeerConnectedHandler handler) {
  std::lock_guard<std::mutex> lock(handler_mutex_);
  on_peer_connected_ = std::move(handler);
}

void PeerManager::SetPeerDisconnectedHandler(PeerDisconnectedHandler handler) {
  std::lock_guard<std::mutex> lock(handler_mutex_);
  on_peer_disconnected_ = std::move(handler);
}

void PeerManager::NotifyPeerConnected(const PeerInfo& info,
                                      const std::shared_ptr<PeerSession>& session) {
  PeerConnectedHandler handler;
  {
    std::lock_guard<std::mutex> lock(handler_mutex_);
    handler = on_peer_connected_;
  }
  if (handler) {
    handler(info, session);
  }
}

void PeerManager::NotifyPeerDisconnected(const PeerInfo& info) {
  PeerDisconnectedHandler handler;
  {
    std::lock_guard<std::mutex> lock(handler_mutex_);
    handler = on_peer_disconnected_;
  }
  if (handler) {
    handler(info);
  }
}

std::vector<std::shared_ptr<PeerSession>> PeerManager::SnapshotSessions() const {
  std::vector<std::shared_ptr<PeerSession>> sessions;
  std::lock_guard<std::mutex> lock(peers_mutex_);
  sessions.reserve(peers_.size());
  for (const auto& peer : peers_) {
    sessions.push_back(peer.session);
  }
  return sessions;
}

std::vector<PeerManager::PeerInfo> PeerManager::SnapshotPeerInfos() const {
  std::vector<PeerInfo> infos;
  std::lock_guard<std::mutex> lock(peers_mutex_);
  infos.reserve(peers_.size());
  for (const auto& peer : peers_) {
    infos.push_back(peer.info);
  }
  return infos;
}

std::vector<PeerManager::PeerEntry>::iterator PeerManager::FindPeerLocked(std::uint64_t peer_id) {
  return std::find_if(peers_.begin(), peers_.end(),
                      [peer_id](const PeerEntry& entry) { return entry.info.id == peer_id; });
}

bool PeerManager::HasCapacityLocked(bool inbound) const {
  if (peers_.size() >= kMaxTotalPeers) {
    return false;
  }
  if (inbound) {
    return CountInboundPeersLocked() < kMaxInboundPeers;
  }
  return CountOutboundPeersLocked() < kMaxOutboundPeers;
}

std::size_t PeerManager::CountInboundPeersLocked() const {
  std::size_t count = 0;
  for (const auto& peer : peers_) {
    if (peer.info.inbound) {
      ++count;
    }
  }
  return count;
}

std::size_t PeerManager::CountOutboundPeersLocked() const {
  std::size_t count = 0;
  for (const auto& peer : peers_) {
    if (!peer.info.inbound) {
      ++count;
    }
  }
  return count;
}

bool PeerManager::HasCapacityForAddressLocked(bool inbound, const std::string& address) const {
  // Enforce global inbound/outbound/total limits first.
  if (!HasCapacityLocked(inbound)) {
    return false;
  }
  if (IsAddressBannedLocked(address)) {
    return false;
  }
  // Enforce a simple per-subnet cap so that a single /24 cannot dominate
  // the connection table.
  const std::string key = SubnetKey(address);
  std::size_t count = 0;
  for (const auto& peer : peers_) {
    if (peer.info.inbound != inbound) {
      continue;
    }
    if (SubnetKey(peer.info.address) == key) {
      ++count;
    }
  }
  return count < kMaxPeersPerSubnet;
}

bool PeerManager::IsAddressBannedLocked(const std::string& address) const {
  const std::string host = ExtractHost(address);
  auto it = banned_until_.find(host);
  if (it == banned_until_.end()) {
    return false;
  }
  const auto now = std::chrono::steady_clock::now();
  if (now >= it->second) {
    // Ban expired; clean up and allow connections again.
    banned_until_.erase(it);
    ban_scores_.erase(host);
    return false;
  }
  return true;
}

bool PeerManager::AllowInboundBeforeHandshakeLocked(const std::string& address,
                                                    std::chrono::steady_clock::time_point now) {
  if (!HasCapacityForAddressLocked(true, address)) {
    return false;
  }

  auto check_window = [&](std::unordered_map<std::string, ThrottleWindow>* table,
                          const std::string& key,
                          std::size_t limit) -> bool {
    if (!table) return false;
    if (table->size() > kMaxInboundThrottleEntries) {
      table->clear();
    }
    auto& window = (*table)[key];
    if (window.window_start.time_since_epoch().count() == 0 ||
        now - window.window_start >= kInboundHandshakeThrottleWindow) {
      window.window_start = now;
      window.count = 0;
    }
    if (window.count >= limit) {
      return false;
    }
    ++window.count;
    return true;
  };

  const std::string host = ExtractHost(address);
  if (!check_window(&inbound_host_throttle_, host, kMaxInboundHandshakesPerHostWindow)) {
    return false;
  }
  const std::string subnet = SubnetKey(address);
  if (!check_window(&inbound_subnet_throttle_, subnet, kMaxInboundHandshakesPerSubnetWindow)) {
    return false;
  }
  return true;
}

std::string PeerManager::ExtractHost(const std::string& address) {
  // IPv6 addresses may be formatted as "[addr]:port".
  if (!address.empty() && address.front() == '[') {
    auto close = address.find(']');
    if (close != std::string::npos) {
      return address.substr(1, close - 1);
    }
  }
  const auto first_colon = address.find(':');
  if (first_colon != std::string::npos &&
      address.find(':', first_colon + 1) != std::string::npos) {
    // Unbracketed IPv6 literal without a port.
    return address;
  }
  const auto pos = address.rfind(':');
  if (pos == std::string::npos) {
    return address;
  }
  return address.substr(0, pos);
}

std::string PeerManager::SubnetKey(const std::string& address) {
  const std::string host = ExtractHost(address);
  std::istringstream iss(host);
  std::string part;
  std::vector<int> octets;
  while (std::getline(iss, part, '.')) {
    try {
      int value = std::stoi(part);
      if (value < 0 || value > 255) {
        octets.clear();
        break;
      }
      octets.push_back(value);
    } catch (...) {
      octets.clear();
      break;
    }
  }
  if (octets.size() == 4) {
    // Collapse IPv4 to a /24-style key.
    std::ostringstream key;
    key << octets[0] << "." << octets[1] << "." << octets[2] << ".0/24";
    return key.str();
  }
  // Non-IPv4: treat the host itself as the key.
  return host;
}

void PeerManager::AddBanScore(std::uint64_t peer_id, int score) {
  std::string host;
  int total_score = 0;
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = FindPeerLocked(peer_id);
    if (it == peers_.end()) {
      return;
    }
    host = ExtractHost(it->info.address);
    auto& current = ban_scores_[host];
    current += score;
    total_score = current;
    if (total_score >= kBanThreshold) {
      banned_until_[host] = std::chrono::steady_clock::now() + kBanDuration;
    }
  }
  if (total_score >= kBanThreshold) {
    std::cerr << "[net] banning address " << host << " for misbehavior\n";
    DisconnectPeer(peer_id);
  }
}

void PeerManager::AddBanScoreForAddress(const std::string& address, int score) {
  if (score <= 0) {
    return;
  }
  const std::string host = ExtractHost(address);
  int total_score = 0;
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto& current = ban_scores_[host];
    current += score;
    total_score = current;
    if (total_score >= kBanThreshold) {
      banned_until_[host] = std::chrono::steady_clock::now() + kBanDuration;
    }
  }
  if (total_score >= kBanThreshold) {
    std::cerr << "[net] banning address " << host << " for handshake misbehavior\n";
    // Ensure any existing peer sessions for this host are disconnected.
    auto infos = SnapshotPeerInfos();
    for (const auto& info : infos) {
      if (ExtractHost(info.address) == host) {
        DisconnectPeer(info.id);
      }
    }
  }
}

}  // namespace qryptcoin::net
