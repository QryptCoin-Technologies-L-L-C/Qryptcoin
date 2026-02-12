#pragma once

#include <mutex>
#include <optional>
#include <thread>
#include <vector>
#include <string>

#include "config/network.hpp"
#include "net/encrypted_channel.hpp"
#include "net/messages.hpp"

namespace qryptcoin::net {

class PeerSession {
 public:
  PeerSession();
  explicit PeerSession(FrameChannel channel, bool initiator);
  PeerSession(const PeerSession&) = delete;
  PeerSession& operator=(const PeerSession&) = delete;
  PeerSession(PeerSession&& other) noexcept;
  PeerSession& operator=(PeerSession&& other) noexcept;

  bool Connect(const std::string& host, std::uint16_t port);
  // Connect via a SOCKS5 proxy and then perform the encrypted
  // handshake over the resulting stream. This is used for Tor/I2P
  // style transports where the proxy abstracts away the underlying
  // network.
  bool ConnectViaProxy(const std::string& proxy_host, std::uint16_t proxy_port,
                       const std::string& dest_host, std::uint16_t dest_port);
  bool Accept(FrameChannel channel);
  bool PerformHandshake(const config::NetworkConfig& cfg,
                        std::uint32_t local_protocol_version = messages::kCurrentProtocolVersion);
  void SetEnforcePeerIdentityPinning(bool enforce) noexcept {
    enforce_peer_identity_pinning_ = enforce;
  }
  bool Send(const messages::Message& message);
  bool Receive(messages::Message* message);
  std::chrono::steady_clock::time_point LastActivity() const { return last_activity_; }
  void UpdateActivity() { last_activity_ = std::chrono::steady_clock::now(); }
  void SetLocalSessionNonce(std::uint64_t nonce) noexcept { local_session_nonce_ = nonce; }
  std::string PeerAddress() const { return secure_channel_.PeerAddress(); }
  // Remote peer's long-term transport identity key (Dilithium public key),
  // populated when encrypted transport authentication is enabled.
  const std::vector<std::uint8_t>& peer_identity_public_key() const noexcept {
    return peer_identity_public_key_;
  }
  void Close();
  config::EncryptionMode negotiated_mode() const { return negotiated_mode_; }
  const std::string& last_error() const { return last_error_; }

 private:
  bool initiator_{false};
  bool enforce_peer_identity_pinning_{true};
  std::string dial_target_;
  FrameChannel channel_;
  EncryptedChannel secure_channel_{FrameChannel{}};
  config::EncryptionMode negotiated_mode_{config::EncryptionMode::kPlaintext};
  messages::VersionMessage remote_version_{};
  std::vector<std::uint8_t> peer_identity_public_key_;
  std::mutex send_mutex_;
  std::uint64_t local_session_nonce_{0};
  std::chrono::steady_clock::time_point last_activity_{std::chrono::steady_clock::now()};
  std::string last_error_;
};

}  // namespace qryptcoin::net
