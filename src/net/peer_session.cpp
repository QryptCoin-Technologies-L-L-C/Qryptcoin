#include "net/peer_session.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#include "consensus/params.hpp"
#include "crypto/hash.hpp"
#include "net/messages.hpp"
#include "net/transport_auth.hpp"
#include "net/time_adjuster.hpp"

namespace qryptcoin::net {

namespace {

std::string ExtractHostForPin(std::string_view address) {
  if (!address.empty() && address.front() == '[') {
    const auto close = address.find(']');
    if (close != std::string_view::npos) {
      return std::string(address.substr(1, close - 1));
    }
  }
  const auto first_colon = address.find(':');
  if (first_colon != std::string_view::npos &&
      address.find(':', first_colon + 1) != std::string_view::npos) {
    // Unbracketed IPv6 literal without a port.
    return std::string(address);
  }
  const auto pos = address.rfind(':');
  if (pos == std::string_view::npos) {
    return std::string(address);
  }
  return std::string(address.substr(0, pos));
}

std::string FormatDialTarget(std::string_view host, std::uint16_t port) {
  const bool has_colon = host.find(':') != std::string_view::npos;
  if (has_colon && !(host.size() >= 2 && host.front() == '[' && host.back() == ']')) {
    return "[" + std::string(host) + "]:" + std::to_string(port);
  }
  return std::string(host) + ":" + std::to_string(port);
}

}  // namespace

PeerSession::PeerSession() : secure_channel_(FrameChannel{}) {}

PeerSession::PeerSession(FrameChannel channel, bool initiator)
    : initiator_(initiator),
      channel_(std::move(channel)),
      secure_channel_(FrameChannel{}) {}

PeerSession::PeerSession(PeerSession&& other) noexcept
    : initiator_(other.initiator_),
      enforce_peer_identity_pinning_(other.enforce_peer_identity_pinning_),
      dial_target_(std::move(other.dial_target_)),
      channel_(std::move(other.channel_)),
      secure_channel_(std::move(other.secure_channel_)),
      negotiated_mode_(other.negotiated_mode_),
      remote_version_(other.remote_version_),
      peer_identity_public_key_(std::move(other.peer_identity_public_key_)),
      local_session_nonce_(other.local_session_nonce_),
      last_activity_(other.last_activity_),
      last_useful_activity_(other.last_useful_activity_),
      last_error_(std::move(other.last_error_)) {}

PeerSession& PeerSession::operator=(PeerSession&& other) noexcept {
  if (this != &other) {
    initiator_ = other.initiator_;
    enforce_peer_identity_pinning_ = other.enforce_peer_identity_pinning_;
    dial_target_ = std::move(other.dial_target_);
    channel_ = std::move(other.channel_);
    secure_channel_ = std::move(other.secure_channel_);
    negotiated_mode_ = other.negotiated_mode_;
    remote_version_ = other.remote_version_;
    peer_identity_public_key_ = std::move(other.peer_identity_public_key_);
    local_session_nonce_ = other.local_session_nonce_;
    last_activity_ = other.last_activity_;
    last_useful_activity_ = other.last_useful_activity_;
    last_error_ = std::move(other.last_error_);
  }
  return *this;
}

bool PeerSession::Connect(const std::string& host, std::uint16_t port) {
  last_error_.clear();
  initiator_ = true;
  dial_target_ = FormatDialTarget(host, port);
  if (!channel_.Connect(host, port)) {
    last_error_ = "tcp connect failed";
    return false;
  }
  return true;
}

bool PeerSession::ConnectViaProxy(const std::string& proxy_host, std::uint16_t proxy_port,
                                  const std::string& dest_host, std::uint16_t dest_port) {
  last_error_.clear();
  initiator_ = true;
  dial_target_ = FormatDialTarget(dest_host, dest_port);
  if (!channel_.ConnectViaProxy(proxy_host, proxy_port, dest_host, dest_port)) {
    last_error_ = "tcp connect via proxy failed";
    return false;
  }
  return true;
}

bool PeerSession::Accept(FrameChannel channel) {
  last_error_.clear();
  initiator_ = false;
  dial_target_.clear();
  channel_ = std::move(channel);
  return true;
}

bool PeerSession::PerformHandshake(const config::NetworkConfig& cfg,
                                   std::uint32_t local_protocol_version) {
  last_error_.clear();
  channel_.SetMessageStart(cfg.message_start);
  // Prevent inbound/outbound handshakes from blocking shutdown indefinitely.
  constexpr int kHandshakeTimeoutMs = 5000;
  channel_.socket().SetTimeout(kHandshakeTimeoutMs);

  messages::VersionMessage local_version{};
  if (local_protocol_version < messages::kMinProtocolVersion ||
      local_protocol_version > messages::kCurrentProtocolVersion) {
    last_error_ = "unsupported local protocol version";
    return false;
  }
  local_version.protocol_version = local_protocol_version;
  local_version.services = cfg.service_bits;
  local_version.network_id = cfg.network_id;
  local_version.genesis_hash = consensus::Params(cfg.type).genesis_hash;
  const auto now = std::chrono::system_clock::now();
  const auto now_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
  local_version.timestamp = static_cast<std::uint64_t>(now_seconds);
  local_version.preferred_mode = cfg.encryption_mode;
  local_version.requires_encryption =
      cfg.encryption_required || cfg.authenticated_transport_required;
  local_version.session_nonce = local_session_nonce_;

  const auto& expected_genesis = local_version.genesis_hash;

  auto validate_peer_protocol = [&](const messages::VersionMessage& peer) -> bool {
    if (peer.protocol_version < messages::kMinProtocolVersion ||
        peer.protocol_version > messages::kCurrentProtocolVersion) {
      last_error_ = "peer protocol version unsupported";
      return false;
    }
    // Protocol v3 binds to network id and genesis hash.
    if (peer.protocol_version >= 3) {
      if (peer.network_id != cfg.network_id || peer.genesis_hash != expected_genesis) {
        last_error_ = "peer advertised wrong network id or genesis hash";
        return false;
      }
    }
    return true;
  };

  auto reject_self_connection = [&](const messages::VersionMessage& peer) -> bool {
    if (local_session_nonce_ != 0 && peer.session_nonce != 0 &&
        peer.session_nonce == local_session_nonce_) {
      last_error_ = "self-connection detected";
      return false;
    }
    return true;
  };

  if (initiator_) {
    if (!channel_.Send(messages::EncodeVersion(local_version))) {
      last_error_ = "failed to send version";
      return false;
    }
    messages::Message remote_msg;
    if (!channel_.Receive(&remote_msg)) {
      last_error_ = "failed to receive peer version message";
      return false;
    }
    if (!messages::DecodeVersion(remote_msg, &remote_version_)) {
      last_error_ = "failed to decode peer version";
      return false;
    }
    if (!validate_peer_protocol(remote_version_)) {
      return false;
    }
    if (!reject_self_connection(remote_version_)) {
      return false;
    }
    if (!channel_.Send(messages::EncodeVerAck())) {
      last_error_ = "failed to send verack";
      return false;
    }
    if (!channel_.Receive(&remote_msg)) {
      last_error_ = "failed to receive verack message";
      return false;
    }
    if (!messages::IsVerAck(remote_msg)) {
      last_error_ = "received unexpected message instead of verack";
      return false;
    }
  } else {
    messages::Message remote_msg;
    if (!channel_.Receive(&remote_msg)) {
      last_error_ = "failed to receive peer version message";
      return false;
    }
    if (!messages::DecodeVersion(remote_msg, &remote_version_)) {
      last_error_ = "failed to decode peer version";
      return false;
    }
    if (!validate_peer_protocol(remote_version_)) {
      return false;
    }
    if (!reject_self_connection(remote_version_)) {
      return false;
    }
    // Respond using a mutually supported protocol version so newer peers can
    // negotiate down if needed.
    const std::uint32_t negotiated =
        std::min<std::uint32_t>(local_version.protocol_version, remote_version_.protocol_version);
    messages::VersionMessage response_version = local_version;
    response_version.protocol_version = negotiated;
    if (!channel_.Send(messages::EncodeVersion(response_version))) {
      last_error_ = "failed to send version";
      return false;
    }
    if (!channel_.Receive(&remote_msg)) {
      last_error_ = "failed to receive verack message";
      return false;
    }
    if (!messages::IsVerAck(remote_msg)) {
      last_error_ = "received unexpected message instead of verack";
      return false;
    }
    if (!channel_.Send(messages::EncodeVerAck())) {
      last_error_ = "failed to send verack";
      return false;
    }
  }

  const std::uint32_t negotiated_protocol =
      std::min<std::uint32_t>(local_version.protocol_version, remote_version_.protocol_version);

  // Record a time-offset sample based on the peer's reported timestamp.
  const auto local_now = std::chrono::system_clock::now();
  const auto local_secs =
      std::chrono::duration_cast<std::chrono::seconds>(local_now.time_since_epoch()).count();
  if (remote_version_.timestamp != 0) {
    const auto offset =
        static_cast<std::int64_t>(remote_version_.timestamp) - static_cast<std::int64_t>(local_secs);
    AddTimeDataSample(offset);
  }

  // Use plaintext transport only when both peers explicitly prefer it and
  // neither side requires encryption; otherwise use encrypted transport.
  const bool local_plain = cfg.encryption_mode == config::EncryptionMode::kPlaintext;
  const bool remote_plain = remote_version_.preferred_mode == config::EncryptionMode::kPlaintext;
  if (local_version.requires_encryption || remote_version_.requires_encryption) {
    negotiated_mode_ = config::EncryptionMode::kEncrypted;
  } else if (local_plain && remote_plain) {
    negotiated_mode_ = config::EncryptionMode::kPlaintext;
  } else {
    negotiated_mode_ = config::EncryptionMode::kEncrypted;
  }
  if (cfg.authenticated_transport_required && cfg.data_dir.empty()) {
    last_error_ = "authenticated transport requires data_dir";
    return false;
  }
  if (cfg.authenticated_transport_required &&
      negotiated_mode_ != config::EncryptionMode::kEncrypted) {
    last_error_ = "authenticated transport requires encryption";
    return false;
  }

  peer_identity_public_key_.clear();
  std::shared_ptr<crypto::QPqDilithiumKey> identity_key;
  if (negotiated_mode_ == config::EncryptionMode::kEncrypted) {
    std::string id_error;
    if (!LoadOrCreateTransportIdentity(cfg.data_dir, &identity_key, &id_error)) {
      last_error_ = !id_error.empty() ? id_error : "failed to load transport identity";
      return false;
    }
  }
  const std::string peer_key_id_prehandshake = channel_.socket().PeerAddress();
  if (initiator_ && negotiated_mode_ == config::EncryptionMode::kPlaintext) {
    std::string pin_error;
    if (!EnforcePeerEncryptionHistory(cfg.data_dir, peer_key_id_prehandshake,
                                      /*negotiated_encryption=*/false, &pin_error)) {
      last_error_ = !pin_error.empty() ? pin_error : "encrypted transport downgrade rejected";
      return false;
    }
  }
  secure_channel_ = EncryptedChannel(std::move(channel_));
  const bool encryption = negotiated_mode_ == config::EncryptionMode::kEncrypted;
  TransportAuthContext auth_ctx;
  if (encryption) {
    auth_ctx.protocol_version = negotiated_protocol;
    auth_ctx.initiator_services =
        initiator_ ? local_version.services : remote_version_.services;
    auth_ctx.responder_services =
        initiator_ ? remote_version_.services : local_version.services;
    auth_ctx.initiator_preferred_mode =
        static_cast<std::uint8_t>(initiator_ ? local_version.preferred_mode
                                            : remote_version_.preferred_mode);
    auth_ctx.responder_preferred_mode =
        static_cast<std::uint8_t>(initiator_ ? remote_version_.preferred_mode
                                            : local_version.preferred_mode);
    auth_ctx.initiator_requires_encryption =
        initiator_ ? local_version.requires_encryption : remote_version_.requires_encryption;
    auth_ctx.responder_requires_encryption =
        initiator_ ? remote_version_.requires_encryption : local_version.requires_encryption;
    auth_ctx.identity_key = identity_key.get();
    auth_ctx.peer_identity_public_key = &peer_identity_public_key_;
  }
  if (!secure_channel_.PerformHandshake(initiator_, encryption,
                                        encryption ? &auth_ctx : nullptr)) {
    const std::string detail = secure_channel_.last_error();
    if (encryption) {
      last_error_ = detail.empty() ? "encrypted transport handshake failed"
                                   : ("encrypted transport handshake failed: " + detail);
    } else {
      last_error_ = detail.empty() ? "plaintext transport handshake failed"
                                   : ("plaintext transport handshake failed: " + detail);
    }
    return false;
  }

  if (encryption && cfg.authenticated_transport_required) {
    // For TOFU pinning, key by the concrete connected endpoint (IP:port) rather
    // than the dial target string (which may be a DNS name that resolves to
    // multiple backends with distinct identities).
    const std::string peer_key_id = secure_channel_.PeerAddress();

    if (initiator_ && !dial_target_.empty() && !cfg.static_seeds.empty()) {
      const std::string peer_host = ExtractHostForPin(dial_target_);
      const bool is_static_seed =
          std::find(cfg.static_seeds.begin(), cfg.static_seeds.end(), peer_host) != cfg.static_seeds.end();
      if (is_static_seed) {
        bool had_seed_pin = false;
        std::string seed_error;
        if (!EnforceSeedIdentityPin(cfg.data_dir, peer_key_id, peer_host, peer_identity_public_key_,
                                    &had_seed_pin, &seed_error)) {
          last_error_ = !seed_error.empty() ? seed_error : "seed identity key mismatch";
          return false;
        }
      }
    }

    // Only enforce peer identity pinning for outbound (initiated) connections.
    //
    // Rationale: For inbound connections the remote "endpoint identity" is
    // ambiguous in the presence of NAT (many peers can share one public IP).
    // Persistently pinning inbound identities keyed by source IP would make
    // those peers mutually incompatible and can lock entire NATs out of the
    // network after an identity key rotation/mismatch. Outbound pinning still
    // provides a meaningful TOFU security invariant because the user/operator
    // chooses the destination endpoint (DNS seed/static seed/manual addnode).
    const bool enforce_peer_pins =
        initiator_ && (!cfg.authenticated_transport_tofu || enforce_peer_identity_pinning_);
    if (enforce_peer_pins) {
      bool pinned_new = false;
      std::string pin_error;
      if (!EnforcePeerIdentityPin(cfg.data_dir, peer_key_id, peer_identity_public_key_,
                                  cfg.authenticated_transport_tofu, &pinned_new, &pin_error)) {
        last_error_ = !pin_error.empty() ? pin_error : "peer identity key mismatch";
        return false;
      }
    }
  }
  if (initiator_ && encryption) {
    std::string pin_error;
    if (!EnforcePeerEncryptionHistory(cfg.data_dir, secure_channel_.PeerAddress(),
                                      /*negotiated_encryption=*/true, &pin_error)) {
      last_error_ = !pin_error.empty() ? pin_error : "failed to persist encrypted transport pin";
      return false;
    }
  }
  // Clear the handshake timeout; higher-level idle timeouts handle quiet peers.
  secure_channel_.SetTimeout(0);
  return true;
}

bool PeerSession::Send(const messages::Message& message) {
  std::lock_guard<std::mutex> lock(send_mutex_);
  const bool ok = secure_channel_.Send(message);
  if (ok) {
    UpdateActivity();
  }
  return ok;
}

bool PeerSession::Receive(messages::Message* message) {
  const bool ok = secure_channel_.Receive(message);
  if (ok) {
    UpdateActivity();
  }
  return ok;
}

void PeerSession::Close() { secure_channel_.Close(); }

}  // namespace qryptcoin::net
