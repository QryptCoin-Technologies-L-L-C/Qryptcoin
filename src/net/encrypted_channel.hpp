#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "crypto/pq_engine.hpp"
#include "net/channel.hpp"
#include "net/messages.hpp"
#include "util/aead.hpp"

namespace qryptcoin::net {

struct TransportAuthContext {
  std::uint32_t protocol_version{0};
  std::uint64_t initiator_services{0};
  std::uint64_t responder_services{0};
  std::uint8_t initiator_preferred_mode{0};
  std::uint8_t responder_preferred_mode{0};
  bool initiator_requires_encryption{false};
  bool responder_requires_encryption{false};
  const crypto::QPqDilithiumKey* identity_key{nullptr};
  // Optional output populated with the peer's identity public key when
  // authenticated transport is enabled.
  std::vector<std::uint8_t>* peer_identity_public_key{nullptr};
};

class EncryptedChannel {
 public:
  explicit EncryptedChannel(FrameChannel channel);

  bool PerformHandshake(bool initiator, bool enable_encryption,
                        const TransportAuthContext* auth = nullptr);
  bool Send(const messages::Message& message);
  bool Receive(messages::Message* message);
  bool SetTimeout(int milliseconds) { return channel_.socket().SetTimeout(milliseconds); }
  bool IsEncrypted() const noexcept { return encrypted_; }
  void Close();
  std::string PeerAddress() const { return channel_.socket().PeerAddress(); }
  const std::string& last_error() const noexcept { return last_error_; }

 private:
  bool SendPlain(const messages::Message& message);
  bool ReceivePlain(messages::Message* message);
  bool EncryptAndSend(const messages::Message& message);
  bool ReceiveAndDecrypt(messages::Message* message);
  bool InitiatorHandshake(const TransportAuthContext& auth);
  bool ResponderHandshake(const TransportAuthContext& auth);
  std::vector<std::uint8_t> DeriveKey(std::span<const std::uint8_t> secret,
                                      std::span<const std::uint8_t> transcript_hash,
                                      std::string_view info);

  FrameChannel channel_;
  bool encrypted_{false};
  std::string last_error_;
  std::array<std::uint8_t, util::kChaCha20Poly1305KeySize> send_key_{};
  std::array<std::uint8_t, util::kChaCha20Poly1305KeySize> recv_key_{};
  std::uint64_t send_counter_{0};
  std::uint64_t recv_counter_{0};
  crypto::QPqKyberKEM kyber_keypair_;
};

}  // namespace qryptcoin::net
