#include "net/handshake.hpp"

namespace qryptcoin::net {

KyberHandshakePacket KyberSession::Initiate(const crypto::QPqKyberKEM& responder_keypair) {
  auto encapsulated = crypto::QPqKyberKEM::Encapsulate(responder_keypair.PublicKey());
  shared_secret_ = encapsulated.shared_secret;
  KyberHandshakePacket packet{};
  packet.ciphertext = std::move(encapsulated.ciphertext);
  packet.initiator_secret = shared_secret_;
  return packet;
}

std::vector<std::uint8_t> KyberSession::Accept(const crypto::QPqKyberKEM& responder_keypair,
                                               std::span<const std::uint8_t> ciphertext) {
  shared_secret_ = responder_keypair.Decapsulate(ciphertext);
  return shared_secret_;
}

}  // namespace qryptcoin::net

