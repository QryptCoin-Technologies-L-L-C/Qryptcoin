#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "crypto/pq_engine.hpp"

namespace qryptcoin::net {

struct KyberHandshakePacket {
  std::vector<std::uint8_t> ciphertext;
  std::vector<std::uint8_t> initiator_secret;
};

class KyberSession {
 public:
  KyberSession() = default;

  KyberHandshakePacket Initiate(const crypto::QPqKyberKEM& responder_keypair);
  std::vector<std::uint8_t> Accept(const crypto::QPqKyberKEM& responder_keypair,
                                   std::span<const std::uint8_t> ciphertext);
  std::span<const std::uint8_t> SharedSecret() const { return shared_secret_; }

 private:
  std::vector<std::uint8_t> shared_secret_;
};

}  // namespace qryptcoin::net
