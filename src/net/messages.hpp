#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "config/network.hpp"
#include "crypto/hash.hpp"
#include "primitives/block.hpp"

namespace qryptcoin::net::messages {

// Network protocol version for peer handshakes. Version 3 binds peers to
// (network_id, genesis_hash). Version 4 adds authenticated encrypted
// transport (Dilithium-signed transcript bound to Kyber KEM outputs).
constexpr std::uint32_t kMinProtocolVersion = 5;
constexpr std::uint32_t kCurrentProtocolVersion = 5;

  // Protocol-level DoS limits. These caps are enforced during decode to
  // prevent attackers from advertising enormous varint counts that would
  // otherwise trigger unbounded allocations.
  constexpr std::size_t kMaxInventoryEntries = 50'000;
  constexpr std::size_t kMaxGetDataEntries = 50'000;
  constexpr std::size_t kMaxLocatorHashes = 64;
  constexpr std::size_t kMaxHeadersResults = 2000;

enum class Command : std::uint16_t {
  kVersion = 0x0001,
  kVerAck = 0x0002,
  kInventory = 0x0003,
  kTransaction = 0x0004,
  kBlock = 0x0005,
  kPing = 0x0006,
  kPong = 0x0007,
  kHandshakeInit = 0x0008,
  kHandshakeResponse = 0x0009,
  kHandshakeFinalize = 0x000A,
  kEncryptedFrame = 0x000B,
  kGetHeaders = 0x000C,
  kHeaders = 0x000D,
  kGetData = 0x000E,
  kHandshakeFinished = 0x000F,
};

struct Message {
  Command command;
  std::vector<std::uint8_t> payload;
};

struct VersionMessage {
  std::uint32_t protocol_version{kCurrentProtocolVersion};
  std::uint64_t services{1};
  std::uint64_t timestamp{0};
  config::EncryptionMode preferred_mode{config::EncryptionMode::kEncrypted};
  bool requires_encryption{false};
  std::string network_id;
  primitives::Hash256 genesis_hash{};
};

struct VerAckMessage {};

enum class InventoryType : std::uint32_t { kTransaction = 1, kBlock = 2 };

struct InventoryVector {
  InventoryType type{InventoryType::kTransaction};
  crypto::Sha3_256Hash identifier{};
};

struct InventoryMessage {
  std::vector<InventoryVector> entries;
};

struct PingMessage {
  std::uint64_t nonce{0};
};

using PongMessage = PingMessage;

struct TransactionMessage {
  std::vector<std::uint8_t> data;
};

struct BlockMessage {
  std::vector<std::uint8_t> data;
};

struct GetHeadersMessage {
  std::vector<primitives::Hash256> locators;
  primitives::Hash256 stop_hash{};
  std::uint32_t max_headers{2000};
};

struct HeadersMessage {
  std::vector<primitives::CBlockHeader> headers;
};

struct HandshakeInit {
  std::vector<std::uint8_t> kyber_public_key;
  std::vector<std::uint8_t> identity_public_key;
};

struct HandshakeResponse {
  std::vector<std::uint8_t> kyber_ciphertext;
  std::vector<std::uint8_t> identity_public_key;
  std::vector<std::uint8_t> signature;
};

struct HandshakeFinalize {
  std::vector<std::uint8_t> signature;
};

struct HandshakeFinished {
  crypto::Sha3_256Hash verify{};
};

Message EncodeVersion(const VersionMessage& msg);
bool DecodeVersion(const Message& msg, VersionMessage* out);
Message EncodeVerAck();
bool IsVerAck(const Message& msg);
Message EncodeInventory(const InventoryMessage& msg);
bool DecodeInventory(const Message& msg, InventoryMessage* out);
Message EncodeGetData(const InventoryMessage& msg);
bool DecodeGetData(const Message& msg, InventoryMessage* out);
Message EncodePing(const PingMessage& msg);
bool DecodePing(const Message& msg, PingMessage* out);
Message EncodePong(const PongMessage& msg);
bool DecodePong(const Message& msg, PongMessage* out);
Message EncodeTransaction(const TransactionMessage& msg);
Message EncodeBlock(const BlockMessage& msg);
Message EncodeGetHeaders(const GetHeadersMessage& msg);
bool DecodeGetHeaders(const Message& msg, GetHeadersMessage* out);
Message EncodeHeaders(const HeadersMessage& msg);
bool DecodeHeaders(const Message& msg, HeadersMessage* out);
Message EncodeHandshakeInit(const HandshakeInit& init);
bool DecodeHandshakeInit(const Message& msg, HandshakeInit* out);
Message EncodeHandshakeResponse(const HandshakeResponse& resp);
bool DecodeHandshakeResponse(const Message& msg, HandshakeResponse* out);
Message EncodeHandshakeFinalize(const HandshakeFinalize& fin);
bool DecodeHandshakeFinalize(const Message& msg, HandshakeFinalize* out);
Message EncodeHandshakeFinished(const HandshakeFinished& fin);
bool DecodeHandshakeFinished(const Message& msg, HandshakeFinished* out);

}  // namespace qryptcoin::net::messages
