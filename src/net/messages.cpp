#include "net/messages.hpp"

#include <array>
#include <chrono>
#include <cstring>

#include "crypto/pq_engine.hpp"
#include "primitives/serialize.hpp"

namespace qryptcoin::net::messages {

namespace {

void WriteUint32(std::vector<std::uint8_t>* out, std::uint32_t value) {
  out->push_back(static_cast<std::uint8_t>(value & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

void WriteUint64(std::vector<std::uint8_t>* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out->push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
  }
}

std::uint32_t ReadUint32(const std::uint8_t* data) {
  return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

std::uint64_t ReadUint64(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
  }
  return value;
}

void WriteVarInt(std::vector<std::uint8_t>* out, std::uint64_t value) {
  primitives::serialize::WriteVarInt(out, value);
}

bool ReadVarInt(const std::vector<std::uint8_t>& data, std::size_t* offset, std::uint64_t* value) {
  return primitives::serialize::ReadVarInt(data, offset, value);
}

bool EnsureAvailable(const std::vector<std::uint8_t>& data, std::size_t offset,
                     std::size_t required) {
  return offset + required <= data.size();
}

}  // namespace

Message EncodeVersion(const VersionMessage& msg) {
  Message message{Command::kVersion, {}};
  WriteUint32(&message.payload, msg.protocol_version);
  WriteUint64(&message.payload, msg.services);
  WriteUint64(&message.payload, msg.timestamp);
  message.payload.push_back(static_cast<std::uint8_t>(msg.preferred_mode));
  message.payload.push_back(static_cast<std::uint8_t>(msg.requires_encryption ? 1 : 0));
  WriteVarInt(&message.payload, msg.network_id.size());
  message.payload.insert(message.payload.end(), msg.network_id.begin(), msg.network_id.end());
  message.payload.insert(message.payload.end(), msg.genesis_hash.begin(), msg.genesis_hash.end());
  // Only append session_nonce when non-zero. Older nodes have a strict
  // offset==size check at the end of DecodeVersion and will reject any
  // message with unexpected trailing bytes. Omitting the nonce when it
  // is zero keeps the payload identical to the pre-nonce format so
  // existing deployments continue to interoperate. Once the entire
  // network is running code that tolerates the trailing field, the
  // nonce can be sent unconditionally.
  if (msg.session_nonce != 0) {
    WriteUint64(&message.payload, msg.session_nonce);
  }
  return message;
}

bool DecodeVersion(const Message& msg, VersionMessage* out) {
  constexpr std::size_t kBaseSize = 4 + 8 + 8 + 1 + 1;
  constexpr std::size_t kGenesisSize = primitives::Hash256{}.size();
  constexpr std::uint64_t kMaxNetworkIdLength = 64;
  if (msg.command != Command::kVersion || msg.payload.size() < kBaseSize) {
    return false;
  }
  const auto* data = msg.payload.data();
  out->protocol_version = ReadUint32(data);
  out->services = ReadUint64(data + 4);
  out->timestamp = ReadUint64(data + 12);
  const std::uint8_t mode = msg.payload[20];
  if (mode > static_cast<std::uint8_t>(config::EncryptionMode::kPlaintext)) {
    return false;
  }
  out->preferred_mode = static_cast<config::EncryptionMode>(mode);
  const std::uint8_t requires_flag = msg.payload[21];
  if (requires_flag > 1) {
    return false;
  }
  out->requires_encryption = requires_flag != 0;
  out->network_id.clear();
  out->genesis_hash.fill(0);
  out->session_nonce = 0;
  if (out->protocol_version < kMinProtocolVersion) {
    return false;
  }
  std::size_t offset = kBaseSize;
  std::uint64_t network_len = 0;
  if (!ReadVarInt(msg.payload, &offset, &network_len)) {
    return false;
  }
  if (network_len > kMaxNetworkIdLength) {
    return false;
  }
  if (!EnsureAvailable(msg.payload, offset, static_cast<std::size_t>(network_len) + kGenesisSize)) {
    return false;
  }
  out->network_id.assign(reinterpret_cast<const char*>(&msg.payload[offset]),
                         static_cast<std::size_t>(network_len));
  offset += static_cast<std::size_t>(network_len);
  std::copy_n(msg.payload.begin() + offset, out->genesis_hash.size(), out->genesis_hash.begin());
  offset += out->genesis_hash.size();
  if (offset == msg.payload.size()) {
    return true;
  }
  if (!EnsureAvailable(msg.payload, offset, sizeof(std::uint64_t))) {
    return false;
  }
  out->session_nonce = ReadUint64(msg.payload.data() + offset);
  offset += sizeof(std::uint64_t);
  return offset == msg.payload.size();
}

Message EncodeVerAck() { return Message{Command::kVerAck, {}}; }

bool IsVerAck(const Message& msg) { return msg.command == Command::kVerAck; }

Message EncodeInventory(const InventoryMessage& inv) {
  Message message{Command::kInventory, {}};
  WriteVarInt(&message.payload, inv.entries.size());
  for (const auto& entry : inv.entries) {
    WriteUint32(&message.payload, static_cast<std::uint32_t>(entry.type));
    message.payload.insert(message.payload.end(), entry.identifier.begin(), entry.identifier.end());
  }
  return message;
}

bool DecodeInventory(const Message& msg, InventoryMessage* out) {
  if (msg.command != Command::kInventory) return false;
  std::size_t offset = 0;
  std::uint64_t count = 0;
  if (!ReadVarInt(msg.payload, &offset, &count)) return false;
  constexpr std::size_t kInventoryEntrySize =
      sizeof(std::uint32_t) + crypto::Sha3_256Hash{}.size();
  if (offset > msg.payload.size()) {
    return false;
  }
  const std::size_t remaining = msg.payload.size() - offset;
  const std::size_t max_by_bytes = remaining / kInventoryEntrySize;
  if (count > kMaxInventoryEntries || count > max_by_bytes) {
    return false;
  }
  out->entries.clear();
  out->entries.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t i = 0; i < count; ++i) {
    if (offset + 4 + crypto::Sha3_256Hash{}.size() > msg.payload.size()) return false;
    InventoryVector vec;
    const auto raw_type = ReadUint32(&msg.payload[offset]);
    if (raw_type != static_cast<std::uint32_t>(InventoryType::kTransaction) &&
        raw_type != static_cast<std::uint32_t>(InventoryType::kBlock)) {
      return false;
    }
    vec.type = static_cast<InventoryType>(raw_type);
    offset += 4;
    std::copy_n(msg.payload.begin() + offset, vec.identifier.size(), vec.identifier.begin());
    offset += vec.identifier.size();
    out->entries.push_back(vec);
  }
  return offset == msg.payload.size();
}

Message EncodeGetData(const InventoryMessage& msg) {
  Message message{Command::kGetData, {}};
  WriteVarInt(&message.payload, msg.entries.size());
  for (const auto& entry : msg.entries) {
    WriteUint32(&message.payload, static_cast<std::uint32_t>(entry.type));
    message.payload.insert(message.payload.end(), entry.identifier.begin(), entry.identifier.end());
  }
  return message;
}

bool DecodeGetData(const Message& msg, InventoryMessage* out) {
  if (msg.command != Command::kGetData) return false;
  std::size_t offset = 0;
  std::uint64_t count = 0;
  if (!ReadVarInt(msg.payload, &offset, &count)) return false;
  constexpr std::size_t kGetDataEntrySize =
      sizeof(std::uint32_t) + crypto::Sha3_256Hash{}.size();
  if (offset > msg.payload.size()) {
    return false;
  }
  const std::size_t remaining = msg.payload.size() - offset;
  const std::size_t max_by_bytes = remaining / kGetDataEntrySize;
  if (count > kMaxGetDataEntries || count > max_by_bytes) {
    return false;
  }
  out->entries.clear();
  out->entries.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t i = 0; i < count; ++i) {
    if (!EnsureAvailable(msg.payload, offset,
                         sizeof(std::uint32_t) + crypto::Sha3_256Hash{}.size())) {
      return false;
    }
    InventoryVector vec;
    const auto raw_type = ReadUint32(&msg.payload[offset]);
    if (raw_type != static_cast<std::uint32_t>(InventoryType::kTransaction) &&
        raw_type != static_cast<std::uint32_t>(InventoryType::kBlock)) {
      return false;
    }
    vec.type = static_cast<InventoryType>(raw_type);
    offset += 4;
    std::copy_n(msg.payload.begin() + offset, vec.identifier.size(), vec.identifier.begin());
    offset += vec.identifier.size();
    out->entries.push_back(vec);
  }
  return offset == msg.payload.size();
}

Message EncodePing(const PingMessage& msg) {
  Message message{Command::kPing, {}};
  WriteUint64(&message.payload, msg.nonce);
  return message;
}

bool DecodePing(const Message& msg, PingMessage* out) {
  if (msg.command != Command::kPing || msg.payload.size() != 8) return false;
  out->nonce = ReadUint64(msg.payload.data());
  return true;
}

Message EncodePong(const PongMessage& msg) {
  Message message{Command::kPong, {}};
  WriteUint64(&message.payload, msg.nonce);
  return message;
}

bool DecodePong(const Message& msg, PongMessage* out) {
  if (msg.command != Command::kPong || msg.payload.size() != 8) return false;
  out->nonce = ReadUint64(msg.payload.data());
  return true;
}

Message EncodeTransaction(const TransactionMessage& msg) {
  Message message{Command::kTransaction, msg.data};
  return message;
}

Message EncodeBlock(const BlockMessage& msg) {
  Message message{Command::kBlock, msg.data};
  return message;
}

Message EncodeGetHeaders(const GetHeadersMessage& msg) {
  Message message{Command::kGetHeaders, {}};
  WriteVarInt(&message.payload, msg.locators.size());
  for (const auto& hash : msg.locators) {
    message.payload.insert(message.payload.end(), hash.begin(), hash.end());
  }
  message.payload.insert(message.payload.end(), msg.stop_hash.begin(), msg.stop_hash.end());
  WriteUint32(&message.payload, msg.max_headers);
  return message;
}

bool DecodeGetHeaders(const Message& msg, GetHeadersMessage* out) {
  if (msg.command != Command::kGetHeaders) return false;
  std::size_t offset = 0;
  std::uint64_t count = 0;
  if (!ReadVarInt(msg.payload, &offset, &count)) return false;
  constexpr std::size_t kHashSize = primitives::Hash256{}.size();
  constexpr std::size_t kTrailerSize = kHashSize + sizeof(std::uint32_t);
  if (offset > msg.payload.size()) {
    return false;
  }
  const std::size_t remaining = msg.payload.size() - offset;
  if (remaining < kTrailerSize) {
    return false;
  }
  const std::size_t remaining_for_locators = remaining - kTrailerSize;
  const std::size_t max_by_bytes = remaining_for_locators / kHashSize;
  if (count > kMaxLocatorHashes || count > max_by_bytes) {
    return false;
  }
  out->locators.clear();
  out->locators.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t i = 0; i < count; ++i) {
    if (!EnsureAvailable(msg.payload, offset, primitives::Hash256{}.size())) {
      return false;
    }
    primitives::Hash256 hash{};
    std::copy_n(msg.payload.begin() + offset, hash.size(), hash.begin());
    offset += hash.size();
    out->locators.push_back(hash);
  }
  if (!EnsureAvailable(msg.payload, offset, primitives::Hash256{}.size() + sizeof(std::uint32_t))) {
    return false;
  }
  std::copy_n(msg.payload.begin() + offset, out->stop_hash.size(), out->stop_hash.begin());
  offset += out->stop_hash.size();
  out->max_headers = ReadUint32(&msg.payload[offset]);
  if (out->max_headers > kMaxHeadersResults) {
    out->max_headers = static_cast<std::uint32_t>(kMaxHeadersResults);
  }
  offset += sizeof(std::uint32_t);
  return offset == msg.payload.size();
}

Message EncodeHeaders(const HeadersMessage& msg) {
  Message message{Command::kHeaders, {}};
  WriteVarInt(&message.payload, msg.headers.size());
  for (const auto& header : msg.headers) {
    primitives::serialize::SerializeBlockHeader(header, &message.payload);
  }
  return message;
}

bool DecodeHeaders(const Message& msg, HeadersMessage* out) {
  if (msg.command != Command::kHeaders) return false;
  std::size_t offset = 0;
  std::uint64_t count = 0;
  if (!ReadVarInt(msg.payload, &offset, &count)) return false;
  if (offset > msg.payload.size()) {
    return false;
  }
  constexpr std::size_t kHeaderSize = 80;
  const std::size_t remaining = msg.payload.size() - offset;
  const std::size_t max_by_bytes = remaining / kHeaderSize;
  if (count > kMaxHeadersResults || count > max_by_bytes) {
    return false;
  }
  out->headers.clear();
  out->headers.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t i = 0; i < count; ++i) {
    primitives::CBlockHeader header{};
    if (!primitives::serialize::DeserializeBlockHeader(msg.payload, &offset, &header)) {
      return false;
    }
    out->headers.push_back(header);
  }
  return offset == msg.payload.size();
}

Message EncodeHandshakeInit(const HandshakeInit& init) {
  Message message{Command::kHandshakeInit, {}};
  message.payload.reserve(init.kyber_public_key.size() + init.identity_public_key.size());
  message.payload.insert(message.payload.end(),
                         init.kyber_public_key.begin(),
                         init.kyber_public_key.end());
  message.payload.insert(message.payload.end(),
                         init.identity_public_key.begin(),
                         init.identity_public_key.end());
  return message;
}

bool DecodeHandshakeInit(const Message& msg, HandshakeInit* out) {
  if (msg.command != Command::kHandshakeInit) return false;
  const std::size_t kyber_pk = crypto::KyberPublicKeySize();
  const std::size_t dil_pk = crypto::DilithiumPublicKeySize();
  if (msg.payload.size() != kyber_pk + dil_pk) {
    return false;
  }
  out->kyber_public_key.assign(msg.payload.begin(),
                               msg.payload.begin() + static_cast<std::ptrdiff_t>(kyber_pk));
  out->identity_public_key.assign(msg.payload.begin() + static_cast<std::ptrdiff_t>(kyber_pk),
                                  msg.payload.end());
  return true;
}

Message EncodeHandshakeResponse(const HandshakeResponse& resp) {
  Message message{Command::kHandshakeResponse, {}};
  message.payload.reserve(resp.kyber_ciphertext.size() + resp.identity_public_key.size() +
                          resp.signature.size());
  message.payload.insert(message.payload.end(),
                         resp.kyber_ciphertext.begin(),
                         resp.kyber_ciphertext.end());
  message.payload.insert(message.payload.end(),
                         resp.identity_public_key.begin(),
                         resp.identity_public_key.end());
  message.payload.insert(message.payload.end(),
                         resp.signature.begin(),
                         resp.signature.end());
  return message;
}

bool DecodeHandshakeResponse(const Message& msg, HandshakeResponse* out) {
  if (msg.command != Command::kHandshakeResponse) return false;
  const std::size_t kyber_ct = crypto::KyberCiphertextSize();
  const std::size_t dil_pk = crypto::DilithiumPublicKeySize();
  const std::size_t dil_sig = crypto::DilithiumSignatureSize();
  if (msg.payload.size() != kyber_ct + dil_pk + dil_sig) {
    return false;
  }
  out->kyber_ciphertext.assign(msg.payload.begin(),
                               msg.payload.begin() + static_cast<std::ptrdiff_t>(kyber_ct));
  auto off = msg.payload.begin() + static_cast<std::ptrdiff_t>(kyber_ct);
  out->identity_public_key.assign(off, off + static_cast<std::ptrdiff_t>(dil_pk));
  off += static_cast<std::ptrdiff_t>(dil_pk);
  out->signature.assign(off, msg.payload.end());
  return true;
}

Message EncodeHandshakeFinalize(const HandshakeFinalize& fin) {
  Message message{Command::kHandshakeFinalize, fin.signature};
  return message;
}

bool DecodeHandshakeFinalize(const Message& msg, HandshakeFinalize* out) {
  if (msg.command != Command::kHandshakeFinalize) return false;
  const std::size_t dil_sig = crypto::DilithiumSignatureSize();
  if (msg.payload.size() != dil_sig) {
    return false;
  }
  out->signature = msg.payload;
  return true;
}

Message EncodeHandshakeFinished(const HandshakeFinished& fin) {
  Message message{Command::kHandshakeFinished, {}};
  message.payload.assign(fin.verify.begin(), fin.verify.end());
  return message;
}

bool DecodeHandshakeFinished(const Message& msg, HandshakeFinished* out) {
  if (msg.command != Command::kHandshakeFinished) return false;
  if (msg.payload.size() != crypto::Sha3_256Hash{}.size()) {
    return false;
  }
  std::copy_n(msg.payload.begin(), out->verify.size(), out->verify.begin());
  return true;
}

Message EncodeTxCommitment(const TxCommitmentMessage& msg) {
  Message message{Command::kTxCommitment, {}};
  message.payload.assign(msg.commitment.begin(), msg.commitment.end());
  return message;
}

bool DecodeTxCommitment(const Message& msg, TxCommitmentMessage* out) {
  if (msg.command != Command::kTxCommitment) return false;
  if (msg.payload.size() != crypto::Sha3_256Hash{}.size()) {
    return false;
  }
  std::copy_n(msg.payload.begin(), out->commitment.size(), out->commitment.begin());
  return true;
}

}  // namespace qryptcoin::net::messages
