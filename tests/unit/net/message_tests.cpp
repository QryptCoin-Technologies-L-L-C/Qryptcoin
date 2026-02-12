#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>

#include "net/messages.hpp"
#include "net/channel.hpp"

int main() {
  using namespace qryptcoin::net::messages;
  InventoryMessage inv{};
  InventoryVector vec;
  vec.type = InventoryType::kBlock;
  vec.identifier.fill(0xAB);
  inv.entries.push_back(vec);
  auto encoded = EncodeInventory(inv);
  InventoryMessage decoded;
  if (!DecodeInventory(encoded, &decoded)) {
    std::cerr << "DecodeInventory failed\n";
    return EXIT_FAILURE;
  }
  if (decoded.entries.size() != 1 || decoded.entries[0].identifier != vec.identifier) {
    std::cerr << "Decoded inventory mismatch\n";
    return EXIT_FAILURE;
  }
  VersionMessage version_msg{};
  version_msg.protocol_version = kCurrentProtocolVersion;
  version_msg.services = 1;
  version_msg.timestamp = 123;
  version_msg.preferred_mode = qryptcoin::config::EncryptionMode::kEncrypted;
  version_msg.network_id = "katnet";
  version_msg.genesis_hash.fill(0x11);
  version_msg.session_nonce = 0x1122334455667788ULL;
  auto version = EncodeVersion(version_msg);
  VersionMessage parsed;
  if (!DecodeVersion(version, &parsed)) {
    std::cerr << "DecodeVersion failed\n";
    return EXIT_FAILURE;
  }
  if (parsed.protocol_version != kCurrentProtocolVersion || parsed.services != 1 ||
      parsed.timestamp != 123) {
    std::cerr << "Version mismatch\n";
    return EXIT_FAILURE;
  }
  if (parsed.network_id != version_msg.network_id || parsed.genesis_hash != version_msg.genesis_hash) {
    std::cerr << "Version network binding mismatch\n";
    return EXIT_FAILURE;
  }
  if (parsed.session_nonce != version_msg.session_nonce) {
    std::cerr << "Version session nonce mismatch\n";
    return EXIT_FAILURE;
  }

  // Backward compatibility: old version payloads omit session_nonce.
  Message legacy_version = version;
  if (legacy_version.payload.size() < sizeof(std::uint64_t)) {
    std::cerr << "Version payload unexpectedly short\n";
    return EXIT_FAILURE;
  }
  legacy_version.payload.resize(legacy_version.payload.size() - sizeof(std::uint64_t));
  VersionMessage legacy_parsed;
  if (!DecodeVersion(legacy_version, &legacy_parsed)) {
    std::cerr << "DecodeVersion failed for legacy payload\n";
    return EXIT_FAILURE;
  }
  if (legacy_parsed.session_nonce != 0) {
    std::cerr << "Legacy version payload should decode session nonce as zero\n";
    return EXIT_FAILURE;
  }

  // Encoding with nonce=0 must produce the same payload as the legacy
  // format (no trailing bytes) so older nodes with a strict offset==size
  // check in DecodeVersion can still parse the message.
  VersionMessage zero_nonce_msg = version_msg;
  zero_nonce_msg.session_nonce = 0;
  auto zero_nonce_encoded = EncodeVersion(zero_nonce_msg);
  if (zero_nonce_encoded.payload.size() != legacy_version.payload.size()) {
    std::cerr << "Encoding with nonce=0 should omit trailing nonce bytes\n";
    return EXIT_FAILURE;
  }
  if (!qryptcoin::net::FrameChannel::ValidatePayloadLength(
          qryptcoin::net::FrameChannel::kMaxFramePayload)) {
    std::cerr << "Max payload rejected unexpectedly\n";
    return EXIT_FAILURE;
  }
  if (qryptcoin::net::FrameChannel::ValidatePayloadLength(
          qryptcoin::net::FrameChannel::kMaxFramePayload + 1)) {
    std::cerr << "Oversized payload accepted\n";
    return EXIT_FAILURE;
  }
  std::array<std::uint8_t, 10> header{};
  const std::array<std::uint8_t, 4> message_start{{0x51, 0x51, 0x51, 0x51}};
  header[0] = message_start[0];
  header[1] = message_start[1];
  header[2] = message_start[2];
  header[3] = message_start[3];
  header[4] = 0x01;
  header[5] = 0x00;
  constexpr std::uint32_t kTestLength = 7;
  header[6] = static_cast<std::uint8_t>(kTestLength & 0xFF);
  header[7] = static_cast<std::uint8_t>((kTestLength >> 8) & 0xFF);
  header[8] = static_cast<std::uint8_t>((kTestLength >> 16) & 0xFF);
  header[9] = static_cast<std::uint8_t>((kTestLength >> 24) & 0xFF);
  std::uint32_t command = 0;
  std::uint32_t length = 0;
  if (!qryptcoin::net::TestDecodeFrameHeader(header, message_start, &command, &length) || command != 1 ||
      length != kTestLength) {
    std::cerr << "Header decode failed\n";
    return EXIT_FAILURE;
  }
  header[0] = 0x00;
  if (qryptcoin::net::TestDecodeFrameHeader(header, message_start, &command, &length)) {
    std::cerr << "Malformed header accepted\n";
    return EXIT_FAILURE;
  }

  // Round-trip a getheaders message to ensure locator encoding,
  // stop-hash, and max-headers fields are parsed correctly.
  GetHeadersMessage get_headers{};
  get_headers.max_headers = 2000;
  get_headers.locators.resize(3);
  for (std::size_t i = 0; i < get_headers.locators.size(); ++i) {
    get_headers.locators[i].fill(static_cast<std::uint8_t>(0x10 + i));
  }
  get_headers.stop_hash.fill(0xFF);
  auto encoded_getheaders = EncodeGetHeaders(get_headers);
  GetHeadersMessage decoded_getheaders{};
  if (!DecodeGetHeaders(encoded_getheaders, &decoded_getheaders)) {
    std::cerr << "DecodeGetHeaders failed\n";
    return EXIT_FAILURE;
  }
  if (decoded_getheaders.locators.size() != get_headers.locators.size() ||
      decoded_getheaders.max_headers != get_headers.max_headers ||
      decoded_getheaders.stop_hash != get_headers.stop_hash) {
    std::cerr << "Decoded getheaders mismatch\n";
    return EXIT_FAILURE;
  }

  // Round-trip a headers message with enough entries to exercise the
  // 0xFD (16-bit) varint encoding branch and confirm that each
  // header's core fields survive encode/decode intact.
  HeadersMessage headers_msg{};
  constexpr std::size_t kHeaderCount = 300;
  headers_msg.headers.resize(kHeaderCount);
  for (std::size_t i = 0; i < kHeaderCount; ++i) {
    auto& h = headers_msg.headers[i];
    h.version = 1;
    h.previous_block_hash.fill(static_cast<std::uint8_t>(i & 0xFFu));
    h.merkle_root.fill(static_cast<std::uint8_t>(0xA0u + (i & 0x0Fu)));
    h.timestamp = 1700000000u + static_cast<std::uint32_t>(i);
    h.difficulty_bits = 0x1d00ffffu;
    h.nonce = static_cast<std::uint32_t>(i);
  }
  auto encoded_headers = EncodeHeaders(headers_msg);
  HeadersMessage decoded_headers{};
  if (!DecodeHeaders(encoded_headers, &decoded_headers)) {
    std::cerr << "DecodeHeaders failed\n";
    return EXIT_FAILURE;
  }
  if (decoded_headers.headers.size() != kHeaderCount) {
    std::cerr << "Decoded headers count mismatch\n";
    return EXIT_FAILURE;
  }
  const auto& original0 = headers_msg.headers.front();
  const auto& roundtrip0 = decoded_headers.headers.front();
  if (original0.version != roundtrip0.version ||
      original0.previous_block_hash != roundtrip0.previous_block_hash ||
      original0.merkle_root != roundtrip0.merkle_root ||
      static_cast<std::uint32_t>(original0.timestamp) !=
          static_cast<std::uint32_t>(roundtrip0.timestamp) ||
      original0.difficulty_bits != roundtrip0.difficulty_bits ||
      original0.nonce != roundtrip0.nonce) {
    std::cerr << "Decoded header fields mismatch\n";
    return EXIT_FAILURE;
  }

  TxCommitmentMessage commit_msg{};
  commit_msg.commitment.fill(0x42);
  const auto encoded_commit = EncodeTxCommitment(commit_msg);
  TxCommitmentMessage decoded_commit{};
  if (!DecodeTxCommitment(encoded_commit, &decoded_commit)) {
    std::cerr << "DecodeTxCommitment failed\n";
    return EXIT_FAILURE;
  }
  if (decoded_commit.commitment != commit_msg.commitment) {
    std::cerr << "Decoded commitment mismatch\n";
    return EXIT_FAILURE;
  }

  // Round-trip GETADDR (empty payload).
  {
    auto getaddr = EncodeGetAddr();
    if (!IsGetAddr(getaddr)) {
      std::cerr << "IsGetAddr failed for valid GETADDR\n";
      return EXIT_FAILURE;
    }
    Message fake_getaddr{Command::kGetAddr, {0x01}};
    if (IsGetAddr(fake_getaddr)) {
      std::cerr << "IsGetAddr accepted non-empty payload\n";
      return EXIT_FAILURE;
    }
  }

  // Round-trip ADDR with multiple entries.
  {
    AddrMessage addr_msg{};
    addr_msg.entries.push_back({"203.0.113.1", 9375});
    addr_msg.entries.push_back({"198.51.100.2", 18750});
    addr_msg.entries.push_back({"10.0.0.1", 1});
    auto encoded_addr = EncodeAddr(addr_msg);
    AddrMessage decoded_addr{};
    if (!DecodeAddr(encoded_addr, &decoded_addr)) {
      std::cerr << "DecodeAddr failed\n";
      return EXIT_FAILURE;
    }
    if (decoded_addr.entries.size() != 3) {
      std::cerr << "DecodeAddr entry count mismatch\n";
      return EXIT_FAILURE;
    }
    for (std::size_t i = 0; i < addr_msg.entries.size(); ++i) {
      if (decoded_addr.entries[i].host != addr_msg.entries[i].host ||
          decoded_addr.entries[i].port != addr_msg.entries[i].port) {
        std::cerr << "DecodeAddr entry " << i << " mismatch\n";
        return EXIT_FAILURE;
      }
    }
  }

  // DecodeAddr rejects payloads exceeding kMaxAddrEntries.
  {
    Message oversized{Command::kAddr, {}};
    // Encode a varint count of kMaxAddrEntries + 1 to trigger rejection.
    std::vector<std::uint8_t> payload;
    // Use 3-byte varint for 1001: 0xFD followed by little-endian uint16.
    const std::uint16_t big_count = static_cast<std::uint16_t>(kMaxAddrEntries + 1);
    payload.push_back(0xFD);
    payload.push_back(static_cast<std::uint8_t>(big_count & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((big_count >> 8) & 0xFF));
    oversized.payload = payload;
    AddrMessage oversized_decoded{};
    if (DecodeAddr(oversized, &oversized_decoded)) {
      std::cerr << "DecodeAddr accepted oversized count\n";
      return EXIT_FAILURE;
    }
  }

  // DecodeAddr rejects truncated payloads.
  {
    AddrMessage one_entry{};
    one_entry.entries.push_back({"1.2.3.4", 9375});
    auto encoded = EncodeAddr(one_entry);
    // Truncate one byte.
    encoded.payload.pop_back();
    AddrMessage truncated_decoded{};
    if (DecodeAddr(encoded, &truncated_decoded)) {
      std::cerr << "DecodeAddr accepted truncated payload\n";
      return EXIT_FAILURE;
    }
  }

  // DecodeAddr with empty entries.
  {
    AddrMessage empty_msg{};
    auto encoded_empty = EncodeAddr(empty_msg);
    AddrMessage decoded_empty{};
    if (!DecodeAddr(encoded_empty, &decoded_empty)) {
      std::cerr << "DecodeAddr failed for empty entries\n";
      return EXIT_FAILURE;
    }
    if (!decoded_empty.entries.empty()) {
      std::cerr << "DecodeAddr non-empty result for empty input\n";
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}
