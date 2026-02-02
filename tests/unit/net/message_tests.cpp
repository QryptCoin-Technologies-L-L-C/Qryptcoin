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

  return EXIT_SUCCESS;
}
