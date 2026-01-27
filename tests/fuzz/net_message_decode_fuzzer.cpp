#include <cstddef>
#include <cstdint>
#include <exception>
#include <vector>

#include "net/messages.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using namespace qryptcoin::net::messages;

  if (data == nullptr || size < 2) return 0;

  static constexpr Command kCommands[] = {
      Command::kVersion,          Command::kInventory,
      Command::kGetData,          Command::kPing,
      Command::kPong,             Command::kGetHeaders,
      Command::kHeaders,          Command::kHandshakeInit,
      Command::kHandshakeResponse, Command::kHandshakeFinalize,
      Command::kHandshakeFinished,
  };

  const Command cmd = kCommands[data[0] % (sizeof(kCommands) / sizeof(kCommands[0]))];

  Message msg;
  msg.command = cmd;
  msg.payload.assign(data + 1, data + size);

  // Catch allocation failures and parse errors - these are expected when
  // fuzzing malformed input and should not crash the harness.
  try {
    switch (cmd) {
      case Command::kVersion: {
        VersionMessage out;
        (void)DecodeVersion(msg, &out);
        break;
      }
      case Command::kInventory: {
        InventoryMessage out;
        (void)DecodeInventory(msg, &out);
        break;
      }
      case Command::kGetData: {
        InventoryMessage out;
        (void)DecodeGetData(msg, &out);
        break;
      }
      case Command::kPing: {
        PingMessage out;
        (void)DecodePing(msg, &out);
        break;
      }
      case Command::kPong: {
        PongMessage out;
        (void)DecodePong(msg, &out);
        break;
      }
      case Command::kGetHeaders: {
        GetHeadersMessage out;
        (void)DecodeGetHeaders(msg, &out);
        break;
      }
      case Command::kHeaders: {
        HeadersMessage out;
        (void)DecodeHeaders(msg, &out);
        break;
      }
      case Command::kHandshakeInit: {
        HandshakeInit out;
        (void)DecodeHandshakeInit(msg, &out);
        break;
      }
      case Command::kHandshakeResponse: {
        HandshakeResponse out;
        (void)DecodeHandshakeResponse(msg, &out);
        break;
      }
      case Command::kHandshakeFinalize: {
        HandshakeFinalize out;
        (void)DecodeHandshakeFinalize(msg, &out);
        break;
      }
      case Command::kHandshakeFinished: {
        HandshakeFinished out;
        (void)DecodeHandshakeFinished(msg, &out);
        break;
      }
      default:
        break;
    }
  } catch (const std::exception&) {
    // Expected for malformed input (std::length_error, std::bad_alloc, etc.)
  }

  return 0;
}

