#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "net/messages.hpp"
#include "net/socket.hpp"

namespace qryptcoin::net {

class FrameChannel {
 public:
  // Keep enough headroom for encrypted frames (nonce + tag + inner command)
  // so a max-sized 1 MiB block remains relayable when AEAD is enabled.
  static constexpr std::uint32_t kMaxFramePayload = 1 * 1024 * 1024 + 64;
  static constexpr std::size_t kMaxFramesPerSecond = 512;

  struct DropStats {
    std::uint64_t payload_too_large{0};
  };

  FrameChannel();
  explicit FrameChannel(TcpSocket socket);
  FrameChannel(const FrameChannel&) = delete;
  FrameChannel& operator=(const FrameChannel&) = delete;
  FrameChannel(FrameChannel&&) noexcept;
  FrameChannel& operator=(FrameChannel&&) noexcept;
  ~FrameChannel();

  bool Connect(const std::string& host, std::uint16_t port);
  bool ConnectViaProxy(const std::string& proxy_host, std::uint16_t proxy_port,
                       const std::string& dest_host, std::uint16_t dest_port);
  bool BindAndListen(const std::string& address, std::uint16_t port, int backlog = 8);
  FrameChannel Accept() const;
  FrameChannel AcceptWithTimeout(int timeout_ms) const;
  bool Send(const messages::Message& message);
  bool Receive(messages::Message* message);
  bool IsValid() const noexcept;
  void SetMessageStart(std::array<std::uint8_t, 4> message_start) noexcept;
  const std::array<std::uint8_t, 4>& message_start() const noexcept { return message_start_; }
  const std::string& last_error() const noexcept { return last_error_; }
  TcpSocket& socket() { return socket_; }
  const TcpSocket& socket() const { return socket_; }
  static bool ValidatePayloadLength(std::uint32_t length);
  static DropStats GetDropStats();

 private:
  bool IncrementRateCounter(std::size_t* counter,
                            std::chrono::steady_clock::time_point* window_start);
  void CloseChannel();
  bool WriteAll(const std::uint8_t* data, std::size_t length);
  bool ReadAll(std::uint8_t* data, std::size_t length);

  std::array<std::uint8_t, 4> message_start_{};
  TcpSocket socket_;
  std::string last_error_;
  std::size_t frames_sent_{0};
  std::size_t frames_received_{0};
  std::chrono::steady_clock::time_point send_window_start_;
  std::chrono::steady_clock::time_point recv_window_start_;
};

bool TestDecodeFrameHeader(const std::array<std::uint8_t, 10>& data,
                           const std::array<std::uint8_t, 4>& message_start,
                           std::uint32_t* command,
                           std::uint32_t* length);

}  // namespace qryptcoin::net
