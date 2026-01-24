#include "net/channel.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>

#include "config/network.hpp"

namespace qryptcoin::net {

namespace {

using Clock = std::chrono::steady_clock;
constexpr auto kRateWindow = std::chrono::seconds(1);
std::atomic<std::uint64_t> g_payload_too_large{0};

struct FrameHeader {
  std::array<std::uint8_t, 4> magic{};
  std::uint16_t command{0};
  std::uint32_t length{0};
};

void SerializeHeader(const FrameHeader& header, std::array<std::uint8_t, 10>* out) {
  std::copy(header.magic.begin(), header.magic.end(), out->begin());
  (*out)[4] = static_cast<std::uint8_t>(header.command & 0xFF);
  (*out)[5] = static_cast<std::uint8_t>((header.command >> 8) & 0xFF);
  (*out)[6] = static_cast<std::uint8_t>(header.length & 0xFF);
  (*out)[7] = static_cast<std::uint8_t>((header.length >> 8) & 0xFF);
  (*out)[8] = static_cast<std::uint8_t>((header.length >> 16) & 0xFF);
  (*out)[9] = static_cast<std::uint8_t>((header.length >> 24) & 0xFF);
}

bool ParseHeader(const std::array<std::uint8_t, 10>& data,
                 const std::array<std::uint8_t, 4>& expected_magic,
                 FrameHeader* header) {
  if (!std::equal(expected_magic.begin(), expected_magic.end(), data.begin())) {
    return false;
  }
  header->magic = expected_magic;
  header->command = data[4] | (data[5] << 8);
  header->length = data[6] | (data[7] << 8) | (data[8] << 16) | (data[9] << 24);
  return true;
}

}  // namespace

FrameChannel::FrameChannel()
    : message_start_(config::GetNetworkConfig().message_start),
      socket_(),
      send_window_start_(Clock::now()),
      recv_window_start_(Clock::now()) {}

FrameChannel::FrameChannel(TcpSocket socket)
    : message_start_(config::GetNetworkConfig().message_start),
      socket_(std::move(socket)),
      send_window_start_(Clock::now()),
      recv_window_start_(Clock::now()) {}

FrameChannel::FrameChannel(FrameChannel&& other) noexcept
    : message_start_(other.message_start_),
      socket_(std::move(other.socket_)),
      last_error_(std::move(other.last_error_)),
      frames_sent_(other.frames_sent_),
      frames_received_(other.frames_received_),
      send_window_start_(other.send_window_start_),
      recv_window_start_(other.recv_window_start_) {}

FrameChannel& FrameChannel::operator=(FrameChannel&& other) noexcept {
  if (this != &other) {
    message_start_ = other.message_start_;
    socket_ = std::move(other.socket_);
    last_error_ = std::move(other.last_error_);
    frames_sent_ = other.frames_sent_;
    frames_received_ = other.frames_received_;
    send_window_start_ = other.send_window_start_;
    recv_window_start_ = other.recv_window_start_;
  }
  return *this;
}

FrameChannel::~FrameChannel() = default;

bool FrameChannel::Connect(const std::string& host, std::uint16_t port) {
  return socket_.Connect(host, port);
}

bool FrameChannel::ConnectViaProxy(const std::string& proxy_host, std::uint16_t proxy_port,
                                   const std::string& dest_host, std::uint16_t dest_port) {
  return socket_.ConnectViaSocks5(proxy_host, proxy_port, dest_host, dest_port);
}

bool FrameChannel::BindAndListen(const std::string& address, std::uint16_t port, int backlog) {
  return socket_.BindAndListen(address, port, backlog);
}

FrameChannel FrameChannel::Accept() const {
  FrameChannel inbound(socket_.Accept());
  inbound.SetMessageStart(message_start_);
  return inbound;
}

FrameChannel FrameChannel::AcceptWithTimeout(int timeout_ms) const {
  FrameChannel inbound(socket_.AcceptWithTimeout(timeout_ms));
  inbound.SetMessageStart(message_start_);
  return inbound;
}

void FrameChannel::SetMessageStart(std::array<std::uint8_t, 4> message_start) noexcept {
  message_start_ = message_start;
}

bool FrameChannel::Send(const messages::Message& message) {
  last_error_.clear();
  if (!IsValid()) return false;
  if (!ValidatePayloadLength(static_cast<std::uint32_t>(message.payload.size()))) {
    last_error_ = "payload too large";
    CloseChannel();
    return false;
  }
  if (!IncrementRateCounter(&frames_sent_, &send_window_start_)) {
    last_error_ = "send rate limit exceeded";
    CloseChannel();
    return false;
  }
  FrameHeader header{};
  header.magic = message_start_;
  header.command = static_cast<std::uint16_t>(message.command);
  header.length = static_cast<std::uint32_t>(message.payload.size());
  std::array<std::uint8_t, 10> serialized{};
  SerializeHeader(header, &serialized);
  if (!WriteAll(serialized.data(), serialized.size())) {
    return false;
  }
  if (!message.payload.empty()) {
    if (!WriteAll(message.payload.data(), message.payload.size())) {
      return false;
    }
  }
  return true;
}

bool FrameChannel::Receive(messages::Message* message) {
  last_error_.clear();
  if (!IsValid()) return false;
  std::array<std::uint8_t, 10> header_bytes{};
  if (!ReadAll(header_bytes.data(), header_bytes.size())) {
    return false;
  }
  FrameHeader header{};
  if (!ParseHeader(header_bytes, message_start_, &header)) {
    last_error_ = "invalid frame header (bad magic)";
    CloseChannel();
    return false;
  }
  if (!ValidatePayloadLength(header.length)) {
    last_error_ = "payload too large";
    CloseChannel();
    return false;
  }
  message->command = static_cast<messages::Command>(header.command);
  message->payload.resize(header.length);
  if (header.length > 0) {
    if (!ReadAll(message->payload.data(), header.length)) {
      return false;
    }
  }
  if (!IncrementRateCounter(&frames_received_, &recv_window_start_)) {
    last_error_ = "receive rate limit exceeded";
    CloseChannel();
    return false;
  }
  return true;
}

bool FrameChannel::IsValid() const noexcept { return socket_.IsValid(); }

bool FrameChannel::WriteAll(const std::uint8_t* data, std::size_t length) {
  std::size_t total = 0;
  while (total < length) {
    auto sent = socket_.Send(data + total, length - total);
    if (sent <= 0) {
      last_error_ = "socket write failed";
      CloseChannel();
      return false;
    }
    total += static_cast<std::size_t>(sent);
  }
  return true;
}

bool FrameChannel::ReadAll(std::uint8_t* data, std::size_t length) {
  std::size_t total = 0;
  while (total < length) {
    auto received = socket_.Recv(data + total, length - total);
    if (received == 0) {
      last_error_ = "peer closed connection";
      CloseChannel();
      return false;
    }
    if (received < 0) {
      last_error_ = "socket read failed";
      CloseChannel();
      return false;
    }
    total += static_cast<std::size_t>(received);
  }
  return true;
}

bool FrameChannel::ValidatePayloadLength(std::uint32_t length) {
  if (length > kMaxFramePayload) {
    g_payload_too_large.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
  return true;
}

FrameChannel::DropStats FrameChannel::GetDropStats() {
  DropStats stats;
  stats.payload_too_large = g_payload_too_large.load(std::memory_order_relaxed);
  return stats;
}

bool FrameChannel::IncrementRateCounter(std::size_t* counter,
                                        std::chrono::steady_clock::time_point* window_start) {
  const auto now = Clock::now();
  if (now - *window_start >= kRateWindow) {
    *window_start = now;
    *counter = 0;
  }
  ++(*counter);
  return *counter <= kMaxFramesPerSecond;
}

void FrameChannel::CloseChannel() { socket_.Close(); }

bool TestDecodeFrameHeader(const std::array<std::uint8_t, 10>& data,
                           const std::array<std::uint8_t, 4>& message_start,
                           std::uint32_t* command,
                           std::uint32_t* length) {
  FrameHeader header{};
  if (!ParseHeader(data, message_start, &header)) {
    return false;
  }
  if (command) *command = header.command;
  if (length) *length = header.length;
  return true;
}

}  // namespace qryptcoin::net
