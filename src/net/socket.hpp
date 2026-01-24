#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace qryptcoin::net {

class TcpSocket {
 public:
  TcpSocket();
  explicit TcpSocket(std::intptr_t handle);
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;
  TcpSocket(TcpSocket&& other) noexcept;
  TcpSocket& operator=(TcpSocket&& other) noexcept;
  ~TcpSocket();

  bool Connect(const std::string& host, std::uint16_t port, bool quiet = false);
  // Connect via a SOCKS5 proxy. The proxy itself is reached at
  // (proxy_host, proxy_port); the TCP stream is then opened to the
  // final destination (dest_host, dest_port) using the CONNECT command.
  bool ConnectViaSocks5(const std::string& proxy_host, std::uint16_t proxy_port,
                        const std::string& dest_host, std::uint16_t dest_port);
  bool BindAndListen(const std::string& address, std::uint16_t port, int backlog = 8);
  TcpSocket Accept() const;
  TcpSocket AcceptWithTimeout(int timeout_ms) const;
  std::ptrdiff_t Send(const std::uint8_t* data, std::size_t length) const;
  std::ptrdiff_t Recv(std::uint8_t* data, std::size_t length) const;
  bool SetTimeout(int milliseconds);
  std::string PeerAddress() const;
  void Close();
  bool IsValid() const noexcept;

 private:
  std::intptr_t handle_{-1};
};

bool InitializeSockets();
void CleanupSockets();
std::vector<std::string> ResolveHostAddresses(const std::string& host);

}  // namespace qryptcoin::net
