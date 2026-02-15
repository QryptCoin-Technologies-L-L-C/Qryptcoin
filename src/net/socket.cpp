#include "net/socket.hpp"

#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <WS2tcpip.h>
#include <winsock2.h>
#include <mstcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif
using socket_handle = SOCKET;
constexpr socket_handle kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using socket_handle = int;
constexpr socket_handle kInvalidSocket = -1;
#endif

namespace qryptcoin::net {

namespace {

class WinsockInitializer {
 public:
  WinsockInitializer() {
#ifdef _WIN32
    WSADATA wsa_data{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
      throw std::runtime_error("WSAStartup failed");
    }
#endif
  }

  ~WinsockInitializer() {
#ifdef _WIN32
    WSACleanup();
#endif
  }
};

WinsockInitializer& GetInitializer() {
  static WinsockInitializer init{};
  return init;
}

socket_handle CreateSocket(int family) {
  return ::socket(family, SOCK_STREAM, IPPROTO_TCP);
}

void CloseHandle(socket_handle handle) {
#ifdef _WIN32
  if (handle != kInvalidSocket) {
    closesocket(handle);
  }
#else
  if (handle != kInvalidSocket) {
    close(handle);
  }
#endif
}

bool ConnectWithTimeout(socket_handle socket_fd, const sockaddr* addr, socklen_t addr_len,
                        int timeout_ms, bool quiet, const std::string& host,
                        std::uint16_t port) {
  if (socket_fd == kInvalidSocket || addr == nullptr) {
    return false;
  }

#ifdef _WIN32
  u_long nonblocking = 1;
  (void)::ioctlsocket(socket_fd, FIONBIO, &nonblocking);
#else
  const int original_flags = fcntl(socket_fd, F_GETFL, 0);
  if (original_flags >= 0) {
    (void)fcntl(socket_fd, F_SETFL, original_flags | O_NONBLOCK);
  }
#endif

  const int connect_rc = ::connect(socket_fd, addr, addr_len);
  if (connect_rc == 0) {
#ifdef _WIN32
    nonblocking = 0;
    (void)::ioctlsocket(socket_fd, FIONBIO, &nonblocking);
#else
    if (original_flags >= 0) {
      (void)fcntl(socket_fd, F_SETFL, original_flags);
    }
#endif
    return true;
  }

  bool in_progress = false;
#ifdef _WIN32
  const int connect_err = WSAGetLastError();
  in_progress = (connect_err == WSAEWOULDBLOCK || connect_err == WSAEINPROGRESS);
#else
  const int connect_err = errno;
  in_progress = (connect_err == EINPROGRESS);
#endif

  if (!in_progress) {
#ifdef _WIN32
    nonblocking = 0;
    (void)::ioctlsocket(socket_fd, FIONBIO, &nonblocking);
    if (!quiet) {
      std::cerr << "[socket] connect(" << host << ":" << port << ") failed, WSA error "
                << connect_err << "\n";
    }
#else
    if (original_flags >= 0) {
      (void)fcntl(socket_fd, F_SETFL, original_flags);
    }
    if (!quiet) {
      std::cerr << "[socket] connect(" << host << ":" << port << ") failed, errno " << connect_err
                << "\n";
    }
#endif
    return false;
  }

  fd_set write_fds;
  FD_ZERO(&write_fds);
  FD_SET(socket_fd, &write_fds);
  timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
#ifdef _WIN32
  const int ready = ::select(0, nullptr, &write_fds, nullptr, &tv);
#else
  const int ready = ::select(socket_fd + 1, nullptr, &write_fds, nullptr, &tv);
#endif

  int so_error = 0;
#ifdef _WIN32
  int so_error_len = sizeof(so_error);
  const int so_rc = ::getsockopt(socket_fd, SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&so_error), &so_error_len);
  nonblocking = 0;
  (void)::ioctlsocket(socket_fd, FIONBIO, &nonblocking);
#else
  socklen_t so_error_len = sizeof(so_error);
  const int so_rc = ::getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len);
  if (original_flags >= 0) {
    (void)fcntl(socket_fd, F_SETFL, original_flags);
  }
#endif

  if (ready <= 0 || so_rc != 0 || so_error != 0) {
#ifdef _WIN32
    if (!quiet) {
      std::cerr << "[socket] connect(" << host << ":" << port
                << ") timed out or failed, WSA error " << (so_error != 0 ? so_error : connect_err)
                << "\n";
    }
#else
    if (!quiet) {
      std::cerr << "[socket] connect(" << host << ":" << port << ") timed out or failed, errno "
                << (so_error != 0 ? so_error : connect_err) << "\n";
    }
#endif
    return false;
  }
  return true;
}

}  // namespace

bool InitializeSockets() {
  try {
    GetInitializer();
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

void CleanupSockets() {}

std::vector<std::string> ResolveHostAddresses(const std::string& host) {
  InitializeSockets();
  std::vector<std::string> addresses;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) {
    if (result != nullptr) {
      freeaddrinfo(result);
    }
    return addresses;
  }
  std::unordered_set<std::string> seen;
  char hostbuf[NI_MAXHOST]{};
  for (auto* entry = result; entry != nullptr; entry = entry->ai_next) {
    std::memset(hostbuf, 0, sizeof(hostbuf));
    if (getnameinfo(entry->ai_addr, static_cast<socklen_t>(entry->ai_addrlen), hostbuf,
                    sizeof(hostbuf), nullptr, 0, NI_NUMERICHOST) != 0) {
      continue;
    }
    std::string ip(hostbuf);
    if (ip.empty()) continue;
    if (seen.insert(ip).second) {
      addresses.emplace_back(std::move(ip));
    }
  }
  freeaddrinfo(result);
  return addresses;
}

TcpSocket::TcpSocket() {
  InitializeSockets();
  handle_ = static_cast<std::intptr_t>(kInvalidSocket);
}

TcpSocket::TcpSocket(std::intptr_t handle) : handle_(handle) { InitializeSockets(); }

TcpSocket::TcpSocket(TcpSocket&& other) noexcept { handle_ = other.handle_; other.handle_ = kInvalidSocket; }

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
  if (this != &other) {
    Close();
    handle_ = other.handle_;
    other.handle_ = kInvalidSocket;
  }
  return *this;
}

TcpSocket::~TcpSocket() { Close(); }

bool TcpSocket::Connect(const std::string& host, std::uint16_t port, bool quiet) {
  constexpr int kConnectTimeoutMs = 5000;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* result = nullptr;
  const std::string port_str = std::to_string(port);
  if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0 || result == nullptr) {
    if (!quiet) {
      std::cerr << "[socket] Resolve(" << host << ":" << port << ") failed\n";
    }
    if (result) {
      freeaddrinfo(result);
    }
    return false;
  }

  for (auto* entry = result; entry != nullptr; entry = entry->ai_next) {
    socket_handle sock = CreateSocket(entry->ai_family);
    if (sock == kInvalidSocket) {
      continue;
    }
    if (ConnectWithTimeout(sock, entry->ai_addr, static_cast<socklen_t>(entry->ai_addrlen),
                           kConnectTimeoutMs, quiet, host, port)) {
      Close();
      handle_ = static_cast<std::intptr_t>(sock);
      EnableKeepAlive();
      freeaddrinfo(result);
      return true;
    }
    CloseHandle(sock);
  }

  freeaddrinfo(result);
  return false;
}

bool TcpSocket::ConnectViaSocks5(const std::string& proxy_host, std::uint16_t proxy_port,
                                 const std::string& dest_host, std::uint16_t dest_port) {
  // Establish a TCP connection to the proxy itself first.
  if (!Connect(proxy_host, proxy_port)) {
    return false;
  }

  // SOCKS5 greeting: no authentication, single method.
  std::uint8_t greeting[3] = {0x05, 0x01, 0x00};
  if (Send(greeting, sizeof(greeting)) != static_cast<std::ptrdiff_t>(sizeof(greeting))) {
    return false;
  }
  std::uint8_t greeting_reply[2] = {0};
  if (Recv(greeting_reply, sizeof(greeting_reply)) !=
      static_cast<std::ptrdiff_t>(sizeof(greeting_reply))) {
    return false;
  }
  if (greeting_reply[0] != 0x05 || greeting_reply[1] != 0x00) {
    return false;
  }

  // Build CONNECT request with domain-name address type so Tor/I2P
  // style hostnames (e.g. .onion) work transparently.
  const std::uint8_t addr_type = 0x03;  // domain name
  const std::uint8_t host_len =
      static_cast<std::uint8_t>(std::min<std::size_t>(dest_host.size(), 255));
  std::vector<std::uint8_t> request;
  request.reserve(4 + 1 + host_len + 2);
  request.push_back(0x05);           // version
  request.push_back(0x01);           // CONNECT
  request.push_back(0x00);           // reserved
  request.push_back(addr_type);      // atyp = domain name
  request.push_back(host_len);       // length of host
  request.insert(request.end(), dest_host.begin(), dest_host.begin() + host_len);
  request.push_back(static_cast<std::uint8_t>((dest_port >> 8) & 0xFF));
  request.push_back(static_cast<std::uint8_t>(dest_port & 0xFF));

  if (Send(request.data(), request.size()) !=
      static_cast<std::ptrdiff_t>(request.size())) {
    return false;
  }

  // Read the fixed header of the reply (version, reply code, rsv, atyp).
  std::uint8_t reply_hdr[4] = {0};
  if (Recv(reply_hdr, sizeof(reply_hdr)) !=
      static_cast<std::ptrdiff_t>(sizeof(reply_hdr))) {
    return false;
  }
  if (reply_hdr[0] != 0x05 || reply_hdr[1] != 0x00) {
    return false;
  }

  // Consume the bound address described in the reply so that the
  // stream is positioned for application data. The exact value is not
  // needed for our purposes.
  std::size_t to_read = 0;
  switch (reply_hdr[3]) {
    case 0x01:  // IPv4
      to_read = 4 + 2;
      break;
    case 0x03: {  // domain
      std::uint8_t len = 0;
      if (Recv(&len, 1) != 1) return false;
      to_read = static_cast<std::size_t>(len) + 2;
      break;
    }
    case 0x04:  // IPv6
      to_read = 16 + 2;
      break;
    default:
      return false;
  }
  std::vector<std::uint8_t> discard(to_read);
  if (to_read > 0 &&
      Recv(discard.data(), discard.size()) !=
          static_cast<std::ptrdiff_t>(discard.size())) {
    return false;
  }

  return true;
}

bool TcpSocket::BindAndListen(const std::string& address, std::uint16_t port, int backlog) {
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  const bool wants_v4_any = address.empty() || address == "0.0.0.0";
  const bool wants_v6_any = address == "::";
  if (wants_v4_any) {
    hints.ai_family = AF_INET;
  } else if (wants_v6_any) {
    hints.ai_family = AF_INET6;
  } else {
    hints.ai_family = AF_UNSPEC;
  }

  addrinfo* result = nullptr;
  const std::string port_str = std::to_string(port);
  const char* node = (wants_v4_any || wants_v6_any) ? nullptr : address.c_str();
  if (getaddrinfo(node, port_str.c_str(), &hints, &result) != 0 || result == nullptr) {
    if (result) {
      freeaddrinfo(result);
    }
    return false;
  }

  for (auto* entry = result; entry != nullptr; entry = entry->ai_next) {
    socket_handle sock = CreateSocket(entry->ai_family);
    if (sock == kInvalidSocket) {
      continue;
    }
    int opt = 1;
#ifdef _WIN32
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    if (entry->ai_family == AF_INET6) {
      // Prefer dual-stack when possible so "::" can accept both IPv6 and IPv4-mapped
      // connections on platforms that support it.
      int v6only = 0;
#ifdef _WIN32
      (void)setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only),
                       sizeof(v6only));
#else
      (void)setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
#endif
    }
    if (::bind(sock, entry->ai_addr, static_cast<socklen_t>(entry->ai_addrlen)) != 0) {
      CloseHandle(sock);
      continue;
    }
    if (::listen(sock, backlog) != 0) {
      CloseHandle(sock);
      continue;
    }
    Close();
    handle_ = static_cast<std::intptr_t>(sock);
    freeaddrinfo(result);
    return true;
  }

  freeaddrinfo(result);
  return false;
}

TcpSocket TcpSocket::Accept() const {
  if (!IsValid()) return TcpSocket(kInvalidSocket);
  socket_handle client = ::accept(handle_, nullptr, nullptr);
  if (client == kInvalidSocket) {
    return TcpSocket(kInvalidSocket);
  }
  TcpSocket peer(client);
  peer.EnableKeepAlive();
  return peer;
}

TcpSocket TcpSocket::AcceptWithTimeout(int timeout_ms) const {
  if (timeout_ms < 0) {
    return Accept();
  }
  if (!IsValid()) return TcpSocket(kInvalidSocket);
  fd_set read_fds;
  FD_ZERO(&read_fds);
  socket_handle socket_fd = static_cast<socket_handle>(handle_);
  FD_SET(socket_fd, &read_fds);

  timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
#ifdef _WIN32
  const int ready = ::select(0, &read_fds, nullptr, nullptr, &tv);
#else
  const int ready = ::select(static_cast<int>(socket_fd + 1), &read_fds, nullptr, nullptr, &tv);
#endif
  if (ready <= 0) {
    return TcpSocket(kInvalidSocket);
  }
  socket_handle client = ::accept(handle_, nullptr, nullptr);
  if (client == kInvalidSocket) {
    return TcpSocket(kInvalidSocket);
  }
  TcpSocket peer(client);
  peer.EnableKeepAlive();
  return peer;
}

std::ptrdiff_t TcpSocket::Send(const std::uint8_t* data, std::size_t length) const {
  if (!IsValid()) return -1;
#ifdef _WIN32
  return ::send(handle_, reinterpret_cast<const char*>(data), static_cast<int>(length), 0);
#else
  return ::send(handle_, data, length, 0);
#endif
}

std::ptrdiff_t TcpSocket::Recv(std::uint8_t* data, std::size_t length) const {
  if (!IsValid()) return -1;
#ifdef _WIN32
  return ::recv(handle_, reinterpret_cast<char*>(data), static_cast<int>(length), 0);
#else
  return ::recv(handle_, data, length, 0);
#endif
}

bool TcpSocket::SetTimeout(int milliseconds) {
  if (!IsValid()) return false;
#ifdef _WIN32
  DWORD timeout = static_cast<DWORD>(milliseconds);
  return ::setsockopt(handle_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
                      sizeof(timeout)) == 0 &&
         ::setsockopt(handle_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout),
                      sizeof(timeout)) == 0;
#else
  struct timeval tv {
    milliseconds / 1000, (milliseconds % 1000) * 1000
  };
  return ::setsockopt(handle_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
         ::setsockopt(handle_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

bool TcpSocket::EnableKeepAlive(std::uint32_t idle_s, std::uint32_t interval_s, std::uint32_t max_probes) {
  if (!IsValid()) {
    return false;
  }
#ifdef _WIN32
  const int enable = 1;
  if (setsockopt(handle_, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&enable),
                sizeof(enable)) != 0) {
    return false;
  }
  tcp_keepalive keep_alive{};
  keep_alive.onoff = 1;
  keep_alive.keepalivetime = idle_s * 1000;
  keep_alive.keepaliveinterval = interval_s * 1000;
  DWORD bytes_returned = 0;
  if (WSAIoctl(handle_, SIO_KEEPALIVE_VALS, &keep_alive, sizeof(keep_alive), nullptr, 0,
               &bytes_returned, nullptr, nullptr) != 0) {
    (void)max_probes;
    return true;
  }
  (void)max_probes;
  return true;
#else
  const int enable = 1;
  if (setsockopt(handle_, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) != 0) {
    return false;
  }
  const int idle = static_cast<int>(idle_s);
  const int interval = static_cast<int>(interval_s);
  const int probes = static_cast<int>(max_probes);
#ifdef TCP_KEEPIDLE
  if (setsockopt(handle_, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) != 0) return false;
#endif
#ifdef TCP_KEEPINTVL
  if (setsockopt(handle_, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) != 0) return false;
#endif
#ifdef TCP_KEEPCNT
  if (setsockopt(handle_, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes)) != 0) return false;
#endif
  return true;
#endif
}

std::string TcpSocket::PeerAddress() const {
  if (!IsValid()) return {};
  sockaddr_storage addr{};
  socklen_t len = static_cast<socklen_t>(sizeof(addr));
  if (::getpeername(handle_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
    return {};
  }
  char hostbuf[NI_MAXHOST]{};
  if (getnameinfo(reinterpret_cast<sockaddr*>(&addr), len, hostbuf, sizeof(hostbuf), nullptr, 0,
                  NI_NUMERICHOST) != 0) {
    return {};
  }
  return std::string(hostbuf);
}

void TcpSocket::Close() {
  const auto invalid = static_cast<std::intptr_t>(kInvalidSocket);
  if (handle_ != invalid) {
    CloseHandle(static_cast<socket_handle>(handle_));
    handle_ = invalid;
  }
}

bool TcpSocket::IsValid() const noexcept {
  return handle_ != static_cast<std::intptr_t>(kInvalidSocket);
}

}  // namespace qryptcoin::net
