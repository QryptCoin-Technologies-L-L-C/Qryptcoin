#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "nlohmann/json.hpp"

#include "net/socket.hpp"

namespace qryptcoin::rpc {

class HttpServer {
 public:
  struct Options {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{0};
    std::string rpc_user;
    std::string rpc_password;
    bool require_auth{true};
    std::vector<std::string> allowed_hosts;  // exact IPv4 strings; empty -> allow loopback only.
    std::size_t max_body_bytes{1024 * 1024};
    int socket_timeout_ms{5000};
  };

  using Handler = std::function<nlohmann::json(const nlohmann::json&)>;

  HttpServer(Options options, Handler handler);
  ~HttpServer();

  // Start the server on a background thread. This returns immediately
  // once the listen socket is bound, and incoming requests are handled
  // on the internal worker thread until Stop() is called.
  void Start();

  // Request a graceful shutdown. This closes the listening socket,
  // causing the worker thread's accept loop to exit, and then joins
  // the thread. It is safe to call multiple times.
  void Stop();

  // Legacy, blocking entry-point used by early tools. This starts the
  // server and blocks the calling thread until Stop() is invoked from
  // another thread or the process exits.
  void Serve();

 private:
  void ServeLoop();
  void HandleClient(net::TcpSocket client);
  bool ReadRequest(net::TcpSocket& client, std::string* body, int* status);
  bool Authorized(const std::string& headers, const std::string& peer);
  bool HostAllowed(const std::string& peer) const;
  static std::string ParseAuthHeader(const std::string& headers);
  void SendResponse(net::TcpSocket& client, int status, const std::string& json_body);

  Options options_;
  Handler handler_;
  std::atomic<bool> running_{false};
  net::TcpSocket listener_;
  std::thread worker_;
};

}  // namespace qryptcoin::rpc
