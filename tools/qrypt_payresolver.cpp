#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "config/network.hpp"
#include "net/socket.hpp"
#include "nlohmann/json.hpp"
#include "util/base64.hpp"

namespace {

struct Options {
  std::string network{"mainnet"};
  std::string bind_address{"127.0.0.1"};
  std::uint16_t listen_port{0};
  std::string rpc_host{"127.0.0.1"};
  std::uint16_t rpc_port{0};
  bool rpc_port_explicit{false};
  std::string data_dir;
  bool data_dir_explicit{false};
  std::string rpc_user;
  std::string rpc_pass;
  bool rpc_wait{false};
  std::uint32_t rpc_wait_seconds{30};
  int rpc_timeout_ms{5000};
};

constexpr std::size_t kMaxHttpHeaderSize = 16 * 1024;
constexpr std::size_t kMaxHttpBodySize = 16 * 1024;
constexpr std::size_t kMaxRpcResponseHeaderSize = 16 * 1024;
constexpr std::size_t kMaxRpcResponseBodySize = 16 * 1024;

constexpr double kRateLimitTokensPerSecond = 5.0;
constexpr double kRateLimitBurstTokens = 10.0;

std::optional<std::string> GetEnvValue(std::string_view name) {
  std::string key(name);
  const char* value = std::getenv(key.c_str());
  if (!value || value[0] == '\0') {
    return std::nullopt;
  }
  return std::string(value);
}

std::string DefaultDataDirForNetwork(std::string_view network) {
  if (auto value = GetEnvValue("QRY_DATA_DIR")) {
    return *value;
  }
  return (std::filesystem::path("data") / std::string(network)).string();
}

std::string TrimTrailingNewlines(std::string input) {
  while (!input.empty() && (input.back() == '\n' || input.back() == '\r')) {
    input.pop_back();
  }
  return input;
}

bool IsLoopbackAddress(std::string_view address) {
  if (address == "localhost" || address == "::1") {
    return true;
  }
  int a = 0;
  int b = 0;
  int c = 0;
  int d = 0;
  if (std::sscanf(std::string(address).c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return false;
  }
  if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) {
    return false;
  }
  return a == 127;
}

std::string ReadFirstLineFromFile(const std::string& path) {
  std::ifstream in(path, std::ios::in);
  if (!in) {
    throw std::runtime_error("unable to read file: " + path);
  }
  std::string line;
  std::getline(in, line);
  return TrimTrailingNewlines(std::move(line));
}

std::string Base64EncodeString(std::string_view input) {
  return qryptcoin::util::Base64Encode(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
}

std::optional<std::string> ResolveBasicAuth(const Options& opts) {
  if (!opts.rpc_user.empty() || !opts.rpc_pass.empty()) {
    if (opts.rpc_user.empty() || opts.rpc_pass.empty()) {
      throw std::runtime_error("--rpc-user and --rpc-pass must be set together");
    }
    const std::string creds = opts.rpc_user + ":" + opts.rpc_pass;
    return Base64EncodeString(creds);
  }
  if (opts.data_dir.empty()) {
    return std::nullopt;
  }
  const auto cookie_path = std::filesystem::path(opts.data_dir) / "rpc.cookie";
  std::error_code ec;
  const bool cookie_exists = std::filesystem::exists(cookie_path, ec);
  std::ifstream in(cookie_path);
  if (!in) {
    if (cookie_exists) {
      throw std::runtime_error("unable to read RPC auth cookie at " + cookie_path.string());
    }
    return std::nullopt;
  }
  std::string cookie_line;
  std::getline(in, cookie_line);
  cookie_line = TrimTrailingNewlines(std::move(cookie_line));
  if (cookie_line.empty()) {
    return std::nullopt;
  }
  return Base64EncodeString(cookie_line);
}

std::string BuildHttpRequest(const std::string& host, std::uint16_t port,
                             const std::string& body,
                             const std::optional<std::string>& basic_auth) {
  std::ostringstream oss;
  oss << "POST / HTTP/1.1\r\n";
  oss << "Host: " << host << ":" << port << "\r\n";
  if (basic_auth && !basic_auth->empty()) {
    oss << "Authorization: Basic " << *basic_auth << "\r\n";
  }
  oss << "Content-Type: application/json\r\n";
  oss << "Content-Length: " << body.size() << "\r\n";
  oss << "Connection: close\r\n\r\n";
  oss << body;
  return oss.str();
}

std::optional<std::size_t> FindHeaderEnd(const std::string& data) {
  auto pos = data.find("\r\n\r\n");
  if (pos == std::string::npos) {
    return std::nullopt;
  }
  return pos + 4;
}

std::optional<int> ParseContentLength(std::string_view headers) {
  std::size_t offset = 0;
  while (offset < headers.size()) {
    auto end = headers.find("\r\n", offset);
    if (end == std::string_view::npos) {
      end = headers.size();
    }
    auto line = headers.substr(offset, end - offset);
    auto colon = line.find(':');
    if (colon != std::string_view::npos) {
      auto key = line.substr(0, colon);
      auto value = line.substr(colon + 1);
      if (key == "Content-Length" || key == "content-length") {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
          value.remove_prefix(1);
        }
        try {
          return std::stoi(std::string(value));
        } catch (const std::exception&) {
          return std::nullopt;
        }
      }
    }
    if (end >= headers.size()) {
      break;
    }
    offset = end + 2;
  }
  return std::nullopt;
}

qryptcoin::net::TcpSocket ConnectToRpc(const Options& opts) {
  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + std::chrono::seconds(opts.rpc_wait_seconds);

  while (true) {
    qryptcoin::net::TcpSocket socket;
    if (socket.Connect(opts.rpc_host, opts.rpc_port, /*quiet=*/opts.rpc_wait)) {
      return socket;
    }
    if (!opts.rpc_wait) {
      break;
    }
    if (clock::now() >= deadline) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  throw std::runtime_error("failed to connect to RPC server");
}

nlohmann::json CallRpc(const Options& opts, const nlohmann::json& request,
                       const std::optional<std::string>& basic_auth) {
  qryptcoin::net::TcpSocket socket = ConnectToRpc(opts);
  if (opts.rpc_timeout_ms > 0) {
    (void)socket.SetTimeout(opts.rpc_timeout_ms);
  }
  const auto payload = request.dump();
  const auto http = BuildHttpRequest(opts.rpc_host, opts.rpc_port, payload, basic_auth);
  if (socket.Send(reinterpret_cast<const std::uint8_t*>(http.data()), http.size()) <= 0) {
    throw std::runtime_error("failed to send request");
  }
  std::string response;
  response.reserve(1024);
  std::array<std::uint8_t, 2048> chunk{};
  std::ptrdiff_t bytes = 0;
  std::optional<std::size_t> body_offset;
  int content_length = -1;
  while (true) {
    bytes = socket.Recv(chunk.data(), chunk.size());
    if (bytes <= 0) {
      break;
    }
    response.append(reinterpret_cast<const char*>(chunk.data()), bytes);
    if (!body_offset) {
      if (response.size() > kMaxRpcResponseHeaderSize) {
        throw std::runtime_error("RPC response headers too large");
      }
      body_offset = FindHeaderEnd(response);
      if (body_offset) {
        auto headers = std::string_view(response.data(), *body_offset - 4);
        auto length = ParseContentLength(headers);
        if (!length) {
          throw std::runtime_error("missing Content-Length");
        }
        if (*length < 0) {
          throw std::runtime_error("invalid Content-Length");
        }
        if (static_cast<std::size_t>(*length) > kMaxRpcResponseBodySize) {
          throw std::runtime_error("RPC response too large");
        }
        content_length = *length;
      }
    } else if (body_offset) {
      if (response.size() > *body_offset + kMaxRpcResponseBodySize) {
        throw std::runtime_error("RPC response too large");
      }
    }
    if (body_offset && response.size() >= *body_offset + static_cast<std::size_t>(content_length)) {
      break;
    }
  }
  if (!body_offset || content_length < 0) {
    throw std::runtime_error("invalid RPC response");
  }
  std::string body = response.substr(*body_offset, content_length);
  return nlohmann::json::parse(body);
}

void SendHttpResponse(qryptcoin::net::TcpSocket& client, int status,
                      const std::string& body) {
  std::ostringstream oss;
  oss << "HTTP/1.1 " << status << (status == 200 ? " OK" : " Error") << "\r\n";
  oss << "Content-Type: application/json\r\n";
  oss << "Content-Length: " << body.size() << "\r\n";
  oss << "Connection: close\r\n\r\n";
  oss << body;
  const auto response = oss.str();
  client.Send(reinterpret_cast<const std::uint8_t*>(response.data()), response.size());
}

bool HasJsonContentType(std::string_view headers) {
  std::size_t offset = 0;
  while (offset < headers.size()) {
    auto end = headers.find("\r\n", offset);
    if (end == std::string_view::npos) {
      end = headers.size();
    }
    auto line = headers.substr(offset, end - offset);
    if (line.rfind("Content-Type:", 0) == 0 || line.rfind("content-type:", 0) == 0) {
      auto colon = line.find(':');
      if (colon == std::string_view::npos) {
        return false;
      }
      auto value = line.substr(colon + 1);
      while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
      }
      auto sep = value.find(';');
      if (sep != std::string_view::npos) {
        value = value.substr(0, sep);
      }
      while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
      }
      return value == "application/json";
    }
    if (end >= headers.size()) {
      break;
    }
    offset = end + 2;
  }
  return false;
}

struct HttpRequest {
  std::string method;
  std::string path;
  std::string body;
};

bool ReadHttpRequest(qryptcoin::net::TcpSocket& client, HttpRequest* out_request,
                     int* out_status) {
  std::string buffer;
  buffer.reserve(1024);
  std::array<std::uint8_t, 2048> chunk{};
  std::ptrdiff_t bytes = 0;
  std::size_t header_end = std::string::npos;
  while (buffer.size() < kMaxHttpHeaderSize) {
    bytes = client.Recv(chunk.data(), chunk.size());
    if (bytes <= 0) {
      *out_status = 400;
      return false;
    }
    buffer.append(reinterpret_cast<const char*>(chunk.data()), bytes);
    header_end = buffer.find("\r\n\r\n");
    if (header_end != std::string::npos) {
      break;
    }
  }
  if (header_end == std::string::npos) {
    *out_status = 413;
    return false;
  }
  const std::string headers = buffer.substr(0, header_end);
  auto first_line_end = headers.find("\r\n");
  if (first_line_end == std::string::npos) {
    *out_status = 400;
    return false;
  }
  const auto request_line = headers.substr(0, first_line_end);

  std::string method;
  std::string path;
  {
    const auto first_sp = request_line.find(' ');
    if (first_sp == std::string::npos) {
      *out_status = 400;
      return false;
    }
    const auto second_sp = request_line.find(' ', first_sp + 1);
    if (second_sp == std::string::npos) {
      *out_status = 400;
      return false;
    }
    method = request_line.substr(0, first_sp);
    path = request_line.substr(first_sp + 1, second_sp - (first_sp + 1));
    if (method.empty() || path.empty()) {
      *out_status = 400;
      return false;
    }
  }
  out_request->method = method;
  out_request->path = path;
  out_request->body.clear();

  if (method == "GET") {
    auto length = ParseContentLength(headers);
    if (length && *length != 0) {
      *out_status = 400;
      return false;
    }
    return true;
  }

  if (method != "POST") {
    *out_status = 405;
    return false;
  }

  if (!HasJsonContentType(headers)) {
    *out_status = 415;
    return false;
  }

  auto length = ParseContentLength(headers);
  if (!length || *length < 0) {
    *out_status = 411;
    return false;
  }
  if (static_cast<std::size_t>(*length) > kMaxHttpBodySize) {
    *out_status = 413;
    return false;
  }
  std::string payload = buffer.substr(header_end + 4);
  while (payload.size() < static_cast<std::size_t>(*length)) {
    bytes = client.Recv(chunk.data(), chunk.size());
    if (bytes <= 0) {
      *out_status = 400;
      return false;
    }
    payload.append(reinterpret_cast<const char*>(chunk.data()), bytes);
    if (payload.size() > kMaxHttpBodySize) {
      *out_status = 413;
      return false;
    }
  }
  if (payload.size() > static_cast<std::size_t>(*length)) {
    payload.resize(*length);
  }
  out_request->body = std::move(payload);
  return true;
}

struct TokenBucket {
  double tokens{0.0};
  std::chrono::steady_clock::time_point last_refill{};
};

bool ConsumeRateLimitToken(std::unordered_map<std::string, TokenBucket>& buckets,
                           std::string_view peer) {
  using clock = std::chrono::steady_clock;
  const auto now = clock::now();
  auto& bucket = buckets[std::string(peer)];
  if (bucket.last_refill.time_since_epoch().count() == 0) {
    bucket.tokens = kRateLimitBurstTokens;
    bucket.last_refill = now;
  } else {
    const auto elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - bucket.last_refill);
    bucket.tokens = std::min(kRateLimitBurstTokens,
                             bucket.tokens + elapsed.count() * kRateLimitTokensPerSecond);
    bucket.last_refill = now;
  }
  if (bucket.tokens < 1.0) {
    return false;
  }
  bucket.tokens -= 1.0;
  return true;
}

void Serve(const Options& opts) {
  qryptcoin::net::TcpSocket listener;
  if (!listener.BindAndListen(opts.bind_address, opts.listen_port, /*backlog=*/64)) {
    throw std::runtime_error("failed to bind listen port");
  }

  const auto auth = ResolveBasicAuth(opts);
  std::unordered_map<std::string, TokenBucket> rate_limits;

  while (true) {
    auto client = listener.Accept();
    if (!client.IsValid()) {
      continue;
    }

    (void)client.SetTimeout(5000);
    const std::string peer = client.PeerAddress();
    if (!ConsumeRateLimitToken(rate_limits, peer.empty() ? "unknown" : peer)) {
      SendHttpResponse(client, 429,
                       R"({"jsonrpc":"2.0","error":{"code":-32000,"message":"rate limited"}})");
      continue;
    }

    HttpRequest http_request;
    int status = 200;
    if (!ReadHttpRequest(client, &http_request, &status)) {
      SendHttpResponse(client, status,
                       R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"invalid request"}})");
      continue;
    }

    if (http_request.method == "GET" && http_request.path == "/health") {
      nlohmann::json health = {
          {"mode", "http-insecure"},
          {"version", "1"},
          {"allowed_methods",
           nlohmann::json::array({"validatepaymentcode",
                                 "resolvepaymentcode",
                                 "registerpaymentcode",
                                 "resolvepaymentcodeshort"})},
      };
      const auto body = health.dump();
      SendHttpResponse(client, 200, body);
      continue;
    }

    if (http_request.method != "POST") {
      SendHttpResponse(
          client, 405,
          R"({"jsonrpc":"2.0","error":{"code":-32601,"message":"unsupported HTTP method"}})");
      continue;
    }
    nlohmann::json request;
    try {
      request = nlohmann::json::parse(http_request.body);
    } catch (const std::exception&) {
      SendHttpResponse(client, 400,
                       R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"invalid JSON"}})");
      continue;
    }
    const std::string method = request.value("method", std::string{});
    if (method != "resolvepaymentcode" && method != "validatepaymentcode" &&
        method != "registerpaymentcode" && method != "resolvepaymentcodeshort") {
      SendHttpResponse(client, 200,
                       R"({"jsonrpc":"2.0","error":{"code":-32601,"message":"unknown method"}})");
      continue;
    }
    try {
      auto response = CallRpc(opts, request, auth);
      const auto out = response.dump();
      if (out.size() > kMaxHttpBodySize) {
        throw std::runtime_error("upstream response too large");
      }
      SendHttpResponse(client, 200, out);
    } catch (const std::exception& ex) {
      nlohmann::json error = {
          {"jsonrpc", "2.0"},
          {"error", {{"code", -32603}, {"message", ex.what()}}},
      };
      SendHttpResponse(client, 200, error.dump());
    }
  }
}

void PrintUsage() {
  std::cout << "Usage: qrypt-payresolver [options]\n"
            << "Options:\n"
            << "  --network <net>        mainnet, testnet, regtest, signet (default: mainnet)\n"
            << "  --bind <addr>          Bind address for resolver (default: 127.0.0.1)\n"
            << "  --port <port>          Bind port for resolver (default: rpc_port + 1)\n"
            << "  --rpc-host <host>      qryptd RPC host (default: 127.0.0.1)\n"
            << "  --rpc-port <port>      qryptd RPC port (default: network-specific)\n"
            << "  --rpc-timeout-ms <n>   RPC timeout in milliseconds (default: 5000)\n"
            << "  --data-dir <path>      Data dir for rpc.cookie lookup\n"
            << "  --rpc-user <user>      RPC basic auth user (optional)\n"
            << "  --rpc-pass <pass>      RPC basic auth password (optional)\n"
            << "  --rpc-wait             Wait for the RPC server to be reachable\n"
            << "  --rpc-wait-seconds <n> Max seconds to wait when --rpc-wait is set (default: 30)\n";
}

Options ParseOptions(int argc, char** argv) {
  Options opts;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--network") {
      if (++i >= argc) throw std::runtime_error("missing value for --network");
      opts.network = argv[i];
    } else if (arg == "--bind") {
      if (++i >= argc) throw std::runtime_error("missing value for --bind");
      opts.bind_address = argv[i];
    } else if (arg == "--port") {
      if (++i >= argc) throw std::runtime_error("missing value for --port");
      opts.listen_port = static_cast<std::uint16_t>(std::stoi(argv[i]));
    } else if (arg == "--rpc-host") {
      if (++i >= argc) throw std::runtime_error("missing value for --rpc-host");
      opts.rpc_host = argv[i];
    } else if (arg == "--rpc-port") {
      if (++i >= argc) throw std::runtime_error("missing value for --rpc-port");
      opts.rpc_port = static_cast<std::uint16_t>(std::stoi(argv[i]));
      opts.rpc_port_explicit = true;
    } else if (arg == "--rpc-timeout-ms") {
      if (++i >= argc) throw std::runtime_error("missing value for --rpc-timeout-ms");
      const long parsed = std::stol(argv[i]);
      if (parsed < 100 || parsed > 600000) {
        throw std::runtime_error("--rpc-timeout-ms out of range (100..600000)");
      }
      opts.rpc_timeout_ms = static_cast<int>(parsed);
    } else if (arg == "--data-dir") {
      if (++i >= argc) throw std::runtime_error("missing value for --data-dir");
      opts.data_dir = argv[i];
      opts.data_dir_explicit = true;
    } else if (arg == "--rpc-user") {
      if (++i >= argc) throw std::runtime_error("missing value for --rpc-user");
      opts.rpc_user = argv[i];
    } else if (arg == "--rpc-pass") {
      if (++i >= argc) throw std::runtime_error("missing value for --rpc-pass");
      opts.rpc_pass = argv[i];
    } else if (arg == "--rpc-wait") {
      opts.rpc_wait = true;
    } else if (arg == "--rpc-wait-seconds") {
      if (++i >= argc) throw std::runtime_error("missing value for --rpc-wait-seconds");
      const unsigned long parsed = std::stoul(argv[i]);
      if (parsed > 3600) {
        throw std::runtime_error("--rpc-wait-seconds out of range (max 3600)");
      }
      opts.rpc_wait_seconds = static_cast<std::uint32_t>(parsed);
      opts.rpc_wait = true;
    } else if (arg == "--help" || arg == "-h") {
      PrintUsage();
      std::exit(0);
    } else {
      throw std::runtime_error("unknown option: " + arg);
    }
  }
  return opts;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    auto opts = ParseOptions(argc, argv);
    auto net = qryptcoin::config::NetworkFromString(opts.network);
    qryptcoin::config::SelectNetwork(net);

    if (!opts.rpc_port_explicit) {
      opts.rpc_port = qryptcoin::config::GetNetworkConfig().rpc_port;
    }
    if (!opts.data_dir_explicit) {
      opts.data_dir = DefaultDataDirForNetwork(qryptcoin::config::NetworkName(net));
    }
    if (opts.listen_port == 0) {
      const auto rpc_port = qryptcoin::config::GetNetworkConfig().rpc_port;
      opts.listen_port = static_cast<std::uint16_t>(rpc_port + 1);
    }

    if (!IsLoopbackAddress(opts.bind_address)) {
      std::cerr << "warning: qrypt-payresolver is unauthenticated HTTP; binding to "
                << opts.bind_address
                << " may expose payment-code resolution to untrusted networks\n";
    }

    std::cout << "qrypt-payresolver listening on " << opts.bind_address << ":" << opts.listen_port
              << " (proxying RPC " << opts.rpc_host << ":" << opts.rpc_port << ")\n";
    Serve(opts);
  } catch (const std::exception& ex) {
    std::cerr << "qrypt-payresolver: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}
