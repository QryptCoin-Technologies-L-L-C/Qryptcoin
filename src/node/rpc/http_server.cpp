#include "rpc/http_server.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cctype>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace qryptcoin::rpc {

namespace {

constexpr std::size_t kMaxHeaderSize = 64 * 1024;
constexpr std::size_t kDefaultMaxBodySize = 1024 * 1024;

bool IsJsonContentType(std::string_view value) {
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
  constexpr std::string_view kJson = "application/json";
  if (value.size() != kJson.size()) {
    return false;
  }
  for (std::size_t i = 0; i < kJson.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(value[i])) !=
        std::tolower(static_cast<unsigned char>(kJson[i]))) {
      return false;
    }
  }
  return true;
}

bool HasJsonContentType(const std::string& headers) {
  std::string_view hdr_view(headers);
  std::size_t start = 0;
  while (start < hdr_view.size()) {
    auto end = hdr_view.find("\r\n", start);
    auto line = end == std::string_view::npos ? hdr_view.substr(start)
                                              : hdr_view.substr(start, end - start);
    if (line.starts_with("Content-Type:") || line.starts_with("content-type:")) {
      line.remove_prefix(line.find(':') + 1);
      return IsJsonContentType(line);
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 2;
  }
  return false;
}

int ParseContentLength(const std::string& headers) {
  std::string_view hdr_view(headers);
  std::size_t start = 0;
  while (start < hdr_view.size()) {
    auto end = hdr_view.find("\r\n", start);
    auto line = end == std::string_view::npos ? hdr_view.substr(start)
                                              : hdr_view.substr(start, end - start);
    if (line.starts_with("Content-Length:") || line.starts_with("content-length:")) {
      line.remove_prefix(line.find(':') + 1);
      while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front()))) {
        line.remove_prefix(1);
      }
      try {
        return std::stoi(std::string(line));
      } catch (const std::exception&) {
        return -1;
      }
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 2;
  }
  // If there is no explicit Content-Length header, signal that the caller
  // should fall back to using whatever payload bytes have already been read
  // from the socket instead of rejecting the request outright.
  return -1;
}

}  // namespace

HttpServer::HttpServer(Options options, Handler handler)
    : options_(std::move(options)), handler_(std::move(handler)) {
  if (options_.max_body_bytes == 0) {
    options_.max_body_bytes = kDefaultMaxBodySize;
  }
}

HttpServer::~HttpServer() { Stop(); }

void HttpServer::Start() {
  bool expected = false;
  if (!running_.compare_exchange_strong(expected, true)) {
    return;
  }
  if (!listener_.BindAndListen(options_.bind_address, options_.port)) {
    running_.store(false);
    throw std::runtime_error("failed to bind RPC port");
  }
  worker_ = std::thread([this]() { ServeLoop(); });
}

void HttpServer::Stop() {
  bool expected = true;
  if (!running_.compare_exchange_strong(expected, false)) {
    return;
  }
  listener_.Close();
  if (worker_.joinable()) {
    worker_.join();
  }
}

void HttpServer::Serve() {
  Start();
  if (worker_.joinable()) {
    worker_.join();
  }
}

void HttpServer::ServeLoop() {
  while (running_) {
    auto client = listener_.AcceptWithTimeout(200);
    if (!client.IsValid()) {
      if (!running_) {
        break;
      }
      continue;
    }
    if (options_.socket_timeout_ms > 0) {
      client.SetTimeout(options_.socket_timeout_ms);
    }
    HandleClient(std::move(client));
  }
}

void HttpServer::HandleClient(net::TcpSocket client) {
  std::string body;
  int status = 200;
  if (!ReadRequest(client, &body, &status)) {
    std::string error_json = R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"parse error"}})";
    if (status == 401) {
      error_json = R"({"jsonrpc":"2.0","error":{"code":-32651,"message":"unauthorized"}})";
    } else if (status == 415) {
      error_json = R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"unsupported media type"}})";
    } else if (status == 413) {
      error_json = R"({"jsonrpc":"2.0","error":{"code":-32000,"message":"request too large"}})";
    }
    SendResponse(client, status, error_json);
    return;
  }
  try {
    auto payload = nlohmann::json::parse(body);
    auto response = handler_(payload);
    SendResponse(client, 200, response.dump());
  } catch (const nlohmann::json::exception&) {
    SendResponse(client, 400, R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"invalid JSON"}})");
  } catch (const std::exception& ex) {
    nlohmann::json error = {
        {"jsonrpc", "2.0"},
        {"error", {{"code", -32603}, {"message", ex.what()}}},
    };
    SendResponse(client, 200, error.dump());
  }
}

bool HttpServer::ReadRequest(net::TcpSocket& client, std::string* body, int* status) {
  std::string buffer;
  buffer.reserve(1024);
  std::array<std::uint8_t, 2048> chunk{};
  std::ptrdiff_t bytes = 0;
  std::size_t header_end = std::string::npos;
  std::string peer = client.PeerAddress();
  while (buffer.size() < kMaxHeaderSize) {
    bytes = client.Recv(chunk.data(), chunk.size());
    if (bytes <= 0) {
      *status = 400;
      return false;
    }
    buffer.append(reinterpret_cast<const char*>(chunk.data()), bytes);
    header_end = buffer.find("\r\n\r\n");
    if (header_end != std::string::npos) {
      break;
    }
  }
  if (header_end == std::string::npos) {
    *status = 413;
    return false;
  }
  std::string headers = buffer.substr(0, header_end);
  auto first_line_end = headers.find("\r\n");
  if (first_line_end == std::string::npos) {
    *status = 400;
    return false;
  }
  auto request_line = headers.substr(0, first_line_end);
  if (request_line.rfind("POST", 0) != 0) {
    *status = 405;
    return false;
  }
  if (!HasJsonContentType(headers)) {
    *status = 415;
    return false;
  }
  int content_length = ParseContentLength(headers);
  if (content_length < 0) {
    content_length = 0;
  }
  if (!Authorized(headers, peer)) {
    *status = 401;
    return false;
  }
  if (static_cast<std::size_t>(content_length) > options_.max_body_bytes) {
    *status = 413;
    return false;
  }
  std::string payload = buffer.substr(header_end + 4);
  while (payload.size() < static_cast<std::size_t>(content_length)) {
    bytes = client.Recv(chunk.data(), chunk.size());
    if (bytes <= 0) {
      *status = 400;
      return false;
    }
    payload.append(reinterpret_cast<const char*>(chunk.data()), bytes);
    if (payload.size() > options_.max_body_bytes) {
      *status = 413;
      return false;
    }
  }
  if (content_length > 0 && payload.size() > static_cast<std::size_t>(content_length)) {
    payload.resize(content_length);
  }
  *body = std::move(payload);
  return true;
}

bool HttpServer::Authorized(const std::string& headers, const std::string& peer) {
  if (!HostAllowed(peer)) {
    return false;
  }
  if (!options_.require_auth) {
    return true;
  }
  if (options_.rpc_user.empty() || options_.rpc_password.empty()) {
    return false;
  }
  const auto auth = ParseAuthHeader(headers);
  if (auth.empty()) {
    return false;
  }
  return auth == (options_.rpc_user + ":" + options_.rpc_password);
}

bool HttpServer::HostAllowed(const std::string& peer) const {
  if (peer.empty()) {
    return false;
  }
  if (options_.allowed_hosts.empty()) {
    // default allow loopback
    return peer == "127.0.0.1" || peer == "::1" || peer.rfind("127.", 0) == 0;
  }
  return std::find(options_.allowed_hosts.begin(), options_.allowed_hosts.end(), peer) !=
         options_.allowed_hosts.end();
}

std::string HttpServer::ParseAuthHeader(const std::string& headers) {
  std::string_view hdr(headers);
  std::size_t start = 0;
  while (start < hdr.size()) {
    auto end = hdr.find("\r\n", start);
    auto line =
        end == std::string_view::npos ? hdr.substr(start) : hdr.substr(start, end - start);
    if (line.starts_with("Authorization:") || line.starts_with("authorization:")) {
      auto colon = line.find(' ');
      if (colon == std::string_view::npos) {
        break;
      }
      auto scheme = line.substr(colon + 1);
      while (!scheme.empty() && std::isspace(static_cast<unsigned char>(scheme.front()))) {
        scheme.remove_prefix(1);
      }
      constexpr std::string_view kBasic = "Basic ";
      if (!scheme.starts_with(kBasic)) {
        break;
      }
      scheme.remove_prefix(kBasic.size());
      std::string encoded(scheme);
      std::vector<std::uint8_t> decoded;
      decoded.reserve(encoded.size());
      static const std::string base64_chars =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      int val = 0, valb = -8;
      for (unsigned char c : encoded) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        if (c == '=') break;
        auto pos = base64_chars.find(c);
        if (pos == std::string::npos) {
          return {};
        }
        val = (val << 6) + static_cast<int>(pos);
        valb += 6;
        if (valb >= 0) {
          decoded.push_back(static_cast<char>((val >> valb) & 0xFF));
          valb -= 8;
        }
      }
      return std::string(decoded.begin(), decoded.end());
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 2;
  }
  return {};
}

void HttpServer::SendResponse(net::TcpSocket& client, int status, const std::string& json_body) {
  std::ostringstream oss;
  oss << "HTTP/1.1 " << status << (status == 200 ? " OK" : " Error") << "\r\n";
  oss << "Content-Type: application/json\r\n";
  if (status == 401) {
    oss << "WWW-Authenticate: Basic realm=\"qryptcoin\"\r\n";
  }
  oss << "Content-Length: " << json_body.size() << "\r\n";
  oss << "Connection: close\r\n\r\n";
  oss << json_body;
  const auto response = oss.str();
  client.Send(reinterpret_cast<const std::uint8_t*>(response.data()), response.size());
  client.Close();
}

}  // namespace qryptcoin::rpc
