#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

#include "net/socket.hpp"
#include "nlohmann/json.hpp"
#include "rpc/http_server.hpp"

namespace {

std::string Base64Encode(std::string_view input) {
  static const char kBase64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  encoded.reserve(((input.size() + 2) / 3) * 4);
  std::uint32_t val = 0;
  int valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) | c;
    valb += 8;
    while (valb >= 0) {
      encoded.push_back(kBase64[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    encoded.push_back(kBase64[((val << 8) >> (valb + 8)) & 0x3F]);
  }
  while (encoded.size() % 4) {
    encoded.push_back('=');
  }
  return encoded;
}

int ParseHttpStatus(const std::string& response) {
  const auto eol = response.find("\r\n");
  if (eol == std::string::npos) {
    return -1;
  }
  const auto line = response.substr(0, eol);
  const auto first_space = line.find(' ');
  if (first_space == std::string::npos) {
    return -1;
  }
  const auto second_space = line.find(' ', first_space + 1);
  const auto code_str = line.substr(first_space + 1, second_space - first_space - 1);
  try {
    return std::stoi(code_str);
  } catch (const std::exception&) {
    return -1;
  }
}

std::optional<std::string> ExtractHttpBody(const std::string& response) {
  const auto sep = response.find("\r\n\r\n");
  if (sep == std::string::npos) {
    return std::nullopt;
  }
  return response.substr(sep + 4);
}

std::string SendHttpRequest(std::uint16_t port, const std::string& request) {
  qryptcoin::net::TcpSocket socket;
  if (!socket.Connect("127.0.0.1", port)) {
    return {};
  }
  if (socket.Send(reinterpret_cast<const std::uint8_t*>(request.data()), request.size()) <= 0) {
    return {};
  }
  std::string response;
  response.reserve(1024);
  std::array<std::uint8_t, 2048> chunk{};
  while (true) {
    const auto bytes = socket.Recv(chunk.data(), chunk.size());
    if (bytes <= 0) {
      break;
    }
    response.append(reinterpret_cast<const char*>(chunk.data()), bytes);
  }
  return response;
}

std::string BuildRequest(std::uint16_t port, std::string_view content_type,
                         const std::optional<std::string>& basic_auth) {
  const std::string body = R"({"jsonrpc":"2.0","id":"1","method":"ping","params":{}})";
  std::ostringstream oss;
  oss << "POST / HTTP/1.1\r\n";
  oss << "Host: 127.0.0.1:" << port << "\r\n";
  if (basic_auth) {
    oss << "Authorization: Basic " << *basic_auth << "\r\n";
  }
  oss << "Content-Type: " << content_type << "\r\n";
  oss << "Content-Length: " << body.size() << "\r\n";
  oss << "Connection: close\r\n\r\n";
  oss << body;
  return oss.str();
}

std::unique_ptr<qryptcoin::rpc::HttpServer> StartServer(std::uint16_t* port_out) {
  using namespace std::chrono_literals;
  for (std::uint16_t port = 43100; port < 43200; ++port) {
    qryptcoin::rpc::HttpServer::Options options;
    options.bind_address = "127.0.0.1";
    options.port = port;
    options.rpc_user = "user";
    options.rpc_password = "pass";
    options.require_auth = true;
    options.max_body_bytes = 1024 * 1024;
    options.socket_timeout_ms = 2000;

    auto server = std::make_unique<qryptcoin::rpc::HttpServer>(
        std::move(options), [](const nlohmann::json& request) {
          nlohmann::json response;
          response["jsonrpc"] = "2.0";
          response["id"] = request.contains("id") ? request.at("id") : "0";
          response["result"] = {{"ok", true}};
          return response;
        });
    try {
      server->Start();
      std::this_thread::sleep_for(50ms);
      *port_out = port;
      return server;
    } catch (const std::exception&) {
      // Try the next port.
    }
  }
  return nullptr;
}

}  // namespace

int main() {
  std::uint16_t port = 0;
  auto server = StartServer(&port);
  if (!server) {
    std::cerr << "Failed to bind HttpServer for tests\n";
    return EXIT_FAILURE;
  }

  const std::string auth = Base64Encode("user:pass");

  {
    const auto request = BuildRequest(port, "application/json", std::nullopt);
    const auto response = SendHttpRequest(port, request);
    const auto status = ParseHttpStatus(response);
    if (status != 401) {
      std::cerr << "Expected 401 for missing auth, got " << status << "\n";
      return EXIT_FAILURE;
    }
    if (response.find("WWW-Authenticate: Basic") == std::string::npos) {
      std::cerr << "Missing WWW-Authenticate header on 401 response\n";
      return EXIT_FAILURE;
    }
  }

  {
    const auto request = BuildRequest(port, "text/plain", auth);
    const auto response = SendHttpRequest(port, request);
    const auto status = ParseHttpStatus(response);
    if (status != 415) {
      std::cerr << "Expected 415 for non-JSON content-type, got " << status << "\n";
      return EXIT_FAILURE;
    }
  }

  {
    const auto request = BuildRequest(port, "application/json", auth);
    const auto response = SendHttpRequest(port, request);
    const auto status = ParseHttpStatus(response);
    if (status != 200) {
      std::cerr << "Expected 200 for authorized JSON request, got " << status << "\n";
      return EXIT_FAILURE;
    }
    const auto body = ExtractHttpBody(response);
    if (!body) {
      std::cerr << "Missing HTTP body in successful response\n";
      return EXIT_FAILURE;
    }
    try {
      const auto parsed = nlohmann::json::parse(*body);
      if (!parsed.contains("result") || !parsed["result"].value("ok", false)) {
        std::cerr << "Unexpected JSON response body\n";
        return EXIT_FAILURE;
      }
    } catch (const std::exception& ex) {
      std::cerr << "Failed to parse JSON response: " << ex.what() << "\n";
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}

