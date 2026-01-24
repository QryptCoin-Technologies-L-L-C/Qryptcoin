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
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "config/network.hpp"
#include "crypto/p2qh_address.hpp"
#include "crypto/payment_code.hpp"
#include "net/socket.hpp"
#include "nlohmann/json.hpp"
#include "util/csprng.hpp"

namespace {

struct CliOptions {
  std::string rpc_host{"127.0.0.1"};
  std::uint16_t rpc_port{0};
  bool rpc_port_explicit{false};
  std::string data_dir;
  bool data_dir_explicit{false};
  std::string network{"mainnet"};
  bool rpc_wait{false};
  std::uint32_t rpc_wait_seconds{30};
  bool raw{false};
  std::string rpc_user;
  std::string rpc_pass;
  std::vector<std::string> args;
};

bool HasFlag(const std::vector<std::string>& args, std::string_view flag) {
  for (const auto& arg : args) {
    if (arg == flag) {
      return true;
    }
  }
  return false;
}

std::optional<std::string> FindPrefixedOptionValue(const std::vector<std::string>& args,
                                                   std::string_view prefix) {
  for (std::size_t i = 1; i < args.size(); ++i) {
    const auto& arg = args[i];
    if (arg.rfind(prefix, 0) == 0) {
      return arg.substr(prefix.size());
    }
  }
  return std::nullopt;
}

bool IsStdinInteractive() {
#ifdef _WIN32
  return _isatty(_fileno(stdin)) != 0;
#else
  return isatty(fileno(stdin)) != 0;
#endif
}

std::string TrimTrailingNewlines(std::string input) {
  while (!input.empty() && (input.back() == '\n' || input.back() == '\r')) {
    input.pop_back();
  }
  return input;
}

std::string ReadFirstLineFromFile(const std::string& path, std::string_view label) {
  std::ifstream in(path, std::ios::in);
  if (!in) {
    throw std::runtime_error("unable to read " + std::string(label) + " file: " + path);
  }
  std::string line;
  std::getline(in, line);
  return TrimTrailingNewlines(std::move(line));
}

std::string ReadLineFromStdin(std::string_view label) {
  std::string line;
  if (!std::getline(std::cin, line)) {
    throw std::runtime_error("failed to read " + std::string(label) + " from stdin");
  }
  return TrimTrailingNewlines(std::move(line));
}

std::string PromptHidden(std::string_view prompt) {
  if (!IsStdinInteractive()) {
    throw std::runtime_error("stdin is not interactive; use -stdin or -file options");
  }
  std::cerr << prompt;
  std::string line;
#ifdef _WIN32
  const HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
  DWORD original_mode = 0;
  bool have_mode = false;
  if (handle != INVALID_HANDLE_VALUE && GetConsoleMode(handle, &original_mode)) {
    have_mode = true;
    const DWORD new_mode = original_mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT);
    (void)SetConsoleMode(handle, new_mode);
  }
  std::getline(std::cin, line);
  if (have_mode) {
    (void)SetConsoleMode(handle, original_mode);
  }
  std::cerr << "\n";
#else
  termios original{};
  bool have_termios = false;
  if (tcgetattr(STDIN_FILENO, &original) == 0) {
    have_termios = true;
    termios updated = original;
    updated.c_lflag &= static_cast<tcflag_t>(~ECHO);
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &updated);
  }
  std::getline(std::cin, line);
  if (have_termios) {
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
    std::cerr << "\n";
  }
#endif
  return TrimTrailingNewlines(std::move(line));
}

std::optional<std::string> ReadSecretFromArgs(const std::vector<std::string>& args,
                                              std::string_view insecure_prefix,
                                              std::string_view stdin_flag,
                                              std::string_view file_prefix,
                                              std::string_view label,
                                              bool required,
                                              bool hidden) {
  std::optional<std::string> value;
  int sources = 0;

  if (auto insecure = FindPrefixedOptionValue(args, insecure_prefix)) {
    ++sources;
    value = std::move(*insecure);
    std::cerr << "warning: " << insecure_prefix
              << "... exposes secrets via process listings/shell history; prefer "
              << stdin_flag << " or " << file_prefix << "<path>\n";
  }
  if (HasFlag(args, stdin_flag)) {
    ++sources;
    value = ReadLineFromStdin(label);
  }
  if (auto file = FindPrefixedOptionValue(args, file_prefix)) {
    ++sources;
    value = ReadFirstLineFromFile(*file, label);
  }

  if (sources > 1) {
    throw std::runtime_error("specify only one of " + std::string(insecure_prefix) + "... , " +
                             std::string(stdin_flag) + ", or " + std::string(file_prefix) +
                             "<path>");
  }

  if (!value && required) {
    value = hidden ? PromptHidden("Enter " + std::string(label) + ": ")
                   : ReadLineFromStdin(label);
  }

  if (value && required && value->empty()) {
    throw std::runtime_error(std::string(label) + " must not be empty");
  }
  return value;
}

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
#ifndef _WIN32
  {
    std::error_code ec;
    const auto systemd_path =
        (std::filesystem::path("/var/lib/qryptcoin") / std::string(network));
    if (std::filesystem::exists(systemd_path, ec) &&
        std::filesystem::is_directory(systemd_path, ec)) {
      return systemd_path.string();
    }
  }
#endif
  return (std::filesystem::path("data") / std::string(network)).string();
}

void PrintUsage() {
  std::cout << "Usage: qrypt-cli [options] <command> [params]\n"
            << "Commands:\n"
            << "  getblockchaininfo\n"
            << "  health                      Condensed node health summary (wraps gethealth)\n"
            << "  getblockcount\n"
            << "  getbestblockhash\n"
            << "  getblock <hash|height> [--verbosity=N]\n"
            << "  getmempoolinfo\n"
            << "  getrawmempool\n"
            << "  getmempoolentry <txid>\n"
            << "  estimatesmartfee <target_blocks>\n"
            << "  getmininginfo\n"
            << "  createrawtransaction --inputs=<json> --outputs=<json> [--locktime=N]\n"
            << "  decoderawtransaction <hex>\n"
            << "  sendrawtransaction <hex>\n"
            << "  getnewaddress\n"
            << "  getpaymentcode\n"
            << "  validatepaymentcode <code>\n"
            << "  resolvepaymentcode <code>\n"
            << "  sendtoaddress <address> <amount> [--fee-rate=N]\n"
            << "  sendto <paycode-or-address> <amount> [--fee-rate=N] [--resolver=<host:port>]\n"
            << "       [--resolver-policy=local-only|lan-ok|insecure-ok]\n"
            << "       [--allow-lan-resolver] [--allow-insecure-resolver]\n"
            << "       [--resolver-timeout-ms=N] [--resolver-max-retries=N]\n"
            << "  listutxos\n"
            << "  getpqinfo\n"
            << "  getwalletinfo\n"
            << "  listaddresses\n"
            << "  importaddress <address> [--no-rescan]\n"
            << "  listwatchonly\n"
            << "  removewatchonly <address...>\n"
            << "  listtransactions [count]\n"
            << "  getnetworkinfo\n"
            << "  getpeerinfo\n"
            << "  addnode <address[:port]> [--address=<address[:port]>]\n"
            << "  disconnectnode <id> [--id=<id>]\n"
            << "  getaddednodeinfo\n"
            << "  listdnsseeds\n"
            << "  refreshdnsseeds\n"
            << "  getblocktemplate [--address=<addr>]\n"
             << "  submitblock <hex>\n"
             << "  generate <blocks>\n"
             << "  generatetoaddress <blocks> <address>\n"
             << "  createwallet --wallet-path=<path> [--wallet-name=<name>]\n"
             << "             [--passphrase=<pass>|--passphrase-stdin|--passphrase-file=<path>]\n"
             << "             [--mnemonic=<phrase>|--mnemonic-stdin|--mnemonic-file=<path>]\n"
             << "             [--mnemonic-passphrase=<pass>|--mnemonic-passphrase-stdin|--mnemonic-passphrase-file=<path>]\n"
             << "  loadwallet --path=<path> [--passphrase=<pass>|--passphrase-stdin|--passphrase-file=<path>]\n"
             << "  backupwallet --destination=<path>\n"
             << "  encryptwallet [--passphrase=<pass>|--passphrase-stdin|--passphrase-file=<path>]\n"
             << "  walletlock\n"
             << "  walletpassphrase [--passphrase=<pass>|--passphrase-stdin|--passphrase-file=<path>]\n"
              << "Options:\n"
              << "  --network <net>     mainnet, testnet, regtest, signet (default mainnet)\n"
              << "  --rpc-host <host>   RPC host (default 127.0.0.1)\n"
              << "  --rpc-port <port>   RPC port (default depends on network)\n"
             << "  --data-dir <path>   Data directory (for rpc.cookie lookup; default prefers QRY_DATA_DIR or /var/lib)\n"
             << "  --rpc-user <user>   RPC basic auth user (optional)\n"
             << "  --rpc-pass <pass>   RPC basic auth password (optional)\n"
             << "  --rpc-wait          Wait for the RPC server to be reachable\n"
             << "  --rpc-wait-seconds <n>  Max seconds to wait when --rpc-wait is set (default: 30)\n"
             << "  --raw               Print raw JSON response\n";
}

enum class ResolverScope {
  kLocal,
  kLan,
  kPublic,
};

ResolverScope ClassifyResolverHost(std::string_view host) {
  std::string lowered;
  lowered.reserve(host.size());
  for (unsigned char c : host) {
    lowered.push_back(static_cast<char>(std::tolower(c)));
  }
  if (lowered == "localhost" || host == "::1") {
    return ResolverScope::kLocal;
  }
  int a = 0;
  int b = 0;
  int c = 0;
  int d = 0;
  if (std::sscanf(std::string(host).c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return ResolverScope::kPublic;
  }
  if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) {
    return ResolverScope::kPublic;
  }
  if (a == 127) {
    return ResolverScope::kLocal;
  }
  if (a == 10) {
    return ResolverScope::kLan;
  }
  if (a == 172 && b >= 16 && b <= 31) {
    return ResolverScope::kLan;
  }
  if (a == 192 && b == 168) {
    return ResolverScope::kLan;
  }
  return ResolverScope::kPublic;
}

CliOptions ParseOptions(int argc, char** argv) {
  CliOptions opts;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--network") {
      if (++i >= argc) throw std::runtime_error("missing value for --network");
      opts.network = argv[i];
    } else if (arg == "--rpc-host") {
      if (++i >= argc) throw std::runtime_error("missing value for --rpc-host");
      opts.rpc_host = argv[i];
    } else if (arg == "--rpc-port") {
      if (++i >= argc) throw std::runtime_error("missing value for --rpc-port");
      opts.rpc_port = static_cast<std::uint16_t>(std::stoi(argv[i]));
      opts.rpc_port_explicit = true;
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
    } else if (arg == "--raw") {
      opts.raw = true;
    } else if (arg == "--help" || arg == "-h") {
      PrintUsage();
      std::exit(0);
    } else {
      opts.args.emplace_back(arg);
    }
  }
  return opts;
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

std::optional<std::string> ResolveBasicAuth(const CliOptions& opts) {
  if (!opts.rpc_user.empty() || !opts.rpc_pass.empty()) {
    if (opts.rpc_user.empty() || opts.rpc_pass.empty()) {
      throw std::runtime_error("--rpc-user and --rpc-pass must be set together");
    }
    const std::string creds = opts.rpc_user + ":" + opts.rpc_pass;
    return Base64Encode(creds);
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
      throw std::runtime_error("unable to read RPC auth cookie at " + cookie_path.string() +
                               " (run qrypt-cli as the qryptcoin user or pass --rpc-user/--rpc-pass)");
    }
    return std::nullopt;
  }
  std::string cookie_line;
  std::getline(in, cookie_line);
  cookie_line.erase(std::remove_if(cookie_line.begin(), cookie_line.end(),
                                   [](unsigned char c) { return c == '\r' || c == '\n'; }),
                    cookie_line.end());
  if (cookie_line.empty()) {
    return std::nullopt;
  }
  return Base64Encode(cookie_line);
}

qryptcoin::net::TcpSocket ConnectToRpc(const CliOptions& opts) {
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

nlohmann::json CallRpc(const CliOptions& opts, const nlohmann::json& request) {
  qryptcoin::net::TcpSocket socket = ConnectToRpc(opts);
  const auto payload = request.dump();

  const auto basic_auth = ResolveBasicAuth(opts);

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
      body_offset = FindHeaderEnd(response);
      if (body_offset) {
        auto headers = std::string_view(response.data(), *body_offset - 4);
        auto length = ParseContentLength(headers);
        if (!length) {
          throw std::runtime_error("missing Content-Length");
        }
        content_length = *length;
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

std::pair<std::string, std::uint16_t> ParseHostPort(std::string_view input) {
  const auto pos = input.rfind(':');
  if (pos == std::string_view::npos || pos == 0 || pos + 1 >= input.size()) {
    throw std::runtime_error("resolver must be in host:port form");
  }
  std::string host(input.substr(0, pos));
  const unsigned long port = std::stoul(std::string(input.substr(pos + 1)));
  if (port == 0 || port > 65535) {
    throw std::runtime_error("resolver port out of range");
  }
  return {host, static_cast<std::uint16_t>(port)};
}

nlohmann::json CallJsonRpcOnce(const std::string& host, std::uint16_t port,
                              const nlohmann::json& request, int timeout_ms) {
  constexpr std::size_t kMaxResolverResponseHeaderSize = 16 * 1024;
  constexpr std::size_t kMaxResolverResponseBodySize = 16 * 1024;

  qryptcoin::net::TcpSocket socket;
  if (!socket.Connect(host, port)) {
    throw std::runtime_error("failed to connect to resolver");
  }
  if (timeout_ms > 0) {
    (void)socket.SetTimeout(timeout_ms);
  }
  const auto payload = request.dump();
  const auto http = BuildHttpRequest(host, port, payload, /*basic_auth=*/std::nullopt);
  if (socket.Send(reinterpret_cast<const std::uint8_t*>(http.data()), http.size()) <= 0) {
    throw std::runtime_error("failed to send resolver request");
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
      if (response.size() > kMaxResolverResponseHeaderSize) {
        throw std::runtime_error("resolver response headers too large");
      }
      body_offset = FindHeaderEnd(response);
      if (body_offset) {
        auto headers = std::string_view(response.data(), *body_offset - 4);
        auto length = ParseContentLength(headers);
        if (!length) {
          throw std::runtime_error("missing resolver Content-Length");
        }
        if (*length < 0) {
          throw std::runtime_error("invalid resolver Content-Length");
        }
        if (static_cast<std::size_t>(*length) > kMaxResolverResponseBodySize) {
          throw std::runtime_error("resolver response too large");
        }
        content_length = *length;
      }
    } else if (body_offset) {
      if (response.size() > *body_offset + kMaxResolverResponseBodySize) {
        throw std::runtime_error("resolver response too large");
      }
    }
    if (body_offset && response.size() >= *body_offset + static_cast<std::size_t>(content_length)) {
      break;
    }
  }
  if (!body_offset || content_length < 0) {
    throw std::runtime_error("invalid resolver response");
  }
  std::string body = response.substr(*body_offset, content_length);
  return nlohmann::json::parse(body);
}

std::string NextId() {
  static std::uint64_t counter = 0;
  std::ostringstream oss;
  oss << "cli-" << ++counter;
  return oss.str();
}

nlohmann::json BuildRequest(const CliOptions& opts) {
  if (opts.args.empty()) {
    throw std::runtime_error("missing command");
  }
  const auto command = opts.args.front();
  std::string method = command;
  nlohmann::json params = nlohmann::json::object();
  auto find_option = [&](std::string_view name) -> std::optional<std::string> {
    return FindPrefixedOptionValue(opts.args, name);
  };
  if (command == "getblockchaininfo" || command == "getpqinfo" ||
      command == "getnetworkinfo" || command == "getblockcount" ||
      command == "getbestblockhash" || command == "getmempoolinfo" ||
      command == "getrawmempool" || command == "getmininginfo" ||
      command == "getpeerinfo" || command == "listutxos" ||
      command == "getaddednodeinfo" || command == "listdnsseeds" ||
      command == "refreshdnsseeds" ||
      command == "health") {
    if (command == "health") {
      method = "gethealth";
    }
    // no params
  } else if (command == "getblock") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("getblock requires hash or height");
    }
    const auto& target = opts.args[1];
    bool numeric = !target.empty() && std::all_of(target.begin(), target.end(),
                                                  [](char c) { return std::isdigit(static_cast<unsigned char>(c)); });
    if (numeric) {
      params["height"] = std::stoull(target);
    } else {
      params["hash"] = target;
    }
    for (std::size_t i = 2; i < opts.args.size(); ++i) {
      if (opts.args[i].rfind("--verbosity=", 0) == 0) {
        params["verbosity"] = std::stoi(opts.args[i].substr(12));
      }
    }
  } else if (command == "getmempoolentry") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("getmempoolentry requires <txid>");
    }
    params["txid"] = opts.args[1];
  } else if (command == "getnewaddress") {
    // no params
  } else if (command == "getpaymentcode") {
    // no params
  } else if (command == "validatepaymentcode" || command == "resolvepaymentcode") {
    if (opts.args.size() < 2) {
      throw std::runtime_error(command + " requires <code>");
    }
    params["payment_code"] = opts.args[1];
  } else if (command == "sendtoaddress") {
    if (opts.args.size() < 3) {
      throw std::runtime_error("sendtoaddress requires <address> <amount>");
    }
    params["address"] = opts.args[1];
    params["amount"] = opts.args[2];
    for (std::size_t i = 3; i < opts.args.size(); ++i) {
      if (opts.args[i].rfind("--fee-rate=", 0) == 0) {
        params["fee_rate"] = std::stoull(opts.args[i].substr(11));
      }
    }
  } else if (command == "getwalletinfo" || command == "listaddresses" ||
             command == "listwatchonly") {
    // no params
  } else if (command == "listtransactions") {
    if (opts.args.size() >= 2) {
      params["count"] = std::stoi(opts.args[1]);
    }
  } else if (command == "createwallet") {
    auto path_opt = find_option("--wallet-path=");
    if (!path_opt) {
      throw std::runtime_error("createwallet requires --wallet-path");
    }
    params["wallet_path"] = *path_opt;

    const auto passphrase =
        ReadSecretFromArgs(opts.args, "--passphrase=", "--passphrase-stdin",
                           "--passphrase-file=", "wallet passphrase",
                           /*required=*/true, /*hidden=*/true);
    params["passphrase"] = *passphrase;

    if (auto name_opt = find_option("--wallet-name=")) {
      params["wallet_name"] = *name_opt;
    }
    if (const auto mnemonic = ReadSecretFromArgs(
            opts.args, "--mnemonic=", "--mnemonic-stdin", "--mnemonic-file=",
            "mnemonic", /*required=*/false, /*hidden=*/false)) {
      params["mnemonic"] = *mnemonic;
    }
    if (const auto mpass = ReadSecretFromArgs(
            opts.args, "--mnemonic-passphrase=", "--mnemonic-passphrase-stdin",
            "--mnemonic-passphrase-file=", "mnemonic passphrase",
            /*required=*/false, /*hidden=*/true)) {
      params["mnemonic_passphrase"] = *mpass;
    }
  } else if (command == "loadwallet") {
    auto path_opt = find_option("--path=");
    if (!path_opt) {
      throw std::runtime_error("loadwallet requires --path");
    }
    params["path"] = *path_opt;
    if (const auto passphrase =
            ReadSecretFromArgs(opts.args, "--passphrase=", "--passphrase-stdin",
                               "--passphrase-file=", "wallet passphrase",
                               /*required=*/false, /*hidden=*/true)) {
      params["passphrase"] = *passphrase;
    }
  } else if (command == "backupwallet") {
    auto dest_opt = find_option("--destination=");
    if (!dest_opt) {
      throw std::runtime_error("backupwallet requires --destination");
    }
    params["destination"] = *dest_opt;
  } else if (command == "encryptwallet") {
    const auto passphrase =
        ReadSecretFromArgs(opts.args, "--passphrase=", "--passphrase-stdin",
                           "--passphrase-file=", "wallet passphrase",
                           /*required=*/true, /*hidden=*/true);
    params["passphrase"] = *passphrase;
  } else if (command == "walletlock") {
    // no params
  } else if (command == "walletpassphrase") {
    const auto passphrase =
        ReadSecretFromArgs(opts.args, "--passphrase=", "--passphrase-stdin",
                           "--passphrase-file=", "wallet passphrase",
                           /*required=*/true, /*hidden=*/true);
    params["passphrase"] = *passphrase;
  } else if (command == "forgetaddresses") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("forgetaddresses requires at least one address");
    }
    nlohmann::json addrs = nlohmann::json::array();
    for (std::size_t i = 1; i < opts.args.size(); ++i) {
      addrs.push_back(opts.args[i]);
    }
    params["addresses"] = addrs;
  } else if (command == "importaddress") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("importaddress requires <address>");
    }
    params["address"] = opts.args[1];
    bool rescan = true;
    for (std::size_t i = 2; i < opts.args.size(); ++i) {
      if (opts.args[i] == "--no-rescan") {
        rescan = false;
      }
    }
    params["rescan"] = rescan;
  } else if (command == "removewatchonly") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("removewatchonly requires at least one address");
    }
    nlohmann::json addrs = nlohmann::json::array();
    for (std::size_t i = 1; i < opts.args.size(); ++i) {
      addrs.push_back(opts.args[i]);
    }
    params["addresses"] = addrs;
  } else if (command == "generate") {
    int blocks = 1;
    if (opts.args.size() >= 2) {
      blocks = std::stoi(opts.args[1]);
    }
    params["blocks"] = blocks;
  } else if (command == "generatetoaddress") {
    if (opts.args.size() < 3) {
      throw std::runtime_error("generatetoaddress requires <blocks> <address>");
    }
    params["blocks"] = std::stoi(opts.args[1]);
    params["address"] = opts.args[2];
  } else if (command == "getblocktemplate") {
    if (auto addr_opt = find_option("--address=")) {
      params["address"] = *addr_opt;
    }
  } else if (command == "submitblock") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("submitblock requires <hex>");
    }
    params["hex"] = opts.args[1];
  } else if (command == "estimatesmartfee") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("estimatesmartfee requires <target_blocks>");
    }
    params["target_blocks"] = std::stoul(opts.args[1]);
  } else if (command == "decoderawtransaction") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("decoderawtransaction requires <hex>");
    }
    params["hex"] = opts.args[1];
  } else if (command == "sendrawtransaction") {
    if (opts.args.size() < 2) {
      throw std::runtime_error("sendrawtransaction requires <hex>");
    }
    params["hex"] = opts.args[1];
  } else if (command == "addnode") {
    std::optional<std::string> addr_opt = find_option("--address=");
    if (!addr_opt && opts.args.size() >= 2) {
      addr_opt = opts.args[1];
    }
    if (!addr_opt || addr_opt->empty()) {
      throw std::runtime_error("addnode requires <address[:port]> or --address=<address[:port]>");
    }
    params["address"] = *addr_opt;
  } else if (command == "disconnectnode") {
    std::optional<std::string> id_opt = find_option("--id=");
    if (!id_opt && opts.args.size() >= 2) {
      id_opt = opts.args[1];
    }
    if (!id_opt || id_opt->empty()) {
      throw std::runtime_error("disconnectnode requires <id> or --id=<id>");
    }
    params["id"] = std::stoull(*id_opt);
  } else if (command == "createrawtransaction") {
    auto inputs_opt = find_option("--inputs=");
    auto outputs_opt = find_option("--outputs=");
    if (!inputs_opt || !outputs_opt) {
      throw std::runtime_error(
          "createrawtransaction requires --inputs=<json> and --outputs=<json>");
    }
    try {
      params["inputs"] = nlohmann::json::parse(*inputs_opt);
      params["outputs"] = nlohmann::json::parse(*outputs_opt);
    } catch (const std::exception& ex) {
      throw std::runtime_error(std::string("failed to parse inputs/outputs JSON: ") + ex.what());
    }
    if (auto lock_opt = find_option("--locktime=")) {
      params["lock_time"] = std::stoul(*lock_opt);
    }
  } else {
    throw std::runtime_error("unknown command: " + command);
  }
  nlohmann::json request = {
      {"jsonrpc", "2.0"},
      {"id", NextId()},
      {"method", method},
      {"params", params},
  };
  return request;
}

nlohmann::json HandleSendTo(const CliOptions& opts) {
  if (opts.args.size() < 3) {
    throw std::runtime_error("sendto requires <paycode-or-address> <amount>");
  }

  const std::string destination = opts.args[1];
  const std::string amount = opts.args[2];

  std::optional<std::uint64_t> fee_rate;
  std::string resolver_policy = "local-only";
  bool allow_insecure_resolver = HasFlag(opts.args, "--allow-insecure-resolver");
  bool allow_lan_resolver = HasFlag(opts.args, "--allow-lan-resolver");
  int resolver_timeout_ms = 5000;
  int resolver_max_retries = 1;
  for (std::size_t i = 3; i < opts.args.size(); ++i) {
    if (opts.args[i].rfind("--fee-rate=", 0) == 0) {
      fee_rate = std::stoull(opts.args[i].substr(11));
    }
  }
  if (auto policy_opt = FindPrefixedOptionValue(opts.args, "--resolver-policy=")) {
    resolver_policy = *policy_opt;
  }
  if (auto timeout_opt = FindPrefixedOptionValue(opts.args, "--resolver-timeout-ms=")) {
    const long parsed = std::stol(*timeout_opt);
    if (parsed < 100 || parsed > 600000) {
      throw std::runtime_error("--resolver-timeout-ms out of range (100..600000)");
    }
    resolver_timeout_ms = static_cast<int>(parsed);
  }
  if (auto retries_opt = FindPrefixedOptionValue(opts.args, "--resolver-max-retries=")) {
    const long parsed = std::stol(*retries_opt);
    if (parsed < 0 || parsed > 10) {
      throw std::runtime_error("--resolver-max-retries out of range (0..10)");
    }
    resolver_max_retries = static_cast<int>(parsed);
  }
  const bool policy_lan_ok = resolver_policy == "lan-ok" || resolver_policy == "insecure-ok";
  const bool policy_insecure_ok = resolver_policy == "insecure-ok";
  if (resolver_policy != "local-only" && !policy_lan_ok && !policy_insecure_ok) {
    throw std::runtime_error("invalid --resolver-policy (use local-only, lan-ok, or insecure-ok)");
  }

  const auto resolver_opt = FindPrefixedOptionValue(opts.args, "--resolver=");
  const auto& cfg = qryptcoin::config::GetNetworkConfig();

  qryptcoin::crypto::PaymentCodeV1 paycode{};
  std::string paycode_error;
  const bool is_paycode =
      qryptcoin::crypto::DecodePaymentCodeV1(destination, cfg.bech32_hrp, &paycode, &paycode_error);

  std::string address = destination;
  if (is_paycode) {
    if (!resolver_opt) {
      throw std::runtime_error("sendto: --resolver=<host:port> is required for payment codes");
    }
    const auto [resolver_host, resolver_port] = ParseHostPort(*resolver_opt);

    const auto scope = ClassifyResolverHost(resolver_host);
    const bool allow_lan = allow_lan_resolver || policy_lan_ok || policy_insecure_ok;
    const bool allow_public = allow_insecure_resolver || policy_insecure_ok;
    if (scope == ResolverScope::kLan && !allow_lan) {
      throw std::runtime_error(
          "refusing resolver outside localhost; use --allow-lan-resolver or "
          "--resolver-policy=lan-ok");
    }
    if (scope == ResolverScope::kPublic && !allow_public) {
      throw std::runtime_error(
          "refusing insecure remote resolver; use --allow-insecure-resolver or "
          "--resolver-policy=insecure-ok");
    }
    if (scope != ResolverScope::kLocal) {
      std::cerr << "warning: resolver " << resolver_host << ":" << resolver_port
                << " is unauthenticated HTTP and can redirect payments; prefer localhost or an authenticated secure channel\n";
    }

    constexpr std::uint32_t kExpiryDeltaBlocks = 12;

    auto get_sender_height = [&]() -> std::uint64_t {
      nlohmann::json height_req = {
          {"jsonrpc", "2.0"},
          {"id", NextId()},
          {"method", "getblockcount"},
          {"params", nlohmann::json::object()},
      };
      const auto height_resp = CallRpc(opts, height_req);
      if (height_resp.contains("error")) {
        throw std::runtime_error("unable to query local node height: " + height_resp.at("error").dump());
      }
      if (!height_resp.contains("result")) {
        throw std::runtime_error("unable to query local node height: missing result");
      }
      return height_resp.at("result").get<std::uint64_t>();
    };

    std::string resolved_address;
    std::uint64_t resolved_issued_height = 0;
    std::uint64_t resolved_expiry_height = 0;
    for (int attempt = 0; attempt <= resolver_max_retries; ++attempt) {
      std::array<std::uint8_t, 16> challenge{};
      std::string rng_error;
      if (!qryptcoin::util::FillSecureRandomBytes(std::span<std::uint8_t>(challenge), &rng_error)) {
        throw std::runtime_error(rng_error.empty() ? "secure randomness unavailable" : rng_error);
      }
      const std::string challenge_b64 = Base64Encode(std::string_view(
          reinterpret_cast<const char*>(challenge.data()), challenge.size()));
      const std::uint64_t now_unix =
          static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count());

      nlohmann::json resolve_req = {
          {"jsonrpc", "2.0"},
          {"id", NextId()},
          {"method", "resolvepaymentcode"},
          {"params",
           {{"payment_code", destination},
            {"challenge_b64", challenge_b64},
            {"client_time_unix", now_unix},
            {"requested_expiry_delta_blocks", kExpiryDeltaBlocks}}},
      };
      nlohmann::json resolve_resp;
      try {
        resolve_resp =
            CallJsonRpcOnce(resolver_host, resolver_port, resolve_req, resolver_timeout_ms);
      } catch (const std::exception&) {
        if (attempt < resolver_max_retries) {
          continue;
        }
        throw;
      }
      if (resolve_resp.contains("error")) {
        throw std::runtime_error("resolver error: " + resolve_resp.at("error").dump());
      }
      if (!resolve_resp.contains("result") || !resolve_resp.at("result").is_object()) {
        throw std::runtime_error("resolver response missing result object");
      }
      const auto& result = resolve_resp.at("result");
      if (!result.contains("address")) {
        throw std::runtime_error("resolver response missing result.address");
      }
      if (!result.contains("challenge_b64") || !result.at("challenge_b64").is_string()) {
        throw std::runtime_error("resolver response missing result.challenge_b64");
      }
      const std::string resp_challenge = result.at("challenge_b64").get<std::string>();
      if (resp_challenge != challenge_b64) {
        throw std::runtime_error("resolver response challenge mismatch");
      }
      if (!result.contains("issued_height") || !result.contains("expiry_height")) {
        throw std::runtime_error("resolver response missing issued/expiry height");
      }
      const std::uint64_t issued_height = result.at("issued_height").get<std::uint64_t>();
      const std::uint64_t expiry_height = result.at("expiry_height").get<std::uint64_t>();
      if (expiry_height < issued_height) {
        throw std::runtime_error("resolver response has invalid expiry_height");
      }

      const std::uint64_t sender_height = get_sender_height();
      if (sender_height > expiry_height + 1) {
        if (attempt < resolver_max_retries) {
          continue;
        }
        throw std::runtime_error("resolver response expired; retry resolution");
      }

      resolved_address = result.at("address").get<std::string>();
      resolved_issued_height = issued_height;
      resolved_expiry_height = expiry_height;
      qryptcoin::crypto::P2QHDescriptor desc{};
      if (!qryptcoin::crypto::DecodeP2QHAddress(resolved_address, cfg.bech32_hrp, &desc)) {
        throw std::runtime_error("resolver returned invalid address");
      }
      break;
    }

    address = resolved_address;
    std::cerr << "paycode_resolved"
              << " paycode=" << destination
              << " address=" << address
              << " expiry_height=" << resolved_expiry_height
              << " resolver_policy=" << resolver_policy
              << " resolver=" << resolver_host << ":" << resolver_port
              << "\n";
  } else {
    // If it is not a payment code, treat it as a normal address.
    qryptcoin::crypto::P2QHDescriptor desc{};
    if (!qryptcoin::crypto::DecodeP2QHAddress(address, cfg.bech32_hrp, &desc)) {
      if (!paycode_error.empty()) {
        throw std::runtime_error("invalid destination: " + paycode_error);
      }
      throw std::runtime_error("invalid destination (not a payment code or address)");
    }
  }

  nlohmann::json params = {{"address", address}, {"amount", amount}};
  if (fee_rate.has_value()) {
    params["fee_rate"] = *fee_rate;
  }
  nlohmann::json send_req = {
      {"jsonrpc", "2.0"},
      {"id", NextId()},
      {"method", "sendtoaddress"},
      {"params", params},
  };
  return CallRpc(opts, send_req);
}

void PrintResponse(const CliOptions& opts, const nlohmann::json& response) {
  if (opts.raw) {
    std::cout << response.dump(2) << "\n";
    return;
  }
  if (response.contains("error")) {
    std::cerr << "error: " << response["error"].dump() << "\n";
    return;
  }
  const std::string command = opts.args.empty() ? std::string{} : opts.args.front();
  if (command == "health") {
    const auto& result = response.at("result");
    const auto& chain = result.at("chain");
    const auto& mempool = result.at("mempool");
    const auto& peers = result.at("peers");
    bool ok = result.value("ok", true);

    std::cout << "chain: " << chain.value("chain", std::string{"?"})
              << " height=" << chain.value("blocks", 0ULL)
              << " headers=" << chain.value("headers", 0ULL)
              << " tip_age_s=" << chain.value("tip_age_seconds", 0ULL)
              << " ibd=" << (chain.value("initial_block_download", false) ? "true" : "false")
              << "\n";

    std::cout << "peers: total=" << peers.value("total", 0ULL)
              << " inbound=" << peers.value("inbound", 0ULL)
              << " outbound=" << peers.value("outbound", 0ULL)
              << "\n";

    std::cout << "mempool: size=" << mempool.value("size", 0ULL)
              << " bytes=" << mempool.value("bytes", 0ULL)
              << " minfee=" << mempool.value("mempoolminfee", 0.0)
              << "\n";

    std::cout << "status: " << (ok ? "OK" : "WARN") << "\n";
    const auto& warnings = result.at("warnings");
    if (!warnings.empty()) {
      std::cout << "warnings:\n";
      for (const auto& w : warnings) {
        std::cout << "  - " << w.get<std::string>() << "\n";
      }
    }
  } else {
    std::cout << response["result"].dump(2) << "\n";
  }
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
    if (!opts.args.empty() && opts.args.front() == "sendto") {
      auto response = HandleSendTo(opts);
      PrintResponse(opts, response);
    } else {
      auto request = BuildRequest(opts);
      auto response = CallRpc(opts, request);
      PrintResponse(opts, response);
    }
  } catch (const std::exception& ex) {
    std::cerr << "qrypt-cli: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}
