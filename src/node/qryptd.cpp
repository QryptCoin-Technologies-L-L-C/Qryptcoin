#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#endif

#include "config/build_info.hpp"
#include "config/network.hpp"
#include "nlohmann/json.hpp"
#include "net/addr_manager.hpp"
#include "net/messages.hpp"
#include "net/peer_manager.hpp"
#include "net/socket.hpp"
#include "net/upnp.hpp"
#include "node/block_sync.hpp"
#include "node/chain_state.hpp"
#include "rpc/http_server.hpp"
#include "rpc/server.hpp"
#include "util/csprng.hpp"
#include "wallet/hd_wallet.hpp"

namespace {

std::string FormatTimestamp() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t time = std::chrono::system_clock::to_time_t(now);
  std::tm tm_buf{};
#ifdef _WIN32
  localtime_s(&tm_buf, &time);
#else
  localtime_r(&time, &tm_buf);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
  return oss.str();
}

std::string GenerateRpcSecretHex(std::size_t bytes = 24) {
  const auto secret = qryptcoin::util::SecureRandomBytes(bytes);
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : secret) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

bool HardenRpcCookieFile(const std::filesystem::path& path, std::string* warning) {
  if (warning) {
    warning->clear();
  }
#ifdef _WIN32
  // std::filesystem::permissions does not reliably enforce Windows ACLs, so set a
  // best-effort protected DACL: owner + local system full access, no inheritance.
  PSECURITY_DESCRIPTOR sd = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;FA;;;OW)(A;;FA;;;SY)", SDDL_REVISION_1, &sd, nullptr)) {
    if (warning) {
      *warning = "failed to build Windows security descriptor (RPC cookie may be readable by other users)";
    }
    return false;
  }
  const std::wstring wpath = path.wstring();
  const BOOL ok = SetFileSecurityW(wpath.c_str(), DACL_SECURITY_INFORMATION, sd);
  LocalFree(sd);
  if (!ok) {
    if (warning) {
      *warning = "failed to apply Windows ACL to RPC cookie (RPC cookie may be readable by other users)";
    }
    return false;
  }
  return true;
#else
  std::error_code ec;
  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace, ec);
  if (ec) {
    if (warning) {
      *warning = "failed to set RPC cookie permissions";
    }
    return false;
  }
  return true;
#endif
}

enum class LogLevel {
  kDebug = 0,
  kInfo = 1,
  kWarn = 2,
  kError = 3,
};

const char* LogLevelName(LogLevel level) {
  switch (level) {
    case LogLevel::kDebug:
      return "DEBUG";
    case LogLevel::kInfo:
      return "INFO";
    case LogLevel::kWarn:
      return "WARN";
    case LogLevel::kError:
      return "ERROR";
  }
  return "UNKNOWN";
}

LogLevel ParseLogLevelString(const std::string& value) {
  std::string lower;
  lower.reserve(value.size());
  for (char c : value) {
    lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  if (lower == "debug") {
    return LogLevel::kDebug;
  }
  if (lower == "info") {
    return LogLevel::kInfo;
  }
  if (lower == "warn" || lower == "warning") {
    return LogLevel::kWarn;
  }
  if (lower == "error") {
    return LogLevel::kError;
  }
  throw std::runtime_error("invalid log level: " + value);
}

class DebugLogger {
 public:
  void Enable(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stream_.is_open()) {
      stream_.close();
    }
    path_ = path;
    const auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) {
      std::error_code ec;
      std::filesystem::create_directories(parent, ec);
    }
    stream_.open(path, std::ios::app);
    if (!stream_) {
      throw std::runtime_error("failed to open debug log: " + path);
    }
    current_size_ = 0;
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (!ec) {
      current_size_ = size;
    }
    const std::string header =
        "---- qryptd debug log started " + FormatTimestamp() + " ----\n";
    stream_ << header;
    stream_.flush();
    current_size_ += static_cast<std::uintmax_t>(header.size());
  }

  void Configure(LogLevel level, std::uintmax_t max_bytes, std::size_t max_files) {
    std::lock_guard<std::mutex> lock(mutex_);
    level_threshold_ = level;
    max_bytes_ = max_bytes;
    max_files_ = max_files;
  }

  void Log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!stream_.is_open()) {
      return;
    }
    if (static_cast<int>(level) < static_cast<int>(level_threshold_)) {
      return;
    }
    if (max_bytes_ > 0 && current_size_ >= max_bytes_) {
      RotateLocked();
    }
    std::ostringstream line;
    line << "[" << FormatTimestamp() << "] [" << LogLevelName(level) << "] " << message
         << '\n';
    const std::string text = line.str();
    stream_ << text;
    stream_.flush();
    current_size_ += static_cast<std::uintmax_t>(text.size());
  }

  void Log(const std::string& message) { Log(LogLevel::kDebug, message); }

  bool Enabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stream_.is_open();
  }

 private:
  void RotateLocked() {
    if (path_.empty() || max_bytes_ == 0 || max_files_ == 0) {
      return;
    }
    stream_.close();
    // Rotate existing files: logfile.(n-1) -> logfile.n
    for (std::size_t i = max_files_; i > 0; --i) {
      std::filesystem::path rotated =
          std::filesystem::path(path_).concat("." + std::to_string(i));
      std::filesystem::path previous =
          (i == 1) ? std::filesystem::path(path_)
                   : std::filesystem::path(path_).concat("." + std::to_string(i - 1));
      std::error_code ec;
      if (std::filesystem::exists(previous, ec)) {
        std::filesystem::rename(previous, rotated, ec);
      }
    }
    // Re-open the active log file.
    stream_.open(path_, std::ios::trunc);
    current_size_ = 0;
  }

  mutable std::mutex mutex_;
  std::ofstream stream_;
  std::string path_;
  LogLevel level_threshold_{LogLevel::kDebug};
  std::uintmax_t max_bytes_{0};
  std::size_t max_files_{0};
  std::uintmax_t current_size_{0};
};

DebugLogger g_debug_logger;

void LogDebug(const std::string& message) { g_debug_logger.Log(message); }

std::atomic<bool> g_shutdown_requested{false};

void RequestShutdown() {
  bool expected = false;
  if (g_shutdown_requested.compare_exchange_strong(expected, true)) {
    if (g_debug_logger.Enabled()) {
      LogDebug("Shutdown requested");
    }
  }
}

bool ShutdownRequested() { return g_shutdown_requested.load(); }

void HandleSignal(int) {
  // Keep signal handler minimal and async-signal-safe.
  g_shutdown_requested.store(true);
}

void InstallSignalHandlers() {
  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);
}

struct Options {
  std::string network{"mainnet"};
  std::string data_dir;
  std::string blocks_path;
  std::string utxo_path;
  std::string wallet_path;
  bool wallet_path_explicit{false};
  std::string wallet_pass;
  std::string wallet_pass_env;
  bool disable_wallet{false};
  bool no_wallet_autoload{false};
  std::string rpc_bind{"127.0.0.1"};
  std::uint16_t rpc_port{0};
  bool rpc_port_explicit{false};
  std::string rpc_user;
  std::string rpc_pass;
  std::string rpc_pass_env;
  std::vector<std::string> rpc_allow;
  bool unsafe_allow_remote{false};
  bool rpc_require_auth{true};
  bool rpc_read_only{false};
  std::uint16_t p2p_port{0};
  bool p2p_port_explicit{false};
  bool listen_enabled{true};
  std::string mining_address;
  bool allow_generate{false};
  std::vector<std::string> connect_peers;
  std::string debug_log_path;
  std::string log_level{"debug"};
  std::size_t log_max_size_mb{0};
  std::size_t log_max_files{0};
  std::string config_path;
  bool disable_config_file{false};
  std::size_t mempool_limit_mb{300};
  std::uint64_t mempool_expiry_seconds{14ULL * 24ULL * 60ULL * 60ULL};
  std::uint64_t mempool_rebroadcast_seconds{30ULL * 60ULL};
  bool mempool_persist{true};
  std::string mempool_persist_path;
  std::uint64_t mempool_persist_interval_seconds{60};
  double fee_estimator_decay{0.95};
  std::size_t fee_estimator_samples{512};
  std::uint32_t rpc_gbt_rate{5};
  std::uint32_t rpc_submit_rate{10};
  bool enable_upnp{false};
  bool seed_node{false};
  bool require_encryption{false};
  bool require_authenticated_transport{false};
  bool require_authenticated_transport_explicit{false};
  bool allow_private_peers{false};
  std::vector<std::string> extra_static_seeds;
  // Peer limits (0 = use defaults).
  std::size_t max_inbound_peers{0};
  std::size_t max_outbound_peers{0};
  std::size_t max_total_peers{0};
  // Target number of outbound connections to actively maintain.
  // Default: 10 (8 full-relay + 2 block-relay-only).
  std::size_t target_outbound_peers{10};
};

void PrintUsage() {
  std::cout << "qryptd options:\n"
             << "  --network <net>            mainnet, testnet, regtest, signet (default: mainnet)\n"
             << "  --data-dir <path>          Base data directory (default: data/<network>)\n"
             << "  --wallet <path>            Wallet file path (default: <data>/wallet.dat)\n"
             << "  --wallet-pass <passphrase> Wallet passphrase (insecure on shared shells)\n"
             << "  --wallet-pass-env <name>   Environment variable with the wallet passphrase\n"
             << "  --disable-wallet           Disable wallet loading and wallet RPCs\n"
             << "  --no-wallet-autoload       Do not auto-load/create a wallet at startup (wallet RPC remains enabled)\n"
             << "  --rpc-bind <addr>          RPC bind address (default: 127.0.0.1)\n"
             << "  --rpc-port <port>          RPC port (default: network-specific)\n"
             << "  --rpc-user <name>          RPC basic auth user\n"
             << "  --rpc-pass <secret>        RPC basic auth password (use env or prompt if possible)\n"
             << "  --rpc-pass-env <name>      Env var containing the RPC password\n"
             << "  --rpc-allow-ip <addr>      Allow specific client IP (repeatable). Default: loopback only\n"
             << "  --unsafe-allow-remote      Permit non-loopback RPC binds (requires auth + allowlist)\n"
             << "  --rpc-require-auth         Require HTTP basic auth for RPC (default: on)\n"
             << "  --rpc-read-only           Restrict RPC to non-mutating, read-only methods\n"
             << "  --rpc-gbt-rate <n>         Max getblocktemplate RPCs per second (0=unlimited, default: 5)\n"
             << "  --rpc-submit-rate <n>      Max submitblock RPCs per second (0=unlimited, default: 10)\n"
             << "  --p2p-port <port>          P2P listen port override\n"
             << "  --nolisten                 Disable inbound P2P connections (outbound-only)\n"
             << "  --listen <0|1>             Enable/disable inbound P2P (default: 1)\n"
             << "  --mining-address <qry1...> Default reward address for getblocktemplate\n"
             << "  --connect-peer <host:port> Manually connect to a specific peer (repeatable)\n"
             << "  --max-inbound-peers <n>    Override inbound peer limit (0=default)\n"
             << "  --max-outbound-peers <n>   Override outbound peer limit (0=default)\n"
             << "  --max-total-peers <n>      Override total peer limit (0=default)\n"
             << "  --mempool-limit-mb <mb>    Target mempool size limit in MB (default: 300)\n"
             << "  --mempool-expiry-seconds <sec> Evict mempool txs older than <sec> (0=disable, default: 1209600)\n"
             << "  --mempool-rebroadcast-seconds <sec> Re-announce mempool txids every <sec> (0=disable, default: 1800)\n"
             << "  --mempool-persist          Persist mempool to disk (default: on)\n"
             << "  --no-mempool-persist       Disable mempool persistence\n"
            << "  --mempool-persist-path <path> Override persistence path (default: <data>/mempool.json)\n"
            << "  --mempool-persist-interval-seconds <sec> Flush persisted mempool every <sec> when dirty (0=disable, default: 60)\n"
            << "  --fee-estimator-decay <r>  Rolling fee estimator decay rate (0<r<1, default: 0.95)\n"
            << "  --fee-estimator-samples <n> Max confirmation samples to keep (default: 512)\n"
            << "  --allow-generate           Enable generate/generatetoaddress RPCs\n"
            << "  --enable-upnp              Attempt to map the P2P port via UPnP (optional)\n"
            << "  --seed-node                Treat this node as a public bootstrap seed (bind 0.0.0.0, prefer addr relay)\n"
            << "  --require-encryption       Require Kyber/AEAD transport (reject plaintext peers)\n"
            << "  --require-authenticated-transport  Require identity-authenticated encrypted transport (mainnet default)\n"
            << "  --no-require-authenticated-transport  Allow unauthenticated encrypted transport (NOT SAFE for mainnet)\n"
            << "  --allow-private-peers      Permit peers discovered via private/reserved IPs from DNS seeds\n"
            << "  --debug-log <path>         Append structured logs to the given file\n"
            << "  --log-level <lvl>          Log level: debug, info, warn, error (default: debug)\n"
            << "  --log-max-size-mb <mb>     Rotate debug log after approximately <mb> megabytes (0=disable)\n"
            << "  --log-max-files <n>        Number of rotated debug log files to keep (default: 0)\n"
            << "  --conf <path>              Load options from qryptcoin.conf (default: ./qryptcoin.conf)\n"
            << "  --no-conf                  Disable config file loading\n";
}

std::string Trim(const std::string& input) {
  const std::string whitespace = " \t\r\n";
  const auto first = input.find_first_not_of(whitespace);
  if (first == std::string::npos) {
    return {};
  }
  const auto last = input.find_last_not_of(whitespace);
  return input.substr(first, last - first + 1);
}

bool ParseBool(const std::string& value) {
  std::string lower;
  lower.reserve(value.size());
  for (char c : value) {
    lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  if (lower.empty()) {
    return true;
  }
  if (lower == "1" || lower == "true" || lower == "yes" || lower == "on") {
    return true;
  }
  if (lower == "0" || lower == "false" || lower == "no" || lower == "off") {
    return false;
  }
  throw std::runtime_error("invalid boolean value: " + value);
}

std::optional<std::string> GetEnvValue(std::string_view name) {
  std::string key(name);
  const char* value = std::getenv(key.c_str());
  if (!value || value[0] == '\0') {
    return std::nullopt;
  }
  return std::string(value);
}

void ApplyEnvironmentOverrides(Options* opts) {
  auto apply_string = [&](std::string_view name, std::string* target) {
    if (auto value = GetEnvValue(name)) {
      *target = std::move(*value);
    }
  };
  auto apply_string_explicit = [&](std::string_view name, std::string* target, bool* explicit_flag) {
    if (auto value = GetEnvValue(name)) {
      *target = std::move(*value);
      if (explicit_flag) {
        *explicit_flag = true;
      }
    }
  };
  auto apply_uint16 = [&](std::string_view name, std::uint16_t* target, bool* explicit_flag) {
    if (auto value = GetEnvValue(name)) {
      unsigned long parsed = 0;
      try {
        parsed = std::stoul(*value);
      } catch (const std::exception&) {
        throw std::runtime_error("invalid " + std::string(name) + " (expected 0-65535)");
      }
      if (parsed > 65535) {
        throw std::runtime_error("invalid " + std::string(name) + " (out of range)");
      }
      *target = static_cast<std::uint16_t>(parsed);
      if (explicit_flag) {
        *explicit_flag = true;
      }
    }
  };
  auto apply_bool = [&](std::string_view name, bool* target) {
    if (auto value = GetEnvValue(name)) {
      *target = ParseBool(*value);
    }
  };
  auto apply_bool_explicit = [&](std::string_view name, bool* target, bool* explicit_flag) {
    if (auto value = GetEnvValue(name)) {
      *target = ParseBool(*value);
      if (explicit_flag) {
        *explicit_flag = true;
      }
    }
  };

  apply_string("QRY_NETWORK", &opts->network);
  apply_string("QRY_DATA_DIR", &opts->data_dir);
  apply_string("QRY_BLOCKS_PATH", &opts->blocks_path);
  apply_string("QRY_UTXO_PATH", &opts->utxo_path);
  apply_string_explicit("QRY_WALLET_PATH", &opts->wallet_path, &opts->wallet_path_explicit);
  apply_string("QRY_WALLET_PASS", &opts->wallet_pass);
  apply_string("QRY_WALLET_PASS_ENV", &opts->wallet_pass_env);
  apply_bool("QRY_DISABLE_WALLET", &opts->disable_wallet);
  apply_bool("QRY_NO_WALLET_AUTOLOAD", &opts->no_wallet_autoload);

  apply_string("QRY_RPC_BIND", &opts->rpc_bind);
  apply_uint16("QRY_RPC_PORT", &opts->rpc_port, &opts->rpc_port_explicit);
  apply_string("QRY_RPC_USER", &opts->rpc_user);
  apply_string("QRY_RPC_PASS", &opts->rpc_pass);
  apply_string("QRY_RPC_PASS_ENV", &opts->rpc_pass_env);
  apply_bool("QRY_RPC_REQUIRE_AUTH", &opts->rpc_require_auth);
  apply_bool("QRY_RPC_READ_ONLY", &opts->rpc_read_only);

  apply_uint16("QRY_P2P_PORT", &opts->p2p_port, &opts->p2p_port_explicit);
  apply_string("QRY_MINING_ADDRESS", &opts->mining_address);
  apply_bool("QRY_ALLOW_GENERATE", &opts->allow_generate);
  apply_bool("QRY_SEED_NODE", &opts->seed_node);
  apply_bool("QRY_REQUIRE_ENCRYPTION", &opts->require_encryption);
  apply_bool_explicit("QRY_REQUIRE_AUTHENTICATED_TRANSPORT",
                      &opts->require_authenticated_transport,
                      &opts->require_authenticated_transport_explicit);
  apply_bool("QRY_ALLOW_PRIVATE_PEERS", &opts->allow_private_peers);
  apply_bool("QRY_UNSAFE_ALLOW_REMOTE", &opts->unsafe_allow_remote);
  if (auto value = GetEnvValue("QRY_MEMPOOL_LIMIT_MB")) {
    opts->mempool_limit_mb = static_cast<std::size_t>(std::stoul(*value));
  }
  if (auto value = GetEnvValue("QRY_MEMPOOL_EXPIRY_SECONDS")) {
    opts->mempool_expiry_seconds = static_cast<std::uint64_t>(std::stoull(*value));
  }
  if (auto value = GetEnvValue("QRY_MEMPOOL_REBROADCAST_SECONDS")) {
    opts->mempool_rebroadcast_seconds =
        static_cast<std::uint64_t>(std::stoull(*value));
  }
  apply_bool("QRY_MEMPOOL_PERSIST", &opts->mempool_persist);
  apply_string("QRY_MEMPOOL_PERSIST_PATH", &opts->mempool_persist_path);
  if (auto value = GetEnvValue("QRY_MEMPOOL_PERSIST_INTERVAL_SECONDS")) {
    opts->mempool_persist_interval_seconds =
        static_cast<std::uint64_t>(std::stoull(*value));
  }

  auto trim = [](std::string_view text) -> std::string_view {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
      text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
      text.remove_suffix(1);
    }
    return text;
  };

  // Optional manual peering override. This is equivalent to repeating
  // --connect-peer on the command line but easier to manage under systemd.
  if (auto value = GetEnvValue("QRY_CONNECT_PEER")) {
    auto v = trim(*value);
    if (!v.empty()) {
      opts->connect_peers.push_back(std::string(v));
    }
  }
  if (auto value = GetEnvValue("QRY_CONNECT_PEERS")) {
    std::string_view list = *value;
    while (!list.empty()) {
      auto sep = list.find(',');
      auto token = (sep == std::string_view::npos) ? list : list.substr(0, sep);
      token = trim(token);
      if (!token.empty()) {
        opts->connect_peers.push_back(std::string(token));
      }
      if (sep == std::string_view::npos) {
        break;
      }
      list.remove_prefix(sep + 1);
    }
  }

  apply_string("QRY_DEBUG_LOG", &opts->debug_log_path);
  apply_string("QRY_LOG_LEVEL", &opts->log_level);
  if (auto value = GetEnvValue("QRY_LOG_MAX_SIZE_MB")) {
    opts->log_max_size_mb = static_cast<std::size_t>(std::stoul(*value));
  }
  if (auto value = GetEnvValue("QRY_LOG_MAX_FILES")) {
    opts->log_max_files = static_cast<std::size_t>(std::stoul(*value));
  }

  // Peer connection limits (environment variable overrides).
  if (auto value = GetEnvValue("QRY_MAX_INBOUND_PEERS")) {
    opts->max_inbound_peers = static_cast<std::size_t>(std::stoul(*value));
  }
  if (auto value = GetEnvValue("QRY_MAX_OUTBOUND_PEERS")) {
    opts->max_outbound_peers = static_cast<std::size_t>(std::stoul(*value));
  }
  if (auto value = GetEnvValue("QRY_MAX_TOTAL_PEERS")) {
    opts->max_total_peers = static_cast<std::size_t>(std::stoul(*value));
  }
}

std::string NormalizeKey(std::string key) {
  std::string out;
  out.reserve(key.size());
  for (char c : key) {
    if (c == '-' || c == '_') {
      continue;
    }
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
}

void ApplyConfigOption(const std::string& raw_key, const std::string& value, Options* opts) {
  const std::string key = NormalizeKey(raw_key);
  if (key == "network") {
    opts->network = value;
  } else if (key == "datadir" || key == "datadirectory") {
    opts->data_dir = value;
  } else if (key == "wallet") {
    opts->wallet_path = value;
    opts->wallet_path_explicit = true;
  } else if (key == "disablewallet") {
    opts->disable_wallet = ParseBool(value);
  } else if (key == "nowalletautoload" || key == "nowalletload") {
    opts->no_wallet_autoload = ParseBool(value);
  } else if (key == "walletpass") {
    opts->wallet_pass = value;
  } else if (key == "walletpassenv") {
    opts->wallet_pass_env = value;
  } else if (key == "rpcbind") {
    opts->rpc_bind = value;
  } else if (key == "rpcport") {
    opts->rpc_port = static_cast<std::uint16_t>(std::stoi(value));
    opts->rpc_port_explicit = true;
  } else if (key == "rpcuser") {
    opts->rpc_user = value;
  } else if (key == "rpcpassword" || key == "rpcpass") {
    opts->rpc_pass = value;
  } else if (key == "rpcpassenv") {
    opts->rpc_pass_env = value;
  } else if (key == "rpcallowip") {
    opts->rpc_allow.push_back(value);
  } else if (key == "unsafeallowremote") {
    opts->unsafe_allow_remote = ParseBool(value);
  } else if (key == "rpcgbtrate") {
    opts->rpc_gbt_rate = static_cast<std::uint32_t>(std::stoul(value));
  } else if (key == "rpcsubmitrate") {
    opts->rpc_submit_rate = static_cast<std::uint32_t>(std::stoul(value));
  } else if (key == "p2pport" || key == "port") {
    opts->p2p_port = static_cast<std::uint16_t>(std::stoi(value));
    opts->p2p_port_explicit = true;
  } else if (key == "nolisten" || key == "listen") {
    if (key == "listen") {
      opts->listen_enabled = ParseBool(value);
    } else {
      opts->listen_enabled = false;
    }
  } else if (key == "maxinboundpeers") {
    opts->max_inbound_peers = static_cast<std::size_t>(std::stoul(value));
  } else if (key == "maxoutboundpeers") {
    opts->max_outbound_peers = static_cast<std::size_t>(std::stoul(value));
  } else if (key == "maxtotalpeers") {
    opts->max_total_peers = static_cast<std::size_t>(std::stoul(value));
  } else if (key == "miningaddress") {
    opts->mining_address = value;
  } else if (key == "connect" || key == "connectpeer") {
    opts->connect_peers.push_back(value);
  } else if (key == "mempoollimitmb") {
    opts->mempool_limit_mb = static_cast<std::size_t>(std::stoul(value));
  } else if (key == "mempoolexpiryseconds") {
    opts->mempool_expiry_seconds = static_cast<std::uint64_t>(std::stoull(value));
  } else if (key == "mempoolrebroadcastseconds") {
    opts->mempool_rebroadcast_seconds =
        static_cast<std::uint64_t>(std::stoull(value));
  } else if (key == "mempoolpersist") {
    opts->mempool_persist = ParseBool(value);
  } else if (key == "mempoolpersistpath") {
    opts->mempool_persist_path = value;
  } else if (key == "mempoolpersistintervalseconds") {
    opts->mempool_persist_interval_seconds =
        static_cast<std::uint64_t>(std::stoull(value));
  } else if (key == "feeestimatordecay") {
    opts->fee_estimator_decay = std::stod(value);
  } else if (key == "feeestimatorsamples") {
    opts->fee_estimator_samples = static_cast<std::size_t>(std::stoul(value));
  } else if (key == "allowgenerate") {
    opts->allow_generate = ParseBool(value);
  } else if (key == "seednode") {
    opts->seed_node = ParseBool(value);
  } else if (key == "requireencryption" || key == "encryptionrequired") {
    opts->require_encryption = ParseBool(value);
  } else if (key == "requireauthenticatedtransport" || key == "requireauthtransport") {
    opts->require_authenticated_transport = ParseBool(value);
    opts->require_authenticated_transport_explicit = true;
  } else if (key == "allowprivatepeers") {
    opts->allow_private_peers = ParseBool(value);
  } else if (key == "debuglog") {
    opts->debug_log_path = value;
  } else if (key == "loglevel") {
    opts->log_level = value;
  } else if (key == "logmaxsizemb") {
    opts->log_max_size_mb = static_cast<std::size_t>(std::stoul(value));
  } else if (key == "logmaxfiles") {
    opts->log_max_files = static_cast<std::size_t>(std::stoul(value));
  } else if (key == "config" || key == "conf") {
    opts->config_path = value;
  } else {
    std::cerr << "[qryptd] warn: unknown config key '" << raw_key << "'\n";
  }
}

void LoadConfigFile(const std::filesystem::path& path, Options* opts) {
  if (path.empty()) {
    return;
  }
  if (!std::filesystem::exists(path)) {
    return;
  }
  std::ifstream in(path);
  if (!in) {
    throw std::runtime_error("failed to open config file: " + path.string());
  }
  std::string line;
  std::size_t lineno = 0;
  while (std::getline(in, line)) {
    ++lineno;
    const auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos) {
      line.resize(comment_pos);
    }
    line = Trim(line);
    if (line.empty()) {
      continue;
    }
    std::string key;
    std::string value;
    const auto eq_pos = line.find_first_of("= ");
    if (eq_pos == std::string::npos) {
      key = line;
      value = "1";
    } else {
      key = Trim(line.substr(0, eq_pos));
      value = Trim(line.substr(eq_pos + 1));
      if (!value.empty() && value.front() == '=') {
        value = Trim(value.substr(1));
      }
      if (value.empty()) {
        value = "1";
      }
    }
    try {
      ApplyConfigOption(key, value, opts);
    } catch (const std::exception& ex) {
      throw std::runtime_error(path.string() + ":" + std::to_string(lineno) + ": " + ex.what());
    }
  }
}

Options ParseOptions(int argc, char** argv) {
  Options opts;
  std::vector<std::string> args;
  args.reserve(static_cast<std::size_t>(argc));
  for (int i = 1; i < argc; ++i) {
    std::string token = argv[i];
    auto eq_pos = token.find('=');
    if (eq_pos != std::string::npos && token.rfind("--", 0) == 0) {
      args.push_back(token.substr(0, eq_pos));
      args.push_back(token.substr(eq_pos + 1));
    } else {
      args.push_back(std::move(token));
    }
  }
  auto ensure_value = [&](std::size_t& idx) -> std::string {
    if (idx + 1 >= args.size()) {
      throw std::runtime_error("missing value for argument");
    }
    return args[++idx];
  };

  for (std::size_t i = 0; i < args.size(); ++i) {
    std::string arg = args[i];
    if (arg == "--help" || arg == "-h") {
      PrintUsage();
      std::exit(0);
    }
    if (arg == "--conf") {
      opts.config_path = ensure_value(i);
    } else if (arg == "--no-conf") {
      opts.disable_config_file = true;
    }
  }

  if (!opts.disable_config_file) {
    std::filesystem::path config_path =
        opts.config_path.empty() ? std::filesystem::path("qryptcoin.conf")
                                 : std::filesystem::path(opts.config_path);
    LoadConfigFile(config_path, &opts);
  }

  ApplyEnvironmentOverrides(&opts);

  for (std::size_t i = 0; i < args.size(); ++i) {
    std::string arg = args[i];
    if (arg == "--network") {
      opts.network = ensure_value(i);
    } else if (arg == "--data-dir") {
      opts.data_dir = ensure_value(i);
    } else if (arg == "--wallet") {
      opts.wallet_path = ensure_value(i);
      opts.wallet_path_explicit = true;
    } else if (arg == "--wallet-pass") {
      opts.wallet_pass = ensure_value(i);
    } else if (arg == "--wallet-pass-env") {
      opts.wallet_pass_env = ensure_value(i);
    } else if (arg == "--disable-wallet" || arg == "--disablewallet") {
      opts.disable_wallet = true;
    } else if (arg == "--no-wallet-autoload" || arg == "--nowalletautoload" || arg == "--no-wallet-load") {
      opts.no_wallet_autoload = true;
    } else if (arg == "--rpc-user") {
      opts.rpc_user = ensure_value(i);
    } else if (arg == "--rpc-pass") {
      opts.rpc_pass = ensure_value(i);
    } else if (arg == "--rpc-pass-env") {
      opts.rpc_pass_env = ensure_value(i);
    } else if (arg == "--rpc-bind") {
      opts.rpc_bind = ensure_value(i);
    } else if (arg == "--rpc-port") {
      opts.rpc_port = static_cast<std::uint16_t>(std::stoi(ensure_value(i)));
      opts.rpc_port_explicit = true;
    } else if (arg == "--rpc-allow-ip") {
      opts.rpc_allow.push_back(ensure_value(i));
    } else if (arg == "--unsafe-allow-remote") {
      opts.unsafe_allow_remote = true;
    } else if (arg == "--rpc-gbt-rate") {
      opts.rpc_gbt_rate =
          static_cast<std::uint32_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--rpc-submit-rate") {
      opts.rpc_submit_rate =
          static_cast<std::uint32_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--rpc-require-auth") {
      opts.rpc_require_auth = true;
    } else if (arg == "--rpc-read-only") {
      opts.rpc_read_only = true;
    } else if (arg == "--p2p-port") {
      opts.p2p_port = static_cast<std::uint16_t>(std::stoi(ensure_value(i)));
      opts.p2p_port_explicit = true;
    } else if (arg == "--nolisten" || arg == "--listen=0") {
      opts.listen_enabled = false;
    } else if (arg == "--listen") {
      opts.listen_enabled = ParseBool(ensure_value(i));
    } else if (arg == "--mining-address") {
      opts.mining_address = ensure_value(i);
    } else if (arg == "--allow-generate") {
      opts.allow_generate = true;
    } else if (arg == "--enable-upnp") {
      opts.enable_upnp = true;
    } else if (arg == "--seed-node") {
      opts.seed_node = true;
    } else if (arg == "--require-encryption") {
      opts.require_encryption = true;
    } else if (arg == "--require-authenticated-transport") {
      opts.require_authenticated_transport = true;
      opts.require_authenticated_transport_explicit = true;
    } else if (arg == "--no-require-authenticated-transport") {
      opts.require_authenticated_transport = false;
      opts.require_authenticated_transport_explicit = true;
    } else if (arg == "--allow-private-peers") {
      opts.allow_private_peers = true;
    } else if (arg == "--connect-peer") {
      opts.connect_peers.push_back(ensure_value(i));
    } else if (arg == "--max-inbound-peers") {
      opts.max_inbound_peers = static_cast<std::size_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--max-outbound-peers") {
      opts.max_outbound_peers = static_cast<std::size_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--max-total-peers") {
      opts.max_total_peers = static_cast<std::size_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--fee-estimator-decay") {
      opts.fee_estimator_decay = std::stod(ensure_value(i));
    } else if (arg == "--fee-estimator-samples") {
      opts.fee_estimator_samples = static_cast<std::size_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--mempool-limit-mb") {
      opts.mempool_limit_mb = static_cast<std::size_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--mempool-expiry-seconds") {
      opts.mempool_expiry_seconds = static_cast<std::uint64_t>(std::stoull(ensure_value(i)));
    } else if (arg == "--mempool-rebroadcast-seconds") {
      opts.mempool_rebroadcast_seconds =
          static_cast<std::uint64_t>(std::stoull(ensure_value(i)));
    } else if (arg == "--mempool-persist") {
      opts.mempool_persist = true;
    } else if (arg == "--no-mempool-persist") {
      opts.mempool_persist = false;
    } else if (arg == "--mempool-persist-path") {
      opts.mempool_persist_path = ensure_value(i);
    } else if (arg == "--mempool-persist-interval-seconds") {
      opts.mempool_persist_interval_seconds =
          static_cast<std::uint64_t>(std::stoull(ensure_value(i)));
    } else if (arg == "--log-level") {
      opts.log_level = ensure_value(i);
    } else if (arg == "--log-max-size-mb") {
      opts.log_max_size_mb = static_cast<std::size_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--log-max-files") {
      opts.log_max_files = static_cast<std::size_t>(std::stoul(ensure_value(i)));
    } else if (arg == "--debug-log") {
      opts.debug_log_path = ensure_value(i);
    } else if (arg == "--conf" || arg == "--no-conf" || arg == "--help" || arg == "-h") {
      // already handled
      continue;
    } else {
      throw std::runtime_error("unknown option: " + arg);
    }
  }

  auto net_type = qryptcoin::config::NetworkFromString(opts.network);
  qryptcoin::config::SelectNetwork(net_type);
  if (!opts.require_authenticated_transport_explicit &&
      net_type == qryptcoin::config::NetworkType::kMainnet) {
    opts.require_authenticated_transport = true;
  }
  if (!opts.rpc_port_explicit) {
    opts.rpc_port = qryptcoin::config::GetNetworkConfig().rpc_port;
  }
  if (!opts.p2p_port_explicit) {
    opts.p2p_port = qryptcoin::config::GetNetworkConfig().listen_port;
  }
  if (opts.data_dir.empty()) {
    std::filesystem::path base;
#ifdef _WIN32
    if (const char* appdata = std::getenv("APPDATA")) {
      base = std::filesystem::path(appdata) / "QryptCoin" /
             std::string(qryptcoin::config::NetworkName(net_type));
    } else {
      base = std::filesystem::path("data") /
             std::string(qryptcoin::config::NetworkName(net_type));
    }
#else
    if (const char* xdg_data = std::getenv("XDG_DATA_HOME")) {
      base = std::filesystem::path(xdg_data) / "qryptcoin" /
             std::string(qryptcoin::config::NetworkName(net_type));
    } else if (const char* home = std::getenv("HOME")) {
      base = std::filesystem::path(home) / ".qryptcoin" /
             std::string(qryptcoin::config::NetworkName(net_type));
    } else {
      base = std::filesystem::path("data") /
             std::string(qryptcoin::config::NetworkName(net_type));
    }
#endif
    opts.data_dir = base.string();
  }
  std::filesystem::path data_root(opts.data_dir);
  if (opts.wallet_path.empty()) {
    if (!opts.no_wallet_autoload) {
      opts.wallet_path = (data_root / "wallet.dat").string();
    }
  }
  opts.blocks_path = (data_root / "blocks.dat").string();
  opts.utxo_path = (data_root / "utxo.dat").string();
  if (opts.mempool_persist) {
    if (opts.mempool_persist_path.empty()) {
      opts.mempool_persist_path = (data_root / "mempool.json").string();
    }
  } else {
    opts.mempool_persist_path.clear();
  }
  if (opts.rpc_pass.empty() && !opts.rpc_pass_env.empty()) {
    if (const char* env = std::getenv(opts.rpc_pass_env.c_str())) {
      opts.rpc_pass = env;
    }
  }
  if (opts.wallet_pass.empty() && !opts.wallet_pass_env.empty()) {
    if (const char* env = std::getenv(opts.wallet_pass_env.c_str())) {
      opts.wallet_pass = env;
    }
  }
  return opts;
}

std::unique_ptr<qryptcoin::wallet::HDWallet> LoadWallet(const Options& opts) {
  if (opts.wallet_path.empty()) {
    LogDebug("Wallet path is empty; skipping wallet load");
    return nullptr;
  }
  LogDebug(std::string("Loading wallet from ") + opts.wallet_path);
  std::error_code ec;
  const bool wallet_exists = std::filesystem::exists(std::filesystem::path(opts.wallet_path), ec);
  std::string wallet_error;
  auto wallet = qryptcoin::wallet::HDWallet::Load(opts.wallet_path, opts.wallet_pass, &wallet_error);
  if (wallet) {
    LogDebug("Wallet loaded successfully");
    return wallet;
  }
  if (wallet_exists) {
    std::string hint;
    if (opts.wallet_pass.empty()) {
      hint = " (passphrase not provided)";
    }
    LogDebug("Wallet load failed; refusing to overwrite existing wallet" + hint +
             (!wallet_error.empty() ? (": " + wallet_error) : ""));
    std::cout << "[qryptd] warn: wallet file exists but could not be loaded" << hint;
    if (!wallet_error.empty()) {
      std::cout << ": " << wallet_error;
    }
    std::cout << "\n";
    // Do not abort daemon startup: wallet management RPCs can still be used
    // to load a different wallet file once the node is running.
    return nullptr;
  }
  std::cout << "[qryptd] creating new wallet at " << opts.wallet_path << "\n";
  if (opts.wallet_pass.empty()) {
    LogDebug("Wallet missing; creating new wallet (unencrypted, empty passphrase)");
    std::cout << "[qryptd] warn: creating wallet with empty passphrase; run encryptwallet to set one\n";
  } else {
    LogDebug("Wallet missing; creating new wallet with default parameters");
  }
  wallet = qryptcoin::wallet::HDWallet::Create(
      opts.wallet_path, opts.wallet_pass,
      qryptcoin::crypto::SignatureAlgorithm::kDilithium);
  if (!wallet) {
    LogDebug("Wallet creation failed");
    throw std::runtime_error("failed to create wallet");
  }
  // For daemon-managed wallets created on first run, explicitly mark a birth
  // height of zero so that future rescans can start from genesis if needed.
  wallet->SetBirthHeight(0);
  wallet->SetLastScanHeight(0);
  wallet->Save();
  LogDebug("Wallet created successfully");
  return wallet;
}

std::vector<std::string> DeduplicateTargets(std::vector<std::string> items) {
  std::vector<std::string> result;
  std::unordered_set<std::string> seen;
  result.reserve(items.size());
  for (auto& item : items) {
    if (seen.insert(item).second) {
      result.push_back(std::move(item));
    }
  }
  return result;
}

std::vector<std::string> ExpandDnsSeeds(const std::vector<std::string>& dns_seeds,
                                        qryptcoin::net::AddrManager* addrman) {
  std::vector<std::string> targets;
  for (const auto& host : dns_seeds) {
    const auto records = qryptcoin::net::ResolveHostAddresses(host);
    if (records.empty()) {
      std::cout << "[qryptd] warn: DNS seed " << host << " returned no A records\n";
      if (addrman) {
        addrman->RecordDnsLookup(0, 1);
      }
      continue;
    }
    if (addrman) {
      addrman->RecordDnsLookup(records.size(), 0);
    }
    targets.insert(targets.end(), records.begin(), records.end());
  }
  return targets;
}

bool IsLoopbackAddress(std::string host) {
  std::transform(host.begin(), host.end(), host.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (host == "localhost" || host == "::1") {
    return true;
  }
  if (host.rfind("127.", 0) == 0) {
    return true;
  }
  return false;
}

  bool AttemptSeedConnections(qryptcoin::net::PeerManager& manager,
                              qryptcoin::net::AddrManager* addrman,
                              const std::vector<std::string>& seeds, std::uint16_t port,
                              bool resolve_dns, std::size_t max_attempts, bool permanent) {
  if (seeds.empty() || max_attempts == 0) {
    LogDebug("Seed connection skipped: no seeds configured or max_attempts=0");
    return false;
  }
  if (ShutdownRequested()) {
    LogDebug("Seed connection skipped: shutdown requested");
    return false;
  }
  LogDebug("Attempting seed connections (count=" + std::to_string(seeds.size()) +
           ", resolve_dns=" + std::string(resolve_dns ? "true" : "false") +
           ", max_attempts=" + std::to_string(max_attempts) + ")");
  std::vector<std::string> targets;
  if (resolve_dns) {
    targets = ExpandDnsSeeds(seeds, addrman);
  } else {
    targets = seeds;
    if (addrman) {
      addrman->RecordStaticSeeds(targets.size());
    }
  }
  targets = DeduplicateTargets(std::move(targets));
  if (targets.empty()) {
    LogDebug("No seed targets available after resolution/deduplication");
    return false;
  }
    if (addrman) {
      for (const auto& host : targets) {
        addrman->Add(host, port, permanent);
      }
    }
    std::shuffle(targets.begin(), targets.end(), std::mt19937{std::random_device{}()});
  bool connected = false;
  std::size_t attempts = 0;
  for (const auto& host : targets) {
    if (ShutdownRequested()) {
      LogDebug("Seed connection loop aborted: shutdown requested");
      break;
    }
    if (attempts >= max_attempts) {
      break;
    }
    ++attempts;
    LogDebug("Connecting to seed " + host + ":" + std::to_string(port));
    std::string dial_error;
    const bool ok =
        manager.ConnectToPeer(host, port, &dial_error, /*enforce_identity_pins=*/permanent);
    if (addrman) {
      addrman->MarkResult(host, port, ok);
    }
    if (ok) {
      LogDebug("Seed " + host + " connected");
      connected = true;
    } else {
      if (!dial_error.empty()) {
        LogDebug("Seed " + host + " connection failed: " + dial_error);
      } else {
        LogDebug("Seed " + host + " connection failed");
      }
      std::cout << "[qryptd] warn: unable to reach seed " << host << "\n";
    }
  }
  if (!connected) {
    LogDebug("No outbound seed connections succeeded");
  }
  return connected;
}

struct NodeContext {
  std::unique_ptr<qryptcoin::node::ChainState> chain;
  std::unique_ptr<qryptcoin::net::PeerManager> peer_manager;
  std::unique_ptr<qryptcoin::node::BlockSyncManager> sync_manager;
  std::unique_ptr<qryptcoin::rpc::RpcServer> rpc_server;
  std::unique_ptr<qryptcoin::rpc::HttpServer> http_server;
  qryptcoin::net::DnsSeedManager* dns_seeds{nullptr};
  std::filesystem::path rpc_cookie_path;
  bool rpc_cookie_generated{false};
};

bool AppInitMain(Options opts, NodeContext* node, qryptcoin::net::AddrManager* addrman,
                 qryptcoin::net::DnsSeedManager* dns_seeds) {
  if (!IsLoopbackAddress(opts.rpc_bind) && !opts.unsafe_allow_remote) {
    std::cerr << "[qryptd] fatal: refusing to bind RPC to non-loopback address without "
                 "--unsafe-allow-remote\n";
    return false;
  }
  if (opts.unsafe_allow_remote && opts.rpc_allow.empty()) {
    std::cerr << "[qryptd] fatal: non-loopback RPC requires at least one --rpc-allow-ip entry\n";
    return false;
  }
  std::vector<std::string> rpc_allow = opts.rpc_allow;
  if (rpc_allow.empty()) {
    rpc_allow.push_back("127.0.0.1");
    rpc_allow.push_back("::1");
  }
  const bool require_rpc_auth = opts.rpc_require_auth;
  if (require_rpc_auth) {
    const bool has_user = !opts.rpc_user.empty();
    const bool has_pass = !opts.rpc_pass.empty();
    if (has_user != has_pass) {
      std::cerr << "[qryptd] fatal: --rpc-user and --rpc-pass must be set together\n";
      return false;
    }
    if (!has_user) {
      const auto cookie_path = std::filesystem::path(opts.data_dir) / "rpc.cookie";
      std::error_code ec;
      std::filesystem::create_directories(cookie_path.parent_path(), ec);
      const std::string cookie_user = "qryptcookie";
      const std::string cookie_pass = GenerateRpcSecretHex(24);
      std::ofstream cookie(cookie_path, std::ios::trunc);
      if (!cookie) {
        std::cerr << "[qryptd] fatal: unable to write RPC cookie at " << cookie_path.string()
                  << "\n";
        return false;
      }
      cookie << cookie_user << ":" << cookie_pass << "\n";
      cookie.close();
      std::string perm_warning;
      if (!HardenRpcCookieFile(cookie_path, &perm_warning)) {
        std::cerr << "[qryptd] warn: " << perm_warning << "\n";
        std::cerr << "[qryptd] warn: protect " << cookie_path.string()
                  << " from other local users (or set --rpc-user/--rpc-pass explicitly)\n";
      }
      opts.rpc_user = cookie_user;
      opts.rpc_pass = cookie_pass;
      if (node) {
        node->rpc_cookie_path = cookie_path;
        node->rpc_cookie_generated = true;
      }
      LogDebug("RPC auth cookie written to " + cookie_path.string());
      std::cout << "[qryptd] RPC auth cookie: " << cookie_path.string() << "\n";
    } else {
      // When operators configure explicit RPC credentials (for example, to allow
      // local containers to authenticate via NODE_RPC_USER/NODE_RPC_PASSWORD),
      // still materialize an rpc.cookie file so local tools can authenticate
      // without exposing secrets in process lists.
      const auto cookie_path = std::filesystem::path(opts.data_dir) / "rpc.cookie";
      std::error_code ec;
      std::filesystem::create_directories(cookie_path.parent_path(), ec);
      std::ofstream cookie(cookie_path, std::ios::trunc);
      if (!cookie) {
        std::cerr << "[qryptd] warn: unable to write RPC cookie at " << cookie_path.string()
                  << " (local tooling may require --rpc-user/--rpc-pass)\n";
      } else {
        cookie << opts.rpc_user << ":" << opts.rpc_pass << "\n";
        cookie.close();
        std::string perm_warning;
        if (!HardenRpcCookieFile(cookie_path, &perm_warning)) {
          std::cerr << "[qryptd] warn: " << perm_warning << "\n";
          std::cerr << "[qryptd] warn: protect " << cookie_path.string()
                    << " from other local users\n";
        }
        LogDebug("RPC auth cookie updated at " + cookie_path.string());
      }
    }
  }
  const bool auth_enabled = !(opts.rpc_user.empty() && opts.rpc_pass.empty());
  if (require_rpc_auth && !auth_enabled) {
    std::cerr << "[qryptd] fatal: RPC auth required but no credentials were configured\n";
    return false;
  }
  if (!IsLoopbackAddress(opts.rpc_bind) && !auth_enabled) {
    std::cerr << "[qryptd] fatal: refusing to bind RPC to " << opts.rpc_bind
              << " without authentication\n";
    return false;
  }

  std::unique_ptr<qryptcoin::wallet::HDWallet> wallet;
  if (opts.disable_wallet) {
    std::cout << "[qryptd] info: wallet disabled (node-only mode)\n";
    LogDebug("Wallet disabled via --disable-wallet/QRY_DISABLE_WALLET");
  } else if (opts.no_wallet_autoload && !opts.wallet_path_explicit) {
    std::cout << "[qryptd] info: wallet autoload skipped; use createwallet/loadwallet via RPC\n";
    LogDebug("Wallet autoload skipped via --no-wallet-autoload/QRY_NO_WALLET_AUTOLOAD");
  } else {
    wallet = LoadWallet(opts);
  }
  node->chain = std::make_unique<qryptcoin::node::ChainState>(opts.blocks_path, opts.utxo_path);
  std::string error;
  LogDebug("Initializing chain state");
  if (!node->chain->Initialize(&error)) {
    LogDebug("Chain initialization failed: " + error);
    throw std::runtime_error("chain init failed: " + error);
  }
  LogDebug("Chain state initialized successfully");

  auto net_config = qryptcoin::config::GetNetworkConfig();
  net_config.listen_port = opts.p2p_port;
  net_config.data_dir = opts.data_dir;
  net_config.authenticated_transport_required = opts.require_authenticated_transport;
  net_config.encryption_required = opts.require_encryption || opts.require_authenticated_transport;
  if (net_config.authenticated_transport_required &&
      net_config.type == qryptcoin::config::NetworkType::kMainnet &&
      !net_config.data_dir.empty() && !net_config.static_seeds.empty()) {
    const auto seed_pins_path =
        std::filesystem::path(net_config.data_dir) / "p2p_seed_pins.txt";
    if (!std::filesystem::exists(seed_pins_path)) {
      std::cerr << "[qryptd] warn: no seed identity pins configured at "
                << seed_pins_path.string() << "\n";
      std::cerr << "[qryptd] warn: bootstrap seeds will not be identity-pinned unless "
                   "p2p_seed_pins.txt is populated out-of-band\n";
    }
  }
  if (opts.seed_node) {
    net_config.listen_address = "0.0.0.0";
  }
  // Apply peer limits from options.
  net_config.max_inbound_peers = opts.max_inbound_peers;
  net_config.max_outbound_peers = opts.max_outbound_peers;
  net_config.max_total_peers = opts.max_total_peers;
  net_config.target_outbound_peers = opts.target_outbound_peers;
  // Update global config so RPC can report accurate peer limits.
  auto& global_config = qryptcoin::config::GetMutableNetworkConfig();
  global_config.max_inbound_peers = opts.max_inbound_peers;
  global_config.max_outbound_peers = opts.max_outbound_peers;
  global_config.max_total_peers = opts.max_total_peers;
  global_config.target_outbound_peers = opts.target_outbound_peers;
  if (!opts.extra_static_seeds.empty()) {
    net_config.static_seeds.insert(net_config.static_seeds.end(),
                                   opts.extra_static_seeds.begin(),
                                   opts.extra_static_seeds.end());
  }
  node->peer_manager = std::make_unique<qryptcoin::net::PeerManager>(net_config);
  node->sync_manager =
      std::make_unique<qryptcoin::node::BlockSyncManager>(*node->chain, *node->peer_manager);
  node->dns_seeds = dns_seeds;
  if (addrman) {
    node->sync_manager->SetAddressObserver(
        [addrman, port = qryptcoin::config::GetNetworkConfig().listen_port](const std::string& address) {
          // PeerManager::PeerInfo::address already includes the remote host,
          // so we treat it as a host string and pair it with the network
          // listen port for future outbound attempts.
          addrman->Add(address, port, false);
        });
  }

  node->rpc_server = std::make_unique<qryptcoin::rpc::RpcServer>(
      std::move(wallet), !opts.disable_wallet, *node->chain, node->peer_manager.get(),
      node->sync_manager.get(), addrman, dns_seeds, opts.seed_node, opts.mining_address,
      opts.allow_generate, opts.rpc_read_only,
      static_cast<std::uint64_t>(opts.mempool_limit_mb) * 1024ULL * 1024ULL,
      opts.mempool_persist ? opts.mempool_persist_path : std::string(),
      opts.mempool_expiry_seconds,
      opts.mempool_rebroadcast_seconds,
      opts.mempool_persist ? opts.mempool_persist_interval_seconds : 0);
  node->rpc_server->ConfigureFeeEstimator(opts.fee_estimator_decay, opts.fee_estimator_samples);
  qryptcoin::rpc::ConfigureMiningRpcRateLimits(opts.rpc_gbt_rate, opts.rpc_submit_rate);
  node->sync_manager->SetTransactionHandler(
      [server = node->rpc_server.get()](const qryptcoin::primitives::CTransaction& tx,
                                        std::string* reject_reason) {
        return server->SubmitTransactionFromNetwork(tx, reject_reason);
      });
  node->sync_manager->SetTxCommitmentHandler(
      [server = node->rpc_server.get()](const qryptcoin::primitives::Hash256& commitment,
                                        std::uint64_t peer_id) {
        server->NotifyTransactionCommitmentFromNetwork(commitment, peer_id);
      });
  node->sync_manager->SetTransactionInventoryPolicy(
      [server = node->rpc_server.get()](const qryptcoin::primitives::Hash256& txid) {
        return server->HasMempoolTransaction(txid);
      },
      [server = node->rpc_server.get()](const qryptcoin::primitives::Hash256& txid,
                                        std::vector<std::uint8_t>* raw) {
        return server->GetMempoolTransactionBytes(txid, raw);
      });
  node->sync_manager->SetBlockConnectedHandler(
      [server = node->rpc_server.get()](const qryptcoin::primitives::CBlock& block,
                                        std::uint32_t height) {
        server->NotifyBlockConnected(block, height);
      });

  LogDebug("Starting block sync manager");
  node->sync_manager->Start();
  if (opts.listen_enabled) {
    LogDebug("Starting peer listener on port " + std::to_string(net_config.listen_port));
    node->peer_manager->StartListener();
  } else {
    LogDebug("P2P listener disabled via --nolisten/listen=0");
    std::cout << "[qryptd] info: P2P listener disabled (--nolisten)\n";
  }

  qryptcoin::rpc::HttpServer::Options http_opts;
  http_opts.bind_address = opts.rpc_bind;
  http_opts.port = opts.rpc_port;
  http_opts.rpc_user = opts.rpc_user;
  http_opts.rpc_password = opts.rpc_pass;
  http_opts.require_auth = opts.rpc_require_auth;
  http_opts.allowed_hosts = rpc_allow;
  http_opts.max_body_bytes = 2 * 1024 * 1024;
  http_opts.socket_timeout_ms = 5000;

  node->http_server = std::make_unique<qryptcoin::rpc::HttpServer>(
      http_opts, [server = node->rpc_server.get()](const nlohmann::json& request) {
        return server->Handle(request);
      });

  LogDebug("HTTP/RPC server listening on " + opts.rpc_bind + ":" +
           std::to_string(opts.rpc_port));
  std::cout << "[qryptd] " << qryptcoin::config::kProjectName << " "
            << qryptcoin::config::kVersion << " ("
            << qryptcoin::config::NetworkName(qryptcoin::config::GetNetworkConfig().type)
            << ") listening on " << opts.rpc_bind << ":" << opts.rpc_port << "\n";
  LogDebug("Starting HTTP server thread");
  node->http_server->Start();

  if (opts.enable_upnp) {
    std::string external;
    if (qryptcoin::net::TryMapPort(opts.p2p_port, &external)) {
      std::cout << "[qryptd] UPnP mapped P2P port " << opts.p2p_port;
      if (!external.empty()) {
        std::cout << " (external address " << external << ")";
      }
      std::cout << "\n";
    } else {
      std::cout << "[qryptd] info: UPnP mapping requested but no compatible gateway was found\n";
    }
  }

  const auto default_seed_port = qryptcoin::config::GetNetworkConfig().listen_port;
  bool connected = AttemptSeedConnections(*node->peer_manager, addrman,
                                          net_config.static_seeds, default_seed_port,
                                          /*resolve_dns=*/false,
                                          net_config.static_seeds.size(),
                                          /*permanent=*/false);
  std::vector<std::string> dns_targets;
  if (dns_seeds) {
    dns_seeds->ForceRefresh();
    dns_seeds->Tick();
    dns_targets = dns_seeds->SnapshotAllAddresses();
  }
  if (dns_targets.empty() && !net_config.dns_seeds.empty()) {
    dns_targets = ExpandDnsSeeds(net_config.dns_seeds, addrman);
  }
  connected |= AttemptSeedConnections(*node->peer_manager, addrman,
                                      dns_targets, default_seed_port,
                                      /*resolve_dns=*/false,
                                      /*max_attempts=*/16,
                                      /*permanent=*/false);
  for (const auto& target : opts.connect_peers) {
    auto sep = target.rfind(':');
    if (sep == std::string::npos) {
      std::cout << "[qryptd] invalid connect-peer target: " << target << "\n";
      continue;
    }
    auto host = target.substr(0, sep);
    auto port = static_cast<std::uint16_t>(std::stoi(target.substr(sep + 1)));
    LogDebug("Attempting manual peer connection to " + host + ":" + std::to_string(port));
    if (node->peer_manager->ConnectToPeer(host, port)) {
      LogDebug("Manual peer connection to " + host + " succeeded");
      connected = true;
    } else {
      LogDebug("Manual peer connection to " + host + " failed");
      std::cout << "[qryptd] warn: connect-peer " << target << " failed\n";
    }
  }
  if (!connected) {
    if (opts.listen_enabled) {
      std::cout << "[qryptd] warn: no seed connections succeeded; waiting for inbound peers\n";
    } else {
      std::cout << "[qryptd] warn: no seed connections succeeded and inbound P2P is disabled; "
                   "configure connect= targets\n";
    }
  }
  return true;
}

void ShutdownNode(NodeContext& node) {
  LogDebug("Shutdown: stopping services");
  if (node.http_server) {
    node.http_server->Stop();
  }
  if (node.sync_manager) {
    node.sync_manager->Stop();
  }
  if (node.peer_manager) {
    node.peer_manager->Stop();
  }
  if (node.rpc_server) {
    node.rpc_server->SaveWalletIfLoaded();
  }
  LogDebug("Shutdown: completed");
}

struct SeedLoopState {
  std::chrono::steady_clock::time_point next_dns_attempt{};
  std::chrono::steady_clock::time_point next_static_attempt{};
  std::chrono::seconds dns_backoff{std::chrono::seconds(5)};
  std::chrono::seconds static_backoff{std::chrono::seconds(30)};
};

void MaintainOutboundPeers(qryptcoin::net::PeerManager* peers,
                           qryptcoin::net::AddrManager* addrman,
                           std::uint16_t default_port, std::size_t target_outbound) {
  if (!peers || !addrman || target_outbound == 0) {
    return;
  }
  if (ShutdownRequested()) {
    return;
  }
  const auto infos = peers->GetPeerInfos();
  std::size_t outbound = 0;
  for (const auto& info : infos) {
    if (!info.inbound) {
      ++outbound;
    }
  }
  if (outbound >= target_outbound) {
    return;
  }
  constexpr std::size_t kMaxOutboundDialsPerTick = 2;
  const std::size_t needed = target_outbound - outbound;
  const std::size_t attempts = std::min<std::size_t>(needed, kMaxOutboundDialsPerTick);
  for (std::size_t i = 0; i < attempts; ++i) {
    if (ShutdownRequested()) {
      return;
    }
    auto candidate = addrman->Select();
    if (!candidate) {
      break;
    }
    const std::string host = candidate->host;
    const std::uint16_t port = candidate->port != 0 ? candidate->port : default_port;
    const bool enforce_identity_pins = candidate->permanent;
    if (peers->ConnectToPeer(host, port, /*error=*/nullptr, enforce_identity_pins)) {
      addrman->MarkResult(host, port, true);
    } else {
      addrman->MarkResult(host, port, false);
    }
  }
}

void MaybeRunSeedLoop(NodeContext& node, qryptcoin::net::AddrManager* addrman,
                      qryptcoin::net::DnsSeedManager* dns_seeds,
                      const Options& opts, SeedLoopState* state,
                      std::size_t target_outbound) {
  if (!addrman || !node.peer_manager) {
    return;
  }
  if (ShutdownRequested()) {
    return;
  }
  const auto infos = node.peer_manager->GetPeerInfos();
  std::size_t outbound = 0;
  for (const auto& info : infos) {
    if (!info.inbound) {
      ++outbound;
    }
  }
  if (outbound >= target_outbound) {
    return;
  }
  // Prefer cached peers when there are still dialable candidates; the seed
  // loop is a bootstrap/fallback when we have no outbound peers or the address
  // table is exhausted.
  if (outbound > 0 && addrman->Select().has_value()) {
    return;
  }

  using clock = std::chrono::steady_clock;
  const auto now = clock::now();
  const auto& net_cfg = qryptcoin::config::GetNetworkConfig();

  bool connected = false;
  if (now >= state->next_dns_attempt && dns_seeds) {
    if (ShutdownRequested()) {
      return;
    }
    std::vector<std::string> dns_targets = dns_seeds->SnapshotAllAddresses();
    if (dns_targets.empty() && !net_cfg.dns_seeds.empty()) {
      dns_targets = ExpandDnsSeeds(net_cfg.dns_seeds, addrman);
    }
    connected = AttemptSeedConnections(*node.peer_manager, addrman, dns_targets,
                                       net_cfg.listen_port, /*resolve_dns=*/false,
                                       /*max_attempts=*/4, /*permanent=*/false);
    auto backoff = state->dns_backoff;
    if (connected) {
      backoff = std::chrono::seconds(5);
    } else {
      backoff = std::min(backoff * 2, std::chrono::seconds(300));
    }
    state->dns_backoff = backoff;
    const auto jitter = std::chrono::seconds(backoff.count() / 4);
    state->next_dns_attempt = now + backoff + jitter;
  }

  if (!connected && now >= state->next_static_attempt &&
      !net_cfg.static_seeds.empty()) {
    if (ShutdownRequested()) {
      return;
    }
    connected = AttemptSeedConnections(*node.peer_manager, addrman, net_cfg.static_seeds,
                                       net_cfg.listen_port, /*resolve_dns=*/false,
                                       net_cfg.static_seeds.size(), /*permanent=*/false);
    auto backoff = state->static_backoff;
    if (connected) {
      backoff = std::chrono::seconds(30);
    } else {
      backoff = std::min(backoff * 2, std::chrono::seconds(600));
    }
    state->static_backoff = backoff;
    const auto jitter = std::chrono::seconds(backoff.count() / 4);
    state->next_static_attempt = now + backoff + jitter;
  }
}

void WaitForShutdown(NodeContext& node, qryptcoin::net::AddrManager* addrman,
                     const Options& opts, qryptcoin::net::DnsSeedManager* dns_seeds,
                     const std::filesystem::path& peers_path) {
  SeedLoopState seed_state;
  using clock = std::chrono::steady_clock;
  constexpr auto kPeersSaveInterval = std::chrono::seconds(60);
  auto next_peers_save = clock::now() + kPeersSaveInterval;
  while (!ShutdownRequested()) {
    if (dns_seeds) {
      dns_seeds->Tick();
    }
    MaintainOutboundPeers(node.peer_manager.get(), addrman,
                          qryptcoin::config::GetNetworkConfig().listen_port,
                          opts.target_outbound_peers);
    MaybeRunSeedLoop(node, addrman, dns_seeds, opts, &seed_state, opts.target_outbound_peers);
    if (addrman && !peers_path.empty()) {
      const auto now = clock::now();
      if (now >= next_peers_save) {
        std::string error;
        if (!addrman->Save(peers_path, &error) && !error.empty()) {
          std::cerr << "[qryptd] warn: " << error << "\n";
        }
        next_peers_save = now + kPeersSaveInterval;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

}  // namespace

int main(int argc, char** argv) {
  try {
    auto opts = ParseOptions(argc, argv);
    if (!opts.debug_log_path.empty()) {
      try {
        LogLevel level = LogLevel::kDebug;
        try {
          level = ParseLogLevelString(opts.log_level);
        } catch (const std::exception& ex) {
          std::cerr << "[qryptd] warn: " << ex.what()
                    << " (falling back to debug level)\n";
        }
        std::uintmax_t max_bytes = 0;
        if (opts.log_max_size_mb > 0) {
          max_bytes = static_cast<std::uintmax_t>(opts.log_max_size_mb) * 1024ULL * 1024ULL;
        }
        g_debug_logger.Configure(level, max_bytes, opts.log_max_files);
        g_debug_logger.Enable(opts.debug_log_path);
        LogDebug("Debug log enabled at " + opts.debug_log_path);
      } catch (const std::exception& ex) {
        std::cerr << "[qryptd] fatal: " << ex.what() << "\n";
        return 1;
      }
    }

    InstallSignalHandlers();

    const std::string wallet_label = [&opts]() -> std::string {
      if (opts.disable_wallet) {
        return "disabled";
      }
      if (opts.no_wallet_autoload && !opts.wallet_path_explicit) {
        return "autoload_skipped";
      }
      if (opts.wallet_path.empty()) {
        return "<unset>";
      }
      return opts.wallet_path;
    }();

    LogDebug(std::string("qryptd starting on network=") + opts.network +
             ", data_dir=" + opts.data_dir + ", wallet=" + wallet_label +
             ", rpc=" + opts.rpc_bind + ":" + std::to_string(opts.rpc_port) +
             ", p2p_port=" + std::to_string(opts.p2p_port));

    std::filesystem::path data_root(opts.data_dir);
    // Optional static seed overrides loaded from data/<network>/seeds.json.
    try {
      std::filesystem::path seeds_path = data_root / "seeds.json";
      if (std::filesystem::exists(seeds_path)) {
        nlohmann::json json;
        std::ifstream in(seeds_path);
        if (in) {
          in >> json;
          if (json.is_array()) {
            for (const auto& item : json) {
              if (item.is_string()) {
                opts.extra_static_seeds.push_back(item.get<std::string>());
              }
            }
          } else if (json.is_object() && json.contains("static_seeds") &&
                     json["static_seeds"].is_array()) {
            for (const auto& item : json["static_seeds"]) {
              if (item.is_string()) {
                opts.extra_static_seeds.push_back(item.get<std::string>());
              }
            }
          }
        }
      }
    } catch (const std::exception& ex) {
      std::cerr << "[qryptd] warn: failed to load seeds.json: " << ex.what() << "\n";
    }

    const auto peers_path = data_root / "peers.json";
    const auto peers_version_path = data_root / "peers.version";
    const std::uint32_t current_proto =
        static_cast<std::uint32_t>(qryptcoin::net::messages::kCurrentProtocolVersion);
    std::uint32_t stored_proto = 0;
    if (std::filesystem::exists(peers_version_path)) {
      try {
        std::ifstream in(peers_version_path);
        if (in) {
          in >> stored_proto;
        }
      } catch (...) {
        stored_proto = 0;
      }
    }
    if (stored_proto != current_proto) {
      std::error_code ec;
      std::filesystem::remove(peers_path, ec);
      std::cout << "[qryptd] info: resetting peers cache after protocol/protocol-id change ("
                << stored_proto << " -> " << current_proto << ")\n";
    }
    // Ensure the peers cache version marker is up-to-date even if the node
    // runs continuously. This avoids needless cache resets on restart.
    try {
      std::ofstream version_out(peers_version_path);
      if (version_out) {
        version_out << current_proto << "\n";
      }
    } catch (...) {
      // Best-effort; peers cache will simply be reset again on next start.
    }

    qryptcoin::net::AddrManager addrman;
    std::string addr_error;
    if (!addrman.Load(peers_path, &addr_error)) {
      std::cerr << "[qryptd] warn: " << addr_error << "\n";
    }

    qryptcoin::net::DnsSeedManager dns_seeds(opts.allow_private_peers);
    dns_seeds.Initialize(qryptcoin::config::GetNetworkConfig().dns_seeds);

    NodeContext node;
    if (!AppInitMain(opts, &node, &addrman, &dns_seeds)) {
      return 1;
    }

    // Seed the address manager with static seeds so that future
    // outbound dialing can make progress even when the DNS seeds are
    // temporarily unreachable.
    const auto& net_cfg = qryptcoin::config::GetNetworkConfig();
    for (const auto& host : net_cfg.static_seeds) {
      addrman.Add(host, net_cfg.listen_port, true);
    }
    for (const auto& host : opts.extra_static_seeds) {
      addrman.Add(host, net_cfg.listen_port, true);
    }

    WaitForShutdown(node, &addrman, opts, &dns_seeds, peers_path);
    ShutdownNode(node);

    if (!addrman.Save(peers_path, &addr_error)) {
      std::cerr << "[qryptd] warn: " << addr_error << "\n";
    }
  } catch (const std::exception& ex) {
    LogDebug(std::string("fatal exception: ") + ex.what());
    std::cerr << "[qryptd] fatal: " << ex.what() << "\n";
    return 1;
  }
  return 0;
}
