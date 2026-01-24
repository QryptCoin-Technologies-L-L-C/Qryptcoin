#include "config/network.hpp"

namespace qryptcoin::config {

namespace {

constexpr std::uint64_t kServiceFullNode = 1ULL << 0;
constexpr std::uint64_t kServicePqNative = 1ULL << 1;

NetworkConfig BuildConfig(NetworkType type, std::string id, std::string hrp,
                          std::array<std::uint8_t, 4> magic, std::uint16_t p2p_port,
                          std::uint16_t rpc_port, std::vector<std::string> dns_seeds,
                          std::vector<std::string> static_seeds) {
  NetworkConfig cfg;
  cfg.type = type;
  cfg.network_id = std::move(id);
  cfg.bech32_hrp = std::move(hrp);
  cfg.message_start = magic;
  cfg.listen_port = p2p_port;
  cfg.rpc_port = rpc_port;
  cfg.dns_seeds = std::move(dns_seeds);
  cfg.static_seeds = std::move(static_seeds);
  cfg.service_bits = kServiceFullNode | kServicePqNative;
  return cfg;
}

NetworkConfig g_network_config = [] {
  auto cfg = BuildConfig(NetworkType::kMainnet, "mainnet", "qry", {0x51, 0x52, 0x59, 0x31}, 9375,
                         19735,
                         {"seed1.qryptcoin.org", "seed2.qryptcoin.org"},
                         {"bootstrap-main.qryptcoin.org", "bootstrap-alt.qryptcoin.org"});
  return cfg;
}();

const NetworkConfig& ConfigFor(NetworkType type) {
  static const NetworkConfig testnet =
      BuildConfig(NetworkType::kTestnet, "testnet", "tqry", {0x51, 0x52, 0x59, 0x54}, 19375, 29735,
                  {"testnet-seed1.qryptcoin.org", "testnet-seed2.qryptcoin.org"}, {});
  static const NetworkConfig regtest =
      BuildConfig(NetworkType::kRegtest, "regtest", "rqry", {0x51, 0x52, 0x59, 0x52}, 18444, 18445,
                  {}, {"127.0.0.1"});
  static const NetworkConfig signet =
      BuildConfig(NetworkType::kSignet, "signet", "sqry", {0x51, 0x52, 0x59, 0x53}, 39735, 49735,
                  {}, {});
  static const NetworkConfig mainnet = [] {
    auto cfg = BuildConfig(NetworkType::kMainnet, "mainnet", "qry", {0x51, 0x52, 0x59, 0x31},
                           9375, 19735,
                           {"seed1.qryptcoin.org", "seed2.qryptcoin.org"},
                           {"bootstrap-main.qryptcoin.org", "bootstrap-alt.qryptcoin.org"});
    return cfg;
  }();
  switch (type) {
    case NetworkType::kMainnet:
      return mainnet;
    case NetworkType::kTestnet:
      return testnet;
    case NetworkType::kRegtest:
      return regtest;
    case NetworkType::kSignet:
      return signet;
  }
  return mainnet;
}

}  // namespace

const NetworkConfig& GetNetworkConfig() { return g_network_config; }

void SelectNetwork(NetworkType type) { g_network_config = ConfigFor(type); }

NetworkType NetworkFromString(std::string_view name) {
  if (name == "mainnet" || name == "main") return NetworkType::kMainnet;
  if (name == "testnet" || name == "test") return NetworkType::kTestnet;
  if (name == "regtest" || name == "reg") return NetworkType::kRegtest;
  if (name == "signet" || name == "sig") return NetworkType::kSignet;
  return NetworkType::kMainnet;
}

std::string_view NetworkName(NetworkType type) {
  switch (type) {
    case NetworkType::kMainnet:
      return "mainnet";
    case NetworkType::kTestnet:
      return "testnet";
    case NetworkType::kRegtest:
      return "regtest";
    case NetworkType::kSignet:
      return "signet";
  }
  return "mainnet";
}

}  // namespace qryptcoin::config
