#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace qryptcoin::config {

enum class NetworkType {
  kMainnet,
  kTestnet,
  kRegtest,
  kSignet,
};

enum class EncryptionMode {
  kEncrypted,
  kPlaintext,
};

struct NetworkConfig {
  NetworkType type{NetworkType::kMainnet};
  std::string network_id{"mainnet"};
  std::string bech32_hrp{"qry"};
  std::array<std::uint8_t, 4> message_start{{0x51, 0x52, 0x59, 0x21}};
  std::string listen_address{"0.0.0.0"};
  std::uint16_t listen_port{9375};
  std::uint16_t rpc_port{19735};
  std::uint16_t peers_max{32};
  // Configurable peer limits. Zero means use built-in defaults.
  std::size_t max_inbound_peers{0};
  std::size_t max_outbound_peers{0};
  std::size_t max_total_peers{0};
  // Target number of outbound connections to maintain.
  // Default: 10 (8 full-relay + 2 block-relay-only).
  std::size_t target_outbound_peers{10};
  EncryptionMode encryption_mode{EncryptionMode::kEncrypted};
  bool encryption_required{false};
  // Base data directory used for persistence of P2P transport identity and
  // peer key pins. When empty, the node falls back to an in-memory identity.
  std::string data_dir;
  // When enabled, encrypted transport handshakes are identity-authenticated
  // (Dilithium signatures over a transcript hash). If required, peers that
  // cannot be authenticated are rejected.
  bool authenticated_transport_required{false};
  // Trust-on-first-use (TOFU) pinning for peer identity keys. When enabled,
  // the first successful authenticated handshake for a peer stores its
  // identity key and subsequent changes are treated as suspicious.
  bool authenticated_transport_tofu{true};
  std::vector<std::string> dns_seeds;
  std::vector<std::string> static_seeds;
  std::uint64_t service_bits{1};
  // Optional SOCKS5 proxy for outbound P2P connections. When non-empty,
  // outbound peers are reached via this proxy instead of directly.
  std::string socks5_proxy_host;
  std::uint16_t socks5_proxy_port{0};
  // Optional Tor onion proxy. When set, .onion peers will be routed via
  // this proxy; otherwise the default SOCKS5 proxy is reused.
  std::string onion_proxy_host;
  std::uint16_t onion_proxy_port{0};
};

const NetworkConfig& GetNetworkConfig();
NetworkConfig& GetMutableNetworkConfig();
void SelectNetwork(NetworkType type);
NetworkType NetworkFromString(std::string_view name);
std::string_view NetworkName(NetworkType type);

}  // namespace qryptcoin::config
