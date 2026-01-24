#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>

#include "config/network.hpp"
#include "net/peer_manager.hpp"
#include "net/peer_session.hpp"
#include "net/messages.hpp"

namespace {

std::filesystem::path MakeTempDir(const std::string& prefix) {
  const auto base = std::filesystem::temp_directory_path();
  const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::filesystem::path dir = base / (prefix + "-" + std::to_string(now));
  std::filesystem::create_directories(dir);
  return dir;
}

std::uint16_t StartListenerWithRandomPort(qryptcoin::config::NetworkConfig cfg,
                                         std::unique_ptr<qryptcoin::net::PeerManager>* out) {
  if (!out) {
    return 0;
  }
  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  for (int attempt = 0; attempt < 200; ++attempt) {
    cfg.listen_port = static_cast<std::uint16_t>(20000u + (rng() % 30000u));
    auto server = std::make_unique<qryptcoin::net::PeerManager>(cfg);
    if (server->StartListener()) {
      *out = std::move(server);
      return cfg.listen_port;
    }
  }
  return 0;
}

}  // namespace

int main() {
  using namespace qryptcoin;
  config::SelectNetwork(config::NetworkType::kRegtest);

  config::NetworkConfig server_cfg = config::GetNetworkConfig();
  server_cfg.listen_address = "127.0.0.1";
  server_cfg.encryption_mode = config::EncryptionMode::kEncrypted;
  server_cfg.encryption_required = true;

  std::unique_ptr<net::PeerManager> server;
  const std::uint16_t server_port =
      StartListenerWithRandomPort(server_cfg, &server);
  if (!server_port) {
    std::cerr << "Failed to start listener\n";
    return EXIT_FAILURE;
  }

  auto expect_handshake = [&](config::NetworkConfig client_cfg,
                              std::uint16_t port,
                              bool expect_ok,
                              const char* label,
                              std::optional<config::EncryptionMode> expected_mode =
                                  std::nullopt) {
    net::PeerSession client_session;
    if (!client_session.Connect("127.0.0.1", port)) {
      std::cerr << label << ": client connect failed\n";
      return false;
    }
    const bool ok = client_session.PerformHandshake(client_cfg);
    if (ok != expect_ok) {
      std::cerr << label << ": handshake " << (ok ? "succeeded" : "failed")
                << " but expected " << (expect_ok ? "success" : "failure") << "\n";
      return false;
    }
    if (!ok) {
      return true;
    }
    if (expected_mode && client_session.negotiated_mode() != *expected_mode) {
      std::cerr << label << ": negotiated mode mismatch\n";
      return false;
    }
    qryptcoin::net::messages::InventoryMessage inv{};
    qryptcoin::net::messages::InventoryVector vec;
    vec.identifier.fill(0xCD);
    inv.entries.push_back(vec);
    if (!client_session.Send(qryptcoin::net::messages::EncodeInventory(inv))) {
      std::cerr << label << ": failed to send inventory after handshake\n";
      return false;
    }
    return true;
  };

  // Baseline: encrypted, correct network binding, correct magic.
  if (!expect_handshake(server_cfg, server_port, true, "baseline",
                        config::EncryptionMode::kEncrypted)) {
    server->Stop();
    return EXIT_FAILURE;
  }

  // Peer preference mismatch: remote requests plaintext but local requires encryption.
  config::NetworkConfig downgrade_cfg = server_cfg;
  downgrade_cfg.encryption_mode = config::EncryptionMode::kPlaintext;
  if (!expect_handshake(downgrade_cfg, server_port, true, "downgrade",
                        config::EncryptionMode::kEncrypted)) {
    server->Stop();
    return EXIT_FAILURE;
  }

  // Network-id mismatch: same magic but different declared network_id.
  config::NetworkConfig netid_cfg = server_cfg;
  netid_cfg.network_id = "wrongnet";
  if (!expect_handshake(netid_cfg, server_port, false, "network-id-mismatch")) {
    server->Stop();
    return EXIT_FAILURE;
  }

  // Genesis mismatch: keep network_id the same but advertise a different chain type.
  config::NetworkConfig genesis_cfg = server_cfg;
  genesis_cfg.type = config::NetworkType::kTestnet;
  if (!expect_handshake(genesis_cfg, server_port, false, "genesis-mismatch")) {
    server->Stop();
    return EXIT_FAILURE;
  }

  // Magic mismatch: wrong frame prefix should be rejected before version parsing.
  config::NetworkConfig magic_cfg = server_cfg;
  magic_cfg.message_start = {{0xAA, 0xBB, 0xCC, 0xDD}};
  if (!expect_handshake(magic_cfg, server_port, false, "magic-mismatch")) {
    server->Stop();
    return EXIT_FAILURE;
  }

  server->Stop();

  // Downgrade resistance via history pinning: once encrypted, refuse plaintext.
  std::unique_ptr<net::PeerManager> history_server;
  config::NetworkConfig history_server_cfg = config::GetNetworkConfig();
  history_server_cfg.listen_address = "127.0.0.1";
  history_server_cfg.encryption_mode = config::EncryptionMode::kPlaintext;
  history_server_cfg.encryption_required = false;
  const std::uint16_t history_port =
      StartListenerWithRandomPort(history_server_cfg, &history_server);
  if (!history_port) {
    std::cerr << "Failed to start history listener\n";
    return EXIT_FAILURE;
  }

  const auto client_dir = MakeTempDir("qrypt-handshake-client");
  std::filesystem::create_directories(client_dir);

  config::NetworkConfig history_client_encrypted = history_server_cfg;
  history_client_encrypted.encryption_mode = config::EncryptionMode::kEncrypted;
  history_client_encrypted.data_dir = client_dir.string();
  if (!expect_handshake(history_client_encrypted, history_port, true,
                        "history-encrypted",
                        config::EncryptionMode::kEncrypted)) {
    history_server->Stop();
    return EXIT_FAILURE;
  }
  if (!std::filesystem::exists(client_dir / "p2p_encrypted_peers.txt")) {
    std::cerr << "history-encrypted: expected encrypted peer history file\n";
    history_server->Stop();
    return EXIT_FAILURE;
  }

  config::NetworkConfig history_client_plain = history_client_encrypted;
  history_client_plain.encryption_mode = config::EncryptionMode::kPlaintext;
  if (!expect_handshake(history_client_plain, history_port, false, "history-plaintext")) {
    history_server->Stop();
    return EXIT_FAILURE;
  }

  history_server->Stop();
  return EXIT_SUCCESS;
}
