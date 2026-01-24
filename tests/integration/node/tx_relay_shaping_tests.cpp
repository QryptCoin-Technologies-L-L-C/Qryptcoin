#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "config/network.hpp"
#include "net/messages.hpp"
#include "net/peer_manager.hpp"
#include "net/peer_session.hpp"
#include "node/block_sync.hpp"
#include "node/chain_state.hpp"

namespace {

using namespace qryptcoin;

bool ReceiveWithTimeout(net::PeerSession& session,
                        net::messages::Message* out,
                        std::chrono::milliseconds timeout,
                        const char* label) {
  auto fut = std::async(std::launch::async, [&session, out]() { return session.Receive(out); });
  if (fut.wait_for(timeout) != std::future_status::ready) {
    std::cerr << label << ": receive timed out\n";
    session.Close();
    return false;
  }
  if (!fut.get()) {
    std::cerr << label << ": receive failed\n";
    return false;
  }
  return true;
}

bool WaitForGetData(net::PeerSession& session,
                    net::messages::Message* out,
                    std::chrono::milliseconds timeout,
                    const char* label) {
  constexpr int kMaxMessagesToScan = 20;
  for (int i = 0; i < kMaxMessagesToScan; ++i) {
    net::messages::Message msg;
    if (!ReceiveWithTimeout(session, &msg, timeout, label)) {
      return false;
    }
    if (msg.command == net::messages::Command::kGetData) {
      *out = std::move(msg);
      return true;
    }
  }
  std::cerr << label << ": did not observe GETDATA\n";
  return false;
}

bool AllBytesEqual(const crypto::Sha3_256Hash& hash, std::uint8_t value) {
  for (const auto b : hash) {
    if (b != value) return false;
  }
  return true;
}

std::filesystem::path MakeTempDir(const std::string& suffix) {
  auto root = std::filesystem::temp_directory_path() / suffix;
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);
  return root;
}

bool TestTxInventoryDedup() {
  using namespace std::chrono_literals;

  config::SelectNetwork(config::NetworkType::kRegtest);
  const auto temp_root = MakeTempDir("qryptcoin-tx-relay-dedup-test");

  node::ChainState chain((temp_root / "blocks.dat").string(), (temp_root / "utxo.dat").string());
  std::string error;
  if (!chain.Initialize(&error)) {
    std::cerr << "tx_relay_shaping_tests: chain init failed: " << error << "\n";
    return false;
  }

  config::NetworkConfig cfg = config::GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  cfg.encryption_mode = config::EncryptionMode::kPlaintext;
  cfg.encryption_required = false;

  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));

  std::optional<std::uint16_t> port;
  std::unique_ptr<net::PeerManager> server;
  for (int attempt = 0; attempt < 200; ++attempt) {
    cfg.listen_port = static_cast<std::uint16_t>(20000u + (rng() % 30000u));
    server = std::make_unique<net::PeerManager>(cfg);
    if (server->StartListener()) {
      port = cfg.listen_port;
      break;
    }
  }
  if (!port.has_value()) {
    std::cerr << "tx_relay_shaping_tests: failed to bind listener\n";
    return false;
  }

  node::BlockSyncManager sync(chain, *server);
  sync.SetTransactionInventoryPolicy(
      [](const primitives::Hash256&) { return false; },
      [](const primitives::Hash256&, std::vector<std::uint8_t>*) { return false; });
  sync.Start();

  net::PeerSession client;
  if (!client.Connect(cfg.listen_address, *port)) {
    std::cerr << "tx_relay_shaping_tests: client connect failed\n";
    sync.Stop();
    server->Stop();
    return false;
  }
  if (!client.PerformHandshake(cfg)) {
    std::cerr << "tx_relay_shaping_tests: client handshake failed\n";
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }

  // Drain the initial getheaders request from the server (best-effort).
  {
    net::messages::Message ignored;
    ReceiveWithTimeout(client, &ignored, 2s, "tx-relay-dedup/drain");
  }

  auto send_tx_inv = [&](std::uint8_t marker) -> bool {
    net::messages::InventoryMessage inv;
    net::messages::InventoryVector vec;
    vec.type = net::messages::InventoryType::kTransaction;
    vec.identifier.fill(marker);
    inv.entries.push_back(vec);
    return client.Send(net::messages::EncodeInventory(inv));
  };

  if (!send_tx_inv(0x11)) {
    std::cerr << "tx_relay_shaping_tests: failed to send initial INV\n";
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }

  net::messages::Message msg_a;
  if (!WaitForGetData(client, &msg_a, 2s, "tx-relay-dedup/await-a")) {
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }
  net::messages::InventoryMessage req_a;
  if (!net::messages::DecodeGetData(msg_a, &req_a) || req_a.entries.size() != 1u ||
      req_a.entries[0].type != net::messages::InventoryType::kTransaction ||
      !AllBytesEqual(req_a.entries[0].identifier, 0x11)) {
    std::cerr << "tx_relay_shaping_tests: unexpected GETDATA for tx A\n";
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }

  // Spam duplicate inventory for tx A then advertise tx B. Only tx B should
  // trigger a new GETDATA request.
  for (int i = 0; i < 5; ++i) {
    if (!send_tx_inv(0x11)) {
      std::cerr << "tx_relay_shaping_tests: failed to send duplicate INV\n";
      client.Close();
      sync.Stop();
      server->Stop();
      return false;
    }
  }
  if (!send_tx_inv(0x22)) {
    std::cerr << "tx_relay_shaping_tests: failed to send tx B INV\n";
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }

  std::size_t a_count = 1;
  std::size_t b_count = 0;
  for (int i = 0; i < 20 && b_count == 0; ++i) {
    net::messages::Message msg;
    if (!ReceiveWithTimeout(client, &msg, 2s, "tx-relay-dedup/await-b")) {
      break;
    }
    if (msg.command != net::messages::Command::kGetData) {
      continue;
    }
    net::messages::InventoryMessage req;
    if (!net::messages::DecodeGetData(msg, &req)) {
      std::cerr << "tx_relay_shaping_tests: malformed GETDATA\n";
      client.Close();
      sync.Stop();
      server->Stop();
      return false;
    }
    for (const auto& entry : req.entries) {
      if (entry.type != net::messages::InventoryType::kTransaction) {
        continue;
      }
      if (AllBytesEqual(entry.identifier, 0x11)) {
        ++a_count;
      } else if (AllBytesEqual(entry.identifier, 0x22)) {
        ++b_count;
      } else {
        std::cerr << "tx_relay_shaping_tests: unexpected tx requested via GETDATA\n";
        client.Close();
        sync.Stop();
        server->Stop();
        return false;
      }
    }
  }

  client.Close();
  sync.Stop();
  server->Stop();
  std::filesystem::remove_all(temp_root);

  if (a_count != 1 || b_count != 1) {
    std::cerr << "tx_relay_shaping_tests: expected 1 GETDATA for each tx, got A="
              << a_count << " B=" << b_count << "\n";
    return false;
  }
  return true;
}

bool TestTxInventoryRequestCap() {
  using namespace std::chrono_literals;

  config::SelectNetwork(config::NetworkType::kRegtest);
  const auto temp_root = MakeTempDir("qryptcoin-tx-relay-cap-test");

  node::ChainState chain((temp_root / "blocks.dat").string(), (temp_root / "utxo.dat").string());
  std::string error;
  if (!chain.Initialize(&error)) {
    std::cerr << "tx_relay_shaping_tests: chain init failed: " << error << "\n";
    return false;
  }

  config::NetworkConfig cfg = config::GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  cfg.encryption_mode = config::EncryptionMode::kPlaintext;
  cfg.encryption_required = false;

  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));

  std::optional<std::uint16_t> port;
  std::unique_ptr<net::PeerManager> server;
  for (int attempt = 0; attempt < 200; ++attempt) {
    cfg.listen_port = static_cast<std::uint16_t>(20000u + (rng() % 30000u));
    server = std::make_unique<net::PeerManager>(cfg);
    if (server->StartListener()) {
      port = cfg.listen_port;
      break;
    }
  }
  if (!port.has_value()) {
    std::cerr << "tx_relay_shaping_tests: failed to bind listener\n";
    return false;
  }

  node::BlockSyncManager sync(chain, *server);
  sync.SetTransactionInventoryPolicy(
      [](const primitives::Hash256&) { return false; },
      [](const primitives::Hash256&, std::vector<std::uint8_t>*) { return false; });
  sync.Start();

  net::PeerSession client;
  if (!client.Connect(cfg.listen_address, *port)) {
    std::cerr << "tx_relay_shaping_tests: client connect failed\n";
    sync.Stop();
    server->Stop();
    return false;
  }
  if (!client.PerformHandshake(cfg)) {
    std::cerr << "tx_relay_shaping_tests: client handshake failed\n";
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }

  // Drain the initial getheaders request from the server (best-effort).
  {
    net::messages::Message ignored;
    ReceiveWithTimeout(client, &ignored, 2s, "tx-relay-cap/drain");
  }

  net::messages::InventoryMessage inv;
  inv.entries.reserve(2000);
  for (std::uint32_t i = 0; i < 2000; ++i) {
    net::messages::InventoryVector vec;
    vec.type = net::messages::InventoryType::kTransaction;
    vec.identifier.fill(0);
    vec.identifier[0] = static_cast<std::uint8_t>(i & 0xFFu);
    vec.identifier[1] = static_cast<std::uint8_t>((i >> 8) & 0xFFu);
    inv.entries.push_back(vec);
  }
  if (!client.Send(net::messages::EncodeInventory(inv))) {
    std::cerr << "tx_relay_shaping_tests: failed to send INV burst\n";
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }

  net::messages::Message msg;
  if (!WaitForGetData(client, &msg, 2s, "tx-relay-cap/await-getdata")) {
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }
  net::messages::InventoryMessage req;
  if (!net::messages::DecodeGetData(msg, &req)) {
    std::cerr << "tx_relay_shaping_tests: failed to decode GETDATA\n";
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }

  // The node should cap per-message tx fetch requests (bounds the outbound
  // amplification from a single INV burst).
  if (req.entries.size() != 1024u) {
    std::cerr << "tx_relay_shaping_tests: expected 1024 tx requests, got "
              << req.entries.size() << "\n";
    client.Close();
    sync.Stop();
    server->Stop();
    return false;
  }
  std::set<crypto::Sha3_256Hash> uniq;
  for (const auto& entry : req.entries) {
    if (entry.type != net::messages::InventoryType::kTransaction) {
      std::cerr << "tx_relay_shaping_tests: expected only transaction GETDATA entries\n";
      client.Close();
      sync.Stop();
      server->Stop();
      return false;
    }
    if (!uniq.insert(entry.identifier).second) {
      std::cerr << "tx_relay_shaping_tests: duplicate tx request detected\n";
      client.Close();
      sync.Stop();
      server->Stop();
      return false;
    }
  }

  client.Close();
  sync.Stop();
  server->Stop();
  std::filesystem::remove_all(temp_root);
  return true;
}

}  // namespace

int main() {
  if (!TestTxInventoryDedup()) {
    return EXIT_FAILURE;
  }
  if (!TestTxInventoryRequestCap()) {
    return EXIT_FAILURE;
  }
  std::cout << "tx_relay_shaping_tests: OK\n";
  return EXIT_SUCCESS;
}
