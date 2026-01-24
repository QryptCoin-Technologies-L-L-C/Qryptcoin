#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>
#include <thread>

#include "config/network.hpp"
#include "net/channel.hpp"
#include "net/messages.hpp"
#include "net/peer_session.hpp"

namespace {

bool BindEphemeral(qryptcoin::net::FrameChannel* listener, const std::string& addr,
                   std::uint16_t* out_port) {
  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  for (int attempt = 0; attempt < 200; ++attempt) {
    const std::uint16_t port =
        static_cast<std::uint16_t>(20000u + (rng() % 30000u));
    if (listener->BindAndListen(addr, port)) {
      if (out_port) *out_port = port;
      return true;
    }
  }
  return false;
}

}  // namespace

int main() {
  using namespace qryptcoin;

  config::SelectNetwork(config::NetworkType::kRegtest);

  config::NetworkConfig cfg = config::GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  cfg.encryption_mode = config::EncryptionMode::kEncrypted;

  net::FrameChannel server_listener;
  net::FrameChannel mitm_listener;

  std::uint16_t server_port = 0;
  std::uint16_t mitm_port = 0;
  if (!BindEphemeral(&server_listener, cfg.listen_address, &server_port) ||
      !BindEphemeral(&mitm_listener, cfg.listen_address, &mitm_port)) {
    std::cerr << "Failed to bind listeners\n";
    return 1;
  }

  std::atomic<bool> server_ok{false};
  std::thread server_thread([&] {
    net::FrameChannel inbound = server_listener.Accept();
    inbound.socket().SetTimeout(2000);
    net::PeerSession session(std::move(inbound), /*initiator=*/false);
    if (!session.PerformHandshake(cfg)) {
      return;
    }
    net::messages::Message msg;
    if (!session.Receive(&msg)) {
      return;
    }
    if (msg.command != net::messages::Command::kInventory) {
      return;
    }
    // Replay should cause the next decrypt attempt to fail.
    net::messages::Message replayed;
    if (session.Receive(&replayed)) {
      return;
    }
    server_ok.store(true);
    session.Close();
  });

  std::thread mitm_thread([&] {
    net::FrameChannel from_client = mitm_listener.Accept();
    net::FrameChannel to_server;
    if (!to_server.Connect(cfg.listen_address, server_port)) {
      return;
    }
    from_client.SetMessageStart(cfg.message_start);
    to_server.SetMessageStart(cfg.message_start);
    from_client.socket().SetTimeout(2000);
    to_server.socket().SetTimeout(2000);

    std::atomic<bool> done{false};
    std::atomic<bool> replayed{false};
    int encrypted_from_client_seen = 0;

    std::thread forward_server([&] {
      while (!done.load()) {
        net::messages::Message msg;
        if (!to_server.Receive(&msg)) break;
        if (!from_client.Send(msg)) break;
      }
      done.store(true);
    });

    while (!done.load()) {
      net::messages::Message msg;
      if (!from_client.Receive(&msg)) break;
      if (!to_server.Send(msg)) break;
      if (!replayed.load() && msg.command == net::messages::Command::kEncryptedFrame) {
        ++encrypted_from_client_seen;
        if (encrypted_from_client_seen < 2) {
          continue;
        }
        // Replay the identical outer frame (nonce+ciphertext).
        if (!to_server.Send(msg)) break;
        replayed.store(true);
      }
    }
    done.store(true);
    forward_server.join();
  });

  // Client connects to the MITM and performs a normal handshake.
  net::PeerSession client;
  if (!client.Connect(cfg.listen_address, mitm_port)) {
    std::cerr << "Client connect failed\n";
    return 1;
  }
  if (!client.PerformHandshake(cfg)) {
    std::cerr << "Client handshake failed\n";
    return 1;
  }
  net::messages::InventoryMessage inv{};
  net::messages::InventoryVector vec;
  vec.type = net::messages::InventoryType::kBlock;
  vec.identifier.fill(0x42);
  inv.entries.push_back(vec);
  if (!client.Send(net::messages::EncodeInventory(inv))) {
    std::cerr << "Client send inventory failed\n";
    return 1;
  }
  if (!client.Send(net::messages::EncodePing(net::messages::PingMessage{0x1234}))) {
    std::cerr << "Client send ping failed\n";
    return 1;
  }
  client.Close();

  mitm_thread.join();
  server_thread.join();

  if (!server_ok.load()) {
    std::cerr << "Replay protection test failed\n";
    return 1;
  }
  return 0;
}
